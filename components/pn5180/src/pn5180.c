#include "pn5180.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "pn5180-internal.h"
#include <string.h>

// PN5180 1-Byte Direct Commands
// see 11.4.3.3 Host Interface Command List
#define PN5180_WRITE_REGISTER          (0x00)
#define PN5180_WRITE_REGISTER_OR_MASK  (0x01)
#define PN5180_WRITE_REGISTER_AND_MASK (0x02)
#define PN5180_READ_REGISTER           (0x04)
#define PN5180_WRITE_EEPROM            (0x06)
#define PN5180_READ_EEPROM             (0x07)
#define PN5180_SEND_DATA               (0x09)
#define PN5180_READ_DATA               (0x0A)
#define PN5180_SWITCH_MODE             (0x0B)
#define PN5180_MIFARE_AUTHENTICATE     (0x0C)
#define PN5180_LOAD_RF_CONFIG          (0x11)
#define PN5180_RF_ON                   (0x16)
#define PN5180_RF_OFF                  (0x17)

// EEPROM Addresses
#define MFC_AUTH_TIMEOUT (0x32) // MIFARE Classic authentication timeout

#define LPCD_REFERENCE_VALUE (0x34) // LPCD Gear number
#define LPCD_FIELD_ON_TIME   (0x36) // LPCD RF on time (μs) = 62 + (8 * LPCD_FIELD_ON_TIME)
// LPCD wakes up if current AGC > AGC reference + LCPD_THRESHOLD (03..08: very sensitive, 40..50: very robust)
#define LPCD_THRESHOLD_LEVEL            (0x37)
#define LPCD_REFVAL_GPO_CONTROL         (0x38) // LPCD Reference Value Selection and GPO control
#define LPCD_GPO_TOGGLE_BEFORE_FIELD_ON (0x39) //
#define LPCD_GPO_TOGGLE_AFTER_FIELD_ON  (0x3A) //

static const char TAG[] = "PN5180";

void pn5180_delay_ms(int ms)
{
    int64_t start = esp_timer_get_time();
    while ((esp_timer_get_time() - start) < (ms * 1000)) {
        vTaskDelay(1);
    }
}

pn5180_spi_t *pn5180_spi_init(       //
    spi_host_device_t host_id,       //
    gpio_num_t        sck,           //
    gpio_num_t        miso,          //
    gpio_num_t        mosi,          //
    int               clock_speed_hz //
)
{

    pn5180_spi_t *spi = (pn5180_spi_t *)malloc(sizeof(pn5180_spi_t));
    if (spi == NULL) {
        return NULL;
    }
    gpio_config_t miso_cfg = {
        .pin_bit_mask = (1ULL << miso),        //
        .mode         = GPIO_MODE_INPUT,       //
        .pull_up_en   = GPIO_PULLUP_ENABLE,    //
        .pull_down_en = GPIO_PULLDOWN_DISABLE, //
        .intr_type    = GPIO_INTR_DISABLE      //
    };
    gpio_config(&miso_cfg);
    spi_bus_config_t bus_config = {
        .mosi_io_num     = mosi,
        .miso_io_num     = miso,
        .sclk_io_num     = sck,
        .quadwp_io_num   = -1,
        .quadhd_io_num   = -1,
        .max_transfer_sz = 0,
    };

    spi_device_interface_config_t dev_config = {
        .clock_speed_hz = clock_speed_hz, //
        .mode           = 0,              //
        .spics_io_num   = GPIO_NUM_NC,    //
        .queue_size     = 2,              //
        .flags          = 0               //
    };

    if (spi_bus_initialize(host_id, &bus_config, SPI_DMA_CH_AUTO) != ESP_OK) {
        free(spi);
        ESP_LOGE(TAG, "Failed to initialize SPI bus");
        return NULL;
    }
    if (spi_bus_add_device(host_id, &dev_config, &spi->spi_handle) != ESP_OK) {
        spi_bus_free(host_id);
        free(spi);
        ESP_LOGE(TAG, "Failed to add SPI device");
        return NULL;
    }
    spi->host_id        = host_id;
    spi->clock_speed_hz = clock_speed_hz;
    spi->sck            = sck;
    spi->miso           = miso;
    spi->mosi           = mosi;
    return spi;
}

static bool inline wait_busy_level(pn5180_t *pn5180, int level, const char *timeout_msg)
{
    int64_t deadline = esp_timer_get_time() + (1000LL * pn5180->timeout_ms);
    int     spin     = 0;
    while (gpio_get_level(pn5180->busy) != level) {
        if (esp_timer_get_time() > deadline) {
            ESP_LOGE(TAG, "PN5180 %s timeout waiting for busy level %d", timeout_msg, level);
            return false;
        }
        esp_rom_delay_us(10);
        if ((++spin % 2000) == 0) {
            vTaskDelay(1);
        }
    }
    return true;
}

pn5180_t *pn5180_init(pn5180_spi_t *spi, gpio_num_t nss, gpio_num_t busy, gpio_num_t rst)
{
    pn5180_t *ret = (pn5180_t *)calloc(1, sizeof(pn5180_t));
    if (ret == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for PN5180");
        return NULL;
    }

    ret->send_buf = (uint8_t *)heap_caps_calloc(1, PN5180_MAX_BUF_SIZE, MALLOC_CAP_DMA);
    if (ret->send_buf == NULL) {
        free(ret);
        ESP_LOGE(TAG, "Failed to allocate send buffer");
        return NULL;
    }

    ret->recv_buf = (uint8_t *)heap_caps_calloc(1, PN5180_MAX_BUF_SIZE, MALLOC_CAP_DMA);
    if (ret->recv_buf == NULL) {
        free(ret->send_buf);
        free(ret);
        ESP_LOGE(TAG, "Failed to allocate receive buffer");
        return NULL;
    }
    gpio_set_direction(nss, GPIO_MODE_OUTPUT);
    gpio_set_direction(rst, GPIO_MODE_OUTPUT);
    gpio_set_direction(busy, GPIO_MODE_INPUT);
    ret->spi        = spi;
    ret->nss        = nss;
    ret->busy       = busy;
    ret->rst        = rst;
    ret->timeout_ms = 500;
    ret->tx_config  = 0;
    ret->rf_config  = 0;
    gpio_set_level(nss, 1);
    gpio_set_level(rst, 1);
    pn5180_delay_ms(100);
    if (!pn5180_reset(ret)) {
        ESP_LOGE(TAG, "Failed to reset PN5180 during init");
        pn5180_deinit(ret, false);
        return NULL;
    }
    uint8_t eeprom_data[2];
    if (!pn5180_readEEprom(ret, MFC_AUTH_TIMEOUT, eeprom_data, sizeof(eeprom_data))) {
        ESP_LOGW(TAG, "Failed to set MFC_AUTH_TIMEOUT to maximum");
    } else {
        PN5180_LOGD(TAG, "Current MFC_AUTH_TIMEOUT: 0x%02X 0x%02X", eeprom_data[0], eeprom_data[1]);
    }

    return ret;
}

/**
 * @brief Execute SPI transceive command with PN5180
 *
 * Phase 1: Send command
 * - Wait BUSY low (inactive)
 * - Assert NSS
 * - SPI transmit
 * - Wait BUSY high
 * - Deassert NSS
 *
 * Phase 2: Receive response
 * - Wait BUSY low
 * - Assert NSS
 * - SPI transmit (rx)
 * - Wait BUSY high
 * - Deassert NSS
 * - Copy to buffer
 *
 * @param pn5180 Pointer to PN5180 device structure
 * @param send_data Data to send
 * @param send_data_len Length of data to send
 * @param recv_data Buffer for received data (can be NULL if recv_data_len is 0)
 * @param recv_data_len Length of data to receive
 * @return true on success, false on failure
 */
static bool transceive_command(pn5180_t *pn5180, uint8_t *send_data, size_t send_data_len, uint8_t *recv_data, size_t recv_data_len)
{
    if (send_data_len > PN5180_MAX_BUF_SIZE || recv_data_len > PN5180_MAX_BUF_SIZE) {
        ESP_LOGE(TAG, "transceive_command: Buffer size exceeds maximum");
        return false;
    }

    spi_transaction_t trans;
    memset(&trans, 0, sizeof(trans));
    memcpy(pn5180->send_buf, send_data, send_data_len);
    memset(pn5180->recv_buf, 0xff, PN5180_MAX_BUF_SIZE);
    trans.tx_buffer = pn5180->send_buf;
    trans.rx_buffer = pn5180->recv_buf;
    trans.length    = send_data_len * 8;
    if (!wait_busy_level(pn5180, 0, "before transfer")) {
        return false;
    }
    gpio_set_level(pn5180->nss, 0);
    esp_rom_delay_us(10);
    if (spi_device_polling_transmit(pn5180->spi->spi_handle, &trans) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to transmit command via SPI");
        gpio_set_level(pn5180->nss, 1);
        return false;
    }
    if (!wait_busy_level(pn5180, 1, "wait for busy after transfer")) {
        gpio_set_level(pn5180->nss, 1);
        return false;
    }
    gpio_set_level(pn5180->nss, 1);
    if (!wait_busy_level(pn5180, 0, "wait for idle after send")) {
        return false;
    }
    if (recv_data_len == 0 || recv_data == NULL) {
        return true;
    }
    memset(&trans, 0, sizeof(trans));
    memset(pn5180->send_buf, 0xff, PN5180_MAX_BUF_SIZE);
    trans.tx_buffer = pn5180->send_buf;
    trans.rx_buffer = pn5180->recv_buf;
    trans.length    = recv_data_len * 8;
    gpio_set_level(pn5180->nss, 0);
    esp_rom_delay_us(10);
    if (spi_device_polling_transmit(pn5180->spi->spi_handle, &trans) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to transmit SPI transaction");
        gpio_set_level(pn5180->nss, 1);
        return false;
    }
    if (!wait_busy_level(pn5180, 1, "wait for busy after recv")) {
        gpio_set_level(pn5180->nss, 1);
        return false;
    }
    gpio_set_level(pn5180->nss, 1);
    if (!wait_busy_level(pn5180, 0, "wait for idle after recv")) {
        return false;
    }
    memcpy(recv_data, pn5180->recv_buf, recv_data_len);
    return true;
}

static bool write_register_command(pn5180_t *pn5180, uint8_t cmd, uint8_t reg, uint32_t value)
{
    uint8_t send_buf[6];
    send_buf[0] = cmd;
    send_buf[1] = reg;
    send_buf[2] = value & 0xFF;
    send_buf[3] = (value >> 8) & 0xFF;
    send_buf[4] = (value >> 16) & 0xFF;
    send_buf[5] = (value >> 24) & 0xFF;
    return transceive_command(pn5180, send_buf, sizeof(send_buf), NULL, 0);
}

bool pn5180_writeRegister(pn5180_t *pn5180, uint8_t reg, uint32_t value)
{
    bool ret = write_register_command(pn5180, PN5180_WRITE_REGISTER, reg, value);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to write register 0x%02X", reg);
    }
    return ret;
}

bool pn5180_writeRegisterWithOrMask(pn5180_t *pn5180, uint8_t addr, uint32_t mask)
{
    bool ret = write_register_command(pn5180, PN5180_WRITE_REGISTER_OR_MASK, addr, mask);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to write register with OR mask 0x%02X", addr);
    }
    return ret;
}
bool pn5180_writeRegisterWithAndMask(pn5180_t *pn5180, uint8_t addr, uint32_t mask)
{
    bool ret = write_register_command(pn5180, PN5180_WRITE_REGISTER_AND_MASK, addr, mask);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to write register with AND mask 0x%02X", addr);
    }
    return ret;
}

bool pn5180_readRegister(pn5180_t *pn5180, uint8_t reg, uint32_t *pvalue)
{
    uint8_t cmd_buf[2];
    cmd_buf[0] = PN5180_READ_REGISTER;
    cmd_buf[1] = reg;
    uint8_t value[4];
    bool    ret = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), value, sizeof(value));
    if (!ret) {
        ESP_LOGE(TAG, "Failed to read register 0x%02X", reg);
        return ret;
    }
    if (pvalue == NULL) {
        ESP_LOGE(TAG, "pn5180_readRegister: pvalue is NULL");
        return false;
    }
    *pvalue = (value[3] << 24) | (value[2] << 16) | (value[1] << 8) | value[0];
    return ret;
}

/**
 * @brief READ_EEPROM command (0x07)
 *
 * This command is used to read data from EEPROM memory area. The field 'Address'
 * indicates the start address of the read operation. The field Length indicates the number
 * of bytes to read. The response contains the data read from EEPROM (content of the
 * EEPROM); The data is read in sequentially increasing order starting with the given
 * address.
 *
 * EEPROM Address must be in the range from 0 to 254, inclusive. Read operation must
 * not go beyond EEPROM address 254. If the condition is not fulfilled, an exception is
 * raised.
 *
 * @param pn5180 Pointer to PN5180 device structure
 * @param addr Starting EEPROM address (0-254)
 * @param buffer Buffer to store read data
 * @param len Number of bytes to read
 * @return true on success, false on failure
 */
bool pn5180_readEEprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len)
{
    uint8_t cmd_buf[3];
    if (addr > 254 || (addr + len) > 254) {
        ESP_LOGE(TAG, "EEPROM read address out of range: addr=0x%02X, len=%d", addr, len);
        return false;
    }
    cmd_buf[0] = PN5180_READ_EEPROM;
    cmd_buf[1] = addr;
    cmd_buf[2] = len;
    bool ret   = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), buffer, len);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to read EEPROM at address 0x%02X", addr);
    }
    return ret;
}

bool pn5180_writeEEprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len)
{
    uint8_t *cmd_buf = (uint8_t *)malloc(2 + len);
    if (cmd_buf == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for EEPROM write command");
        return false;
    }
    cmd_buf[0] = PN5180_WRITE_EEPROM;
    cmd_buf[1] = addr;
    memcpy(&cmd_buf[2], buffer, len);
    bool ret = transceive_command(pn5180, cmd_buf, 2 + len, NULL, 0);
    free(cmd_buf);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to write EEPROM at address 0x%02X", addr);
    }
    return ret;
}

pn5180_transceive_state_t pn5180_getTransceiveState(pn5180_t *pn5180)
{
    uint32_t status;
    if (!pn5180_readRegister(pn5180, RF_STATUS, &status)) {
        ESP_LOGE(TAG, "Failed to read RF_STATUS register");
        return PN5180_TS_Idle;
    }
    uint8_t state = ((status >> 24) & 0x07);
    return (pn5180_transceive_state_t)state;
}

bool pn5180_sendData(pn5180_t *pn5180, const uint8_t *data, int len, uint8_t validBits)
{
    if (len > 260) {
        ESP_LOGE(TAG, "sendData: Data length exceeds maximum allowed size of 260 bytes");
        return false;
    }
    if (validBits > 7) {
        ESP_LOGE(TAG, "sendData: validBits must be in the range 0-7");
        return false;
    }

    if (!pn5180_set_transceiver_idle(pn5180)) {
        ESP_LOGE(TAG, "sendData: Failed to set Idle/StopCom Command before sending data");
        return false;
    }
    if (!pn5180_writeRegisterWithOrMask(pn5180, SYSTEM_CONFIG, 0x00000003)) {
        ESP_LOGE(TAG, "sendData: Failed to set Transceive Command before sending data");
        return false;
    }

    pn5180_transceive_state_t state;

    int64_t tstate_deadline = esp_timer_get_time() + (pn5180->timeout_ms * 1000LL);
    do {
        state = pn5180_getTransceiveState(pn5180);
        if (esp_timer_get_time() > tstate_deadline) {
            ESP_LOGE(TAG, "sendData: timeout waiting for transmitting state");
            return false;
        }
    } while (state != PN5180_TS_WaitTransmit);

    pn5180_clearAllIRQs(pn5180);

    uint8_t  small_send_buf[32];
    uint8_t *send_buf;
    if (len + 2 <= sizeof(small_send_buf)) {
        send_buf = small_send_buf;
    } else {
        send_buf = (uint8_t *)malloc(len + 2);
        if (send_buf == NULL) {
            ESP_LOGE(TAG, "sendData: Failed to allocate memory for send buffer");
            return false;
        }
    }
    send_buf[0] = PN5180_SEND_DATA;
    send_buf[1] = validBits;
    if (len != 0 && data != NULL) {
        memcpy(&send_buf[2], data, len);
    }

    bool ret = transceive_command(pn5180, send_buf, len + 2, NULL, 0);
    if (!ret) {
        ESP_LOGE(TAG, "sendData: Failed to send data");
    }
    if (send_buf != small_send_buf) free(send_buf);
    return ret;
}

/**
 * @brief READ_DATA command (0x0A)
 *
 * This command reads data from the RF reception buffer, after a successful reception.
 * The RX_STATUS register contains the information to verify if the reception had been
 * successful. The data is available within the response of the command. The host controls
 * the number of bytes to be read via the SPI interface.
 *
 * The RF data had been successfully received. In case the instruction is executed without
 * preceding an RF data reception, no exception is raised but the data read back from the
 * reception buffer is invalid. If the condition is not fulfilled, an exception is raised.
 *
 * @param pn5180 Pointer to PN5180 device structure
 * @param len Number of bytes to read (0-508)
 * @param buffer Buffer to store received data
 * @return true on success, false on failure
 */
bool pn5180_readData(pn5180_t *pn5180, int len, uint8_t *buffer)
{
    if (len < 0 || len > 508) {
        ESP_LOGE(TAG, "Data length for readData out of range: len=%d", len);
        return false;
    }
    if (buffer == NULL) {
        ESP_LOGE(TAG, "readData: buffer pointer is NULL");
        return false;
    }
    uint8_t cmd_buf[2] = {PN5180_READ_DATA, 0};

    bool ret = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), buffer, len);
    if (!ret) {
        ESP_LOGE(TAG, "readData: Failed to read data");
    }
    return ret;
}

void pn5180_deinit(pn5180_t *pn5180, bool free_spi_bus)
{
    if (pn5180) {
        spi_bus_remove_device(pn5180->spi->spi_handle);
        if (free_spi_bus) {
            spi_bus_free(pn5180->spi->host_id);
        }
        free(pn5180->spi);
        free(pn5180->send_buf);
        free(pn5180->recv_buf);
        free(pn5180);
    }
}

bool pn5180_prepareLPCD(pn5180_t *pn5180)
{
    uint8_t data[255];
    uint8_t response[256];
    uint8_t fieldOn = 0xF0;
    data[0]         = fieldOn;
    if (pn5180_writeEEprom(pn5180, LPCD_FIELD_ON_TIME, data, 1) && pn5180_readEEprom(pn5180, LPCD_FIELD_ON_TIME, response, 1)) {
        fieldOn = response[0];
        PN5180_LOGD(TAG, "LPCD Field On Time set to %d us", 62 + (fieldOn * 8));
    } else {
        ESP_LOGE(TAG, "Failed to set LPCD Field On Time");
        return false;
    }
    uint8_t threshold = 0x03;
    data[0]           = threshold;
    if (pn5180_writeEEprom(pn5180, LPCD_THRESHOLD_LEVEL, data, 1) && pn5180_readEEprom(pn5180, LPCD_THRESHOLD_LEVEL, response, 1)) {
        threshold = response[0];
        PN5180_LOGD(TAG, "LPCD Threshold Level set to %d", threshold);
    } else {
        ESP_LOGE(TAG, "Failed to set LPCD Threshold Level");
        return false;
    }
    if (pn5180_readEEprom(pn5180, LPCD_THRESHOLD_LEVEL, response, 1)) {
        threshold = response[0];
        PN5180_LOGD(TAG, "LPCD Threshold Level set to %d", threshold);
    } else {
        ESP_LOGE(TAG, "Failed to read back LPCD Threshold Level");
        return false;
    }
    uint8_t lpcdMode = 0x01;
    data[0]          = lpcdMode;
    if (pn5180_writeEEprom(pn5180, LPCD_REFVAL_GPO_CONTROL, data, 1) && pn5180_readEEprom(pn5180, LPCD_REFVAL_GPO_CONTROL, response, 1)) {
        lpcdMode = response[0];
        PN5180_LOGD(TAG, "LPCD Reference Value Selection and GPO control set to 0x%02X", lpcdMode);
    } else {
        ESP_LOGE(TAG, "Failed to set LPCD Reference Value Selection and GPO control");
        return false;
    }
    uint8_t beforeFieldOn = 0xF0;
    data[0]               = beforeFieldOn;
    if (pn5180_writeEEprom(pn5180, LPCD_GPO_TOGGLE_BEFORE_FIELD_ON, data, 1) && pn5180_readEEprom(pn5180, LPCD_GPO_TOGGLE_BEFORE_FIELD_ON, response, 1)) {
        beforeFieldOn = response[0];
        PN5180_LOGD(TAG, "LPCD GPO Toggle Before Field On set to 0x%02X", beforeFieldOn);
    } else {
        ESP_LOGE(TAG, "Failed to set LPCD GPO Toggle Before Field On");
        return false;
    }
    uint8_t afterFieldOn = 0xF0;
    data[0]              = afterFieldOn;
    if (pn5180_writeEEprom(pn5180, LPCD_GPO_TOGGLE_AFTER_FIELD_ON, data, 1) && pn5180_readEEprom(pn5180, LPCD_GPO_TOGGLE_AFTER_FIELD_ON, response, 1)) {
        afterFieldOn = response[0];
        PN5180_LOGD(TAG, "LPCD GPO Toggle After Field On set to 0x%02X", afterFieldOn);
    } else {
        ESP_LOGE(TAG, "Failed to set LPCD GPO Toggle After Field On");
        return false;
    }
    return true;
}

uint32_t pn5180_getIRQStatus(pn5180_t *pn5180)
{
    uint32_t irqStatus = 0;
    if (!pn5180_readRegister(pn5180, IRQ_STATUS, &irqStatus)) {
        ESP_LOGE(TAG, "Failed to read IRQ_STATUS register");
        return 0;
    }
    return irqStatus;
}

bool pn5180_clearIRQStatus(pn5180_t *pn5180, uint32_t irqMask)
{
    bool ret = pn5180_writeRegister(pn5180, IRQ_CLEAR, irqMask);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to clear IRQ status with mask 0x%" PRIu32 "08X", irqMask);
    }
    return ret;
}

bool pn5180_switchToLPCD(pn5180_t *pn5180, uint16_t wakeupCounterInMs)
{
    pn5180_clearAllIRQs(pn5180);
    pn5180_writeRegister(                      //
        pn5180,                                //
        IRQ_ENABLE,                            //
        LPCD_IRQ_STAT | GENERAL_ERROR_IRQ_STAT //
    );
    uint8_t cmd_buf[] = {
        PN5180_SWITCH_MODE,                         //
        0x01,                                       //
        (uint8_t)(wakeupCounterInMs & 0xFF),        //
        (uint8_t)((wakeupCounterInMs >> 8U) & 0xFF) //
    };
    bool ret = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), NULL, 0);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to switch to LPCD mode");
    }
    return ret;
}

uint32_t pn5180_rxBytesReceived(pn5180_t *pn5180)
{
    uint32_t rxStatus;
    uint32_t len = 0;

    if (!pn5180_readRegister(pn5180, RX_STATUS, &rxStatus)) {
        ESP_LOGE(TAG, "Failed to read RX_STATUS register");
        return 0;
    }
    len = rxStatus & RX_BYTES_RECEIVED_MASK;
    return len;
}

int16_t pn5180_mifareAuthenticate(pn5180_t *pn5180, uint8_t blockno, const uint8_t *key, uint8_t keyType, const uint8_t uid[4])
{
    if (keyType != 0x60 && keyType != 0x61) {
        ESP_LOGE(TAG, "Invalid key type 0x%02X for MIFARE authentication", keyType);
        return -1;
    }
    uint8_t cmd_buf[13];
    uint8_t rcvBuffer[1];

    // Format per PN5180 datasheet: [Cmd][Key(6)][KeyType][Block][UID(4)]
    cmd_buf[0] = PN5180_MIFARE_AUTHENTICATE;
    memcpy(&cmd_buf[1], key, 6);
    cmd_buf[7] = keyType; // 0x60 Key A, 0x61 Key B
    cmd_buf[8] = blockno; // block within sector to auth
    memcpy(&cmd_buf[9], uid, 4);

    PN5180_LOGD(TAG,
                "AUTH cmd: [Cmd=0x%02X][Key=%02X %02X %02X %02X %02X %02X][KeyType=0x%02X][Block=0x%02X][UID=%02X %02X "
                "%02X %02X]",
                cmd_buf[0], cmd_buf[1], cmd_buf[2], cmd_buf[3], cmd_buf[4], cmd_buf[5], cmd_buf[6], cmd_buf[7], cmd_buf[8], cmd_buf[9], cmd_buf[10],
                cmd_buf[11], cmd_buf[12]);

    bool rc = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), rcvBuffer, 1);
    if (!rc) {
        ESP_LOGE(TAG, "Failed to perform MIFARE authentication SPI transaction");
        return -3;
    }
    PN5180_LOGD(TAG, "AUTH response byte: 0x%02X", rcvBuffer[0]);

    // Check response code first - if not 0x00, authentication failed
    if (rcvBuffer[0] != 0x00) {
        PN5180_LOGD(TAG, "Authentication failed (response: 0x%02X) - resetting transceiver state", rcvBuffer[0]);
        // Clear Crypto1 bit and reset transceiver to clean state
        pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_CLEAR_CRYPTO_MASK); // Clear MFC_CRYPTO_ON
        pn5180_set_transceiver_idle(pn5180);

        // Flush any stale data from RX buffer
        uint32_t rxStatus;
        if (pn5180_readRegister(pn5180, RX_STATUS, &rxStatus)) {
            uint16_t rxLen = rxStatus & RX_BYTES_RECEIVED_MASK;
            if (rxLen > 0 && rxLen < 512) {
                uint8_t dummy[512];
                pn5180_readData(pn5180, rxLen, dummy);
            }
        }

        pn5180_clearAllIRQs(pn5180);

        // Wait for transceiver to reach idle state before returning
        pn5180_transceive_state_t tstate;
        int64_t                   deadline = esp_timer_get_time() + 50 * 1000; // 50ms max
        do {
            tstate = pn5180_getTransceiveState(pn5180);
            if (tstate == PN5180_TS_Idle) {
                break;
            }
            esp_rom_delay_us(10);
        } while (esp_timer_get_time() < deadline);

        return rcvBuffer[0];
    }

    // Authentication response is 0x00 (success) - wait briefly for transceiver readiness
    // Avoid long IRQ polling; prefer checking transceive state
    pn5180_transceive_state_t tstate;

    int64_t deadline = esp_timer_get_time() + 50 * 1000; // 50ms max
    do {
        tstate = pn5180_getTransceiveState(pn5180);
        if (tstate == PN5180_TS_WaitTransmit || tstate == PN5180_TS_Idle) {
            break;
        }
        esp_rom_delay_us(10);
    } while (esp_timer_get_time() < deadline);

    pn5180_clearAllIRQs(pn5180);

    return 0x00;
}

/**
 * @brief LOAD_RF_CONFIG command (0x11)
 *
 * Parameter 'Transmitter Configuration' must be in the range from 0x0 - 0x1C, inclusive. If
 * the transmitter parameter is 0xFF, transmitter configuration is not changed.
 * Field 'Receiver Configuration' must be in the range from 0x80 - 0x9C, inclusive. If the
 * receiver parameter is 0xFF, the receiver configuration is not changed. If the condition is
 * not fulfilled, an exception is raised.
 *
 * The transmitter and receiver configuration shall always be configured for the same
 * transmission/reception speed. No error is returned in case this condition is not taken into
 * account.
 *
 * ## PN5180 RF Configuration Table (LOAD_RF_CONFIG)
 *
 * | Speed            | TX   | RX   | Protocol                       |
|:----------------:|:----:|:----:|--------------------------------|
| **106 kbit/s**   | 0x00 | 0x80 | ISO 14443-A / NFC Type A       |
| **212 kbit/s**   | 0x01 | 0x81 | ISO 14443-A                    |
| **424 kbit/s**   | 0x02 | 0x82 | ISO 14443-A                    |
| **848 kbit/s**   | 0x03 | 0x83 | ISO 14443-A                    |
| **106 kbit/s**   | 0x04 | 0x84 | ISO 14443-B                    |
| **212 kbit/s**   | 0x05 | 0x85 | ISO 14443-B                    |
| **424 kbit/s**   | 0x06 | 0x86 | ISO 14443-B                    |
| **848 kbit/s**   | 0x07 | 0x87 | ISO 14443-B                    |
| **212 kbit/s**   | 0x08 | 0x88 | FeliCa / NFC Type F            |
| **424 kbit/s**   | 0x09 | 0x89 | FeliCa / NFC Type F            |
| **106 kbit/s**   | 0x0A | 0x8A | NFC-Active Initiator           |
| **212 kbit/s**   | 0x0B | 0x8B | NFC-Active Initiator           |
| **424 kbit/s**   | 0x0C | 0x8C | NFC-Active Initiator           |
| **26 kbit/s**    | 0x0D | 0x8D | ISO 15693 (ASK100)             |
| **26 kbit/s**    | 0x0E | 0x8E | ISO 15693 (ASK10)              |
| Tari=18.88 / 106 | 0x0F | 0x8F | ISO 18000-3M3 Manchester 424_4 |
| Tari=9.44 / 212  | 0x10 | 0x90 | ISO 18000-3M3 Manchester 424_2 |
| Tari=18.88 / 212 | 0x11 | 0x91 | ISO 18000-3M3 Manchester 848_4 |
| Tari=9.44 / 424  | 0x12 | 0x92 | ISO 18000-3M3 Manchester 848_2 |
| **106 kbit/s**   | 0x13 | 0x93 | ISO 14443-A PICC               |
| **212 kbit/s**   | 0x14 | 0x94 | ISO 14443-A PICC               |
| **424 kbit/s**   | 0x15 | 0x95 | ISO 14443-A PICC               |
| **848 kbit/s**   | 0x16 | 0x96 | ISO 14443-A PICC               |
| **212 kbit/s**   | 0x17 | 0x97 | NFC Passive Target             |
| **424 kbit/s**   | 0x18 | 0x98 | NFC Passive Target             |
| **106 kbit/s**   | 0x19 | 0x99 | NFC Active Target              |
| **212 kbit/s**   | 0x1A | 0x9A | NFC Active Target              |
| **424 kbit/s**   | 0x1B | 0x9B | NFC Active Target              |
| **ALL**          | 0x1C | 0x9C | GTM (General Target Mode)      |

*/

bool pn5180_loadRFConfig(pn5180_t *pn5180, uint8_t txConf)
{
    uint8_t cmd_buf[3];
    cmd_buf[0] = PN5180_LOAD_RF_CONFIG;
    cmd_buf[1] = txConf;
    cmd_buf[2] = txConf | 0x80; // RX config is TX config + 0x80
    bool ret   = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), NULL, 0);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to load RF config");
    } else {
        pn5180->tx_config = txConf;
    }
    return ret;
}

bool pn5180_setRF_on(pn5180_t *pn5180)
{
    if (pn5180->is_rf_on) {
        return true; // already on
    }
    uint8_t  cmd_buf[] = {PN5180_RF_ON, 0};
    uint32_t rfStatus  = 0;
    uint32_t irqStatus = 0;
    bool     rc        = false;

    for (int attempt = 0; attempt < 3; attempt++) {
        pn5180_clearAllIRQs(pn5180);
        rc = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), NULL, 0);
        if (!rc) {
            ESP_LOGE(TAG, "Failed to set RF on");
        }

        int64_t rf_on_deadline = esp_timer_get_time() + (1000LL * pn5180->timeout_ms);
        rfStatus               = 0;
        while (esp_timer_get_time() < rf_on_deadline) {
            irqStatus = pn5180_getIRQStatus(pn5180);
            if (irqStatus & (RFON_DET_IRQ_STAT | TX_RFON_IRQ_STAT)) {
                pn5180_clearIRQStatus(pn5180, (RFON_DET_IRQ_STAT | TX_RFON_IRQ_STAT));
                break; // RF on detected by IRQ
            }
            if (pn5180_readRegister(pn5180, RF_STATUS, &rfStatus)) {
                if (rfStatus & 0x01) {
                    break; // RF is on
                }
            }
            esp_rom_delay_us(10);
        }

        if ((rfStatus & 0x01) != 0 || (irqStatus & (RFON_DET_IRQ_STAT | TX_RFON_IRQ_STAT))) {
            pn5180->is_rf_on = true;
            return true;
        }

        pn5180_delay_ms(10); // brief delay before retry
    }

    ESP_LOGE(TAG, "RF field is NOT on! RF_STATUS=0x%08" PRIx32 " IRQ_STATUS=0x%08" PRIx32, rfStatus, irqStatus);
    return false;
}

bool pn5180_setRF_off(pn5180_t *pn5180)
{
    uint32_t rfStatus = 0;
    if (pn5180_readRegister(pn5180, RF_STATUS, &rfStatus)) {
        if ((rfStatus & 0x01) == 0) {
            pn5180->is_rf_on = false;
            return true;
        }
    }
    uint8_t cmd_buf[] = {PN5180_RF_OFF, 0};
    bool    rc        = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), NULL, 0);
    if (!rc) {
        ESP_LOGE(TAG, "Failed to set RF off");
    }
    int64_t deadline = esp_timer_get_time() + (1000LL * pn5180->timeout_ms);
    while (0 == (TX_RFOFF_IRQ_STAT & pn5180_getIRQStatus(pn5180))) {
        if (pn5180_readRegister(pn5180, RF_STATUS, &rfStatus)) {
            if ((rfStatus & 0x01) == 0) {
                break; // RF already off
            }
        }
        if (esp_timer_get_time() > deadline) {
            ESP_LOGE(TAG, "Timeout waiting for RF off");
            return false;
        }
        pn5180_delay_ms(10); // brief delay before retry
    }
    pn5180->is_rf_on = false;
    pn5180_clearIRQStatus(pn5180, TX_RFOFF_IRQ_STAT);
    return true;
}

bool pn5180_sendCommand(pn5180_t *pn5180, uint8_t *sendBuffer, size_t sendBufferLen, uint8_t *recvBuffer, size_t recvBufferLen)
{
    bool ret = transceive_command(pn5180, sendBuffer, sendBufferLen, recvBuffer, recvBufferLen);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to send command");
    }
    return ret;
}

bool pn5180_reset(pn5180_t *pn5180)
{
    gpio_set_level(pn5180->rst, 0);
    esp_rom_delay_us(50);
    gpio_set_level(pn5180->rst, 1);
    pn5180_delay_ms(100);
    int64_t saved_timeout = pn5180->timeout_ms;
    pn5180->timeout_ms    = 5000; // increase timeout for boot process
    if (!wait_busy_level(pn5180, 0, "after reset")) {
        ESP_LOGE(TAG, "Failed to boot after reset (BUSY stuck High)");
        pn5180->timeout_ms = saved_timeout;
        return false;
    }
    pn5180->timeout_ms   = saved_timeout;
    int64_t deadline     = esp_timer_get_time() + (1000LL * pn5180->timeout_ms);
    int     attempts     = 1;
    int     max_attempts = 3;
    // Some boards may miss the initial IDLE IRQ after reset; retry with longer pulses.
    while (0 == (IDLE_IRQ_STAT & pn5180_getIRQStatus(pn5180))) { // wait for system to start up (with timeout)
        if (esp_timer_get_time() > deadline) {
            ESP_LOGE(TAG, "Failed to boot after reset (IDLE IRQ not set), attempts=%d", attempts);
            if (++attempts >= max_attempts) {
                return false;
            }
            gpio_set_level(pn5180->rst, 0);
            pn5180_delay_ms(50 + attempts * 10);
            gpio_set_level(pn5180->rst, 1);
            pn5180_delay_ms(100 + attempts * 20);
            deadline = esp_timer_get_time() + (1000LL * pn5180->timeout_ms);
        }
        esp_rom_delay_us(10);
    }
    if (!wait_busy_level(pn5180, 0, "after reset")) {
        ESP_LOGE(TAG, "Failed to boot after reset (BUSY stuck High after IDLE IRQ)");
        return false;
    }
    pn5180->is_rf_on = false;
    return true;
}

bool pn5180_wait_for_irq(pn5180_t *pn5180, uint32_t irq_mask, const char *operation, uint32_t *irqStatus)
{
    int64_t deadline = esp_timer_get_time() + (1000LL * pn5180->timeout_ms);
    while (true) {
        *irqStatus = pn5180_getIRQStatus(pn5180);
        if (*irqStatus & (irq_mask | GENERAL_ERROR_IRQ_STAT)) {
            if (*irqStatus & GENERAL_ERROR_IRQ_STAT) {
                ESP_LOGW(TAG, "General error detected during %s", operation);
            }
            // Clear IRQs to avoid stale bits leaking into the next transaction.
            pn5180_clearAllIRQs(pn5180);
            return true;
        }
        if (esp_timer_get_time() > deadline) {
            ESP_LOGE(TAG, "Timeout waiting for %s", operation);
            pn5180_clearAllIRQs(pn5180);
            return false;
        }
        esp_rom_delay_us(10);
    }
}

bool pn5180_wait_read_rx(     //
    pn5180_t   *pn5180,       //
    uint32_t    irq_mask,     //
    const char *operation,    //
    uint8_t    *buffer,       //
    size_t      buffer_len,   //
    uint16_t   *out_len,      //
    uint32_t   *out_rx_status //
)
{
    uint32_t irq_status = 0;
    if (!pn5180_wait_for_irq(pn5180, irq_mask, operation, &irq_status)) {
        return false;
    }
    if (irq_status & GENERAL_ERROR_IRQ_STAT) {
        return false;
    }
    if (!(irq_status & RX_IRQ_STAT)) {
        return false;
    }

    uint32_t rx_status = 0;
    if (!pn5180_readRegister(pn5180, RX_STATUS, &rx_status)) {
        return false;
    }
    if (rx_status & (RX_PROTOCOL_ERROR | RX_DATA_INTEGRITY_ERROR)) {
        return false;
    }

    uint16_t rx_len = (uint16_t)(rx_status & RX_BYTES_RECEIVED_MASK);
    if (out_len) {
        *out_len = rx_len;
    }
    if (out_rx_status) {
        *out_rx_status = rx_status;
    }

    if (buffer == NULL) {
        return true;
    }
    if (rx_len == 0) {
        return true;
    }

    if (rx_len <= buffer_len) {
        return pn5180_readData(pn5180, rx_len, buffer);
    }

    uint8_t *temp = (uint8_t *)malloc(rx_len);
    if (!temp) {
        return false;
    }
    bool ok = pn5180_readData(pn5180, rx_len, temp);
    if (ok && buffer_len > 0) {
        memcpy(buffer, temp, buffer_len);
    }
    free(temp);
    return ok;
}
