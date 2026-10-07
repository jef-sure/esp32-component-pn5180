#include "pn5180.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "pn5180-internal.h"
#include <inttypes.h>
#include <string.h>

// PN5180 1-Byte Direct Commands
// see 11.4.3.3 Host Interface Command List
#define PN5180_WRITE_REGISTER          (0x00)
#define PN5180_WRITE_REGISTER_OR_MASK  (0x01)
#define PN5180_WRITE_REGISTER_AND_MASK (0x02)
#define PN5180_WRITE_REGISTER_MULTIPLE (0x03)
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
#define LPCD_FIELD_ON_TIME   (0x36) // LPCD RF on time (μs) = 8 * LPCD_FIELD_ON_TIME
// LPCD wakes up if |current AGC - AGC reference| > LPCD_THRESHOLD (03..08: very sensitive, 40..50: very robust)
#define LPCD_THRESHOLD_LEVEL            (0x37)
#define LPCD_REFVAL_GPO_CONTROL         (0x38) // LPCD Reference Value Selection and GPO control
#define LPCD_GPO_TOGGLE_BEFORE_FIELD_ON (0x39) // time from GPO set to field on, 5 μs steps
#define LPCD_GPO_TOGGLE_AFTER_FIELD_OFF (0x3A) // time from field off to GPO clear, 5 μs steps

static const char TAG[] = "PN5180";

static bool pn5180_validate_eeprom_read(uint8_t addr, int len)
{
    if (len <= 0 || len > 0xFF) {
        return false;
    }
    if (addr > PN5180_EEPROM_MAX_ADDR) {
        return false;
    }

    return (uint32_t)len <= ((uint32_t)PN5180_EEPROM_MAX_ADDR - (uint32_t)addr + 1u);
}

static bool pn5180_validate_eeprom_write(uint8_t addr, int len)
{
    if (len <= 0 || len > 0xFF) {
        return false;
    }
    if (addr < PN5180_EEPROM_MIN_ADDR || addr > PN5180_EEPROM_MAX_ADDR) {
        return false;
    }

    return (uint32_t)len <= ((uint32_t)PN5180_EEPROM_MAX_ADDR - (uint32_t)addr + 1u);
}

static bool pn5180_read_firmware_version(pn5180_t *pn5180, uint16_t *fw_version)
{
    uint8_t eeprom_data[2];

    if (fw_version == NULL) {
        return false;
    }
    if (!pn5180_read_eeprom(pn5180, PN5180_FIRMWARE_VERSION, eeprom_data, sizeof(eeprom_data))) {
        return false;
    }
    if (eeprom_data[0] == 0xFF && eeprom_data[1] == 0xFF) {
        return false;
    }

    *fw_version = (uint16_t)((uint16_t)eeprom_data[1] << 8) | eeprom_data[0];
    return true;
}

// Microsecond delay: sleeps whole ticks and busy-waits the remainder.
static void pn5180_delay_us(uint32_t us)
{
    int64_t end     = esp_timer_get_time() + us;
    int64_t tick_us = (int64_t)portTICK_PERIOD_MS * 1000;
    while (end - esp_timer_get_time() > tick_us) {
        vTaskDelay(1);
    }
    int64_t remaining = end - esp_timer_get_time();
    if (remaining > 0) {
        esp_rom_delay_us((uint32_t)remaining);
    }
}

void pn5180_delay_ms(int ms)
{
    if (ms > 0) {
        pn5180_delay_us((uint32_t)ms * 1000u);
    }
}

// Adds the PN5180 as a device on an initialized bus. NSS is driven by the driver, not by the SPI master.
static bool pn5180_spi_add_device(pn5180_spi_t *spi, spi_host_device_t host_id, int clock_speed_hz)
{
    spi_device_interface_config_t dev_config = {
        .clock_speed_hz = clock_speed_hz, //
        .mode           = 0,              //
        .spics_io_num   = GPIO_NUM_NC,    //
        .queue_size     = 2,              //
        .flags          = 0               //
    };
    if (spi_bus_add_device(host_id, &dev_config, &spi->spi_handle) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add SPI device");
        return false;
    }
    spi->host_id        = host_id;
    spi->clock_speed_hz = clock_speed_hz;
    return true;
}

pn5180_spi_t *pn5180_spi_attach(spi_host_device_t host_id, int clock_speed_hz)
{
    pn5180_spi_t *spi = (pn5180_spi_t *)calloc(1, sizeof(pn5180_spi_t));
    if (spi == NULL) {
        return NULL;
    }
    if (!pn5180_spi_add_device(spi, host_id, clock_speed_hz)) {
        free(spi);
        return NULL;
    }
    spi->owns_bus = false;
    spi->sck      = GPIO_NUM_NC;
    spi->miso     = GPIO_NUM_NC;
    spi->mosi     = GPIO_NUM_NC;
    return spi;
}

void pn5180_spi_deinit(pn5180_spi_t *spi, bool free_spi_bus)
{
    if (spi == NULL) {
        return;
    }
    spi_bus_remove_device(spi->spi_handle);
    if (free_spi_bus && spi->owns_bus) {
        spi_bus_free(spi->host_id);
    }
    free(spi);
}

pn5180_spi_t *pn5180_spi_init(       //
    spi_host_device_t host_id,       //
    gpio_num_t        sck,           //
    gpio_num_t        miso,          //
    gpio_num_t        mosi,          //
    int               clock_speed_hz //
)
{

    pn5180_spi_t *spi = (pn5180_spi_t *)calloc(1, sizeof(pn5180_spi_t));
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

    if (spi_bus_initialize(host_id, &bus_config, SPI_DMA_CH_AUTO) != ESP_OK) {
        free(spi);
        ESP_LOGE(TAG, "Failed to initialize SPI bus");
        return NULL;
    }
    if (!pn5180_spi_add_device(spi, host_id, clock_speed_hz)) {
        spi_bus_free(host_id);
        free(spi);
        return NULL;
    }
    spi->owns_bus = true;
    spi->sck      = sck;
    spi->miso     = miso;
    spi->mosi     = mosi;
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

static void pn5180_poll_timer_cb(void *arg)
{
    xSemaphoreGive((SemaphoreHandle_t)arg);
}

// Sleeps for about us microseconds with the CPU released. vTaskDelay() cannot do this: it sleeps
// whole ticks, typically 10 ms.
static void pn5180_poll_sleep(pn5180_t *pn5180, uint32_t us)
{
    // A tick that is no longer than the wanted sleep makes vTaskDelay() precise enough.
    if (pn5180->poll_timer == NULL || (uint32_t)portTICK_PERIOD_MS * 1000u <= us) {
        vTaskDelay(1);
        return;
    }
    esp_timer_handle_t timer = (esp_timer_handle_t)pn5180->poll_timer;
    xSemaphoreTake((SemaphoreHandle_t)pn5180->poll_sem, 0);
    if (esp_timer_start_once(timer, us) != ESP_OK) {
        vTaskDelay(1);
        return;
    }
    // The tick timeout is only a backstop in case the timer does not fire.
    xSemaphoreTake((SemaphoreHandle_t)pn5180->poll_sem, pdMS_TO_TICKS(us / 1000 + 20) + 1);
    esp_timer_stop(timer);
}

// Frees only what pn5180_init() allocated; the SPI structure stays with the caller.
static void pn5180_free(pn5180_t *pn5180)
{
    if (pn5180->irq_sem != NULL) {
        gpio_isr_handler_remove(pn5180->irq);
        vSemaphoreDelete((SemaphoreHandle_t)pn5180->irq_sem);
    }
    if (pn5180->poll_timer != NULL) {
        esp_timer_stop((esp_timer_handle_t)pn5180->poll_timer);
        esp_timer_delete((esp_timer_handle_t)pn5180->poll_timer);
    }
    if (pn5180->poll_sem != NULL) {
        vSemaphoreDelete((SemaphoreHandle_t)pn5180->poll_sem);
    }
    free(pn5180->send_buf);
    free(pn5180->recv_buf);
    free(pn5180);
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
    ret->spi              = spi;
    ret->nss              = nss;
    ret->busy             = busy;
    ret->rst              = rst;
    ret->irq              = GPIO_NUM_NC;
    ret->timeout_ms       = 500;
    ret->tx_config        = 0;
    ret->hw_rx_timeout    = true;
    ret->rf_guard_time_us = 5100;
    // Timer for sleeping between IRQ_STATUS polls with sub-tick precision. Without it the driver
    // still works, with tick-length sleeps.
    ret->poll_sem = xSemaphoreCreateBinary();
    if (ret->poll_sem != NULL) {
        const esp_timer_create_args_t poll_timer_args = {
            .callback = pn5180_poll_timer_cb, //
            .arg      = ret->poll_sem,        //
            .name     = "pn5180_poll"         //
        };
        esp_timer_handle_t poll_timer = NULL;
        if (esp_timer_create(&poll_timer_args, &poll_timer) == ESP_OK) {
            ret->poll_timer = poll_timer;
        } else {
            ESP_LOGW(TAG, "Failed to create poll timer, polling with tick resolution");
        }
    }
    // Set the idle levels before the pins become outputs so that NSS and RST do not glitch low.
    gpio_set_level(nss, 1);
    gpio_set_level(rst, 1);
    gpio_config_t out_cfg = {
        .pin_bit_mask = (1ULL << nss) | (1ULL << rst), //
        .mode         = GPIO_MODE_OUTPUT,              //
        .pull_up_en   = GPIO_PULLUP_DISABLE,           //
        .pull_down_en = GPIO_PULLDOWN_DISABLE,         //
        .intr_type    = GPIO_INTR_DISABLE              //
    };
    gpio_config_t busy_cfg = {
        .pin_bit_mask = (1ULL << busy),        //
        .mode         = GPIO_MODE_INPUT,       //
        .pull_up_en   = GPIO_PULLUP_DISABLE,   //
        .pull_down_en = GPIO_PULLDOWN_DISABLE, //
        .intr_type    = GPIO_INTR_DISABLE      //
    };
    gpio_config(&out_cfg);
    gpio_config(&busy_cfg);
    gpio_set_level(nss, 1);
    gpio_set_level(rst, 1);
    pn5180_delay_ms(100);
    if (!pn5180_reset(ret)) {
        ESP_LOGE(TAG, "Failed to reset PN5180 during init");
        pn5180_free(ret);
        return NULL;
    }
    uint16_t firmware_version = 0;
    if (!pn5180_read_firmware_version(ret, &firmware_version)) {
        ESP_LOGE(TAG, "Failed to read PN5180 firmware version");
        pn5180_free(ret);
        return NULL;
    }
    ret->firmware_version = firmware_version;
    if (firmware_version < PN5180_MIN_FIRMWARE_VERSION) {
        ESP_LOGE(TAG, "Unsupported PN5180 firmware version 0x%04X", firmware_version);
        pn5180_free(ret);
        return NULL;
    }

    uint8_t auth_timeout[2];
    if (!pn5180_read_eeprom(ret, MFC_AUTH_TIMEOUT, auth_timeout, sizeof(auth_timeout))) {
        ESP_LOGW(TAG, "Failed to read MFC_AUTH_TIMEOUT");
    } else {
        PN5180_LOGD(TAG, "PN5180 firmware version: 0x%04X", firmware_version);
        PN5180_LOGD(TAG, "Current MFC_AUTH_TIMEOUT: 0x%02X 0x%02X", auth_timeout[0], auth_timeout[1]);
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
// One SPI transfer framed by NSS. The bus is held only while NSS is low: with NSS high the PN5180
// ignores the bus, so other devices on a shared bus may use it while the PN5180 is busy with the command.
static bool pn5180_spi_transfer(pn5180_t *pn5180, spi_transaction_t *trans, const char *busy_msg)
{
    if (spi_device_acquire_bus(pn5180->spi->spi_handle, portMAX_DELAY) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to acquire SPI bus");
        return false;
    }
    gpio_set_level(pn5180->nss, 0);
    esp_rom_delay_us(10);
    bool ok = spi_device_polling_transmit(pn5180->spi->spi_handle, trans) == ESP_OK;
    if (!ok) {
        ESP_LOGE(TAG, "SPI transfer failed");
    } else {
        ok = wait_busy_level(pn5180, 1, busy_msg);
    }
    gpio_set_level(pn5180->nss, 1);
    spi_device_release_bus(pn5180->spi->spi_handle);
    return ok;
}

static bool transceive_command(pn5180_t *pn5180, const uint8_t *send_data, size_t send_data_len, uint8_t *recv_data, size_t recv_data_len)
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
    if (!pn5180_spi_transfer(pn5180, &trans, "wait for busy after transfer")) {
        return false;
    }
    // The PN5180 executes the command now; this can take long (RF_ON, LOAD_RF_CONFIG) and does not need the bus.
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
    if (!pn5180_spi_transfer(pn5180, &trans, "wait for busy after recv")) {
        return false;
    }
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

bool pn5180_write_register(pn5180_t *pn5180, uint8_t reg, uint32_t value)
{
    bool ret = write_register_command(pn5180, PN5180_WRITE_REGISTER, reg, value);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to write register 0x%02X", reg);
    }
    return ret;
}

bool pn5180_write_register_or_mask(pn5180_t *pn5180, uint8_t addr, uint32_t mask)
{
    bool ret = write_register_command(pn5180, PN5180_WRITE_REGISTER_OR_MASK, addr, mask);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to write register with OR mask 0x%02X", addr);
    }
    return ret;
}
bool pn5180_write_register_and_mask(pn5180_t *pn5180, uint8_t addr, uint32_t mask)
{
    bool ret = write_register_command(pn5180, PN5180_WRITE_REGISTER_AND_MASK, addr, mask);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to write register with AND mask 0x%02X", addr);
    }
    return ret;
}

bool pn5180_read_register(pn5180_t *pn5180, uint8_t reg, uint32_t *pvalue)
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
        ESP_LOGE(TAG, "pn5180_read_register: pvalue is NULL");
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
bool pn5180_read_eeprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len)
{
    uint8_t cmd_buf[3];
    if (buffer == NULL || !pn5180_validate_eeprom_read(addr, len)) {
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

bool pn5180_write_eeprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len)
{
    if (buffer == NULL || !pn5180_validate_eeprom_write(addr, len)) {
        ESP_LOGE(TAG, "EEPROM write address out of range: addr=0x%02X, len=%d", addr, len);
        return false;
    }

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

pn5180_transceive_state_t pn5180_get_transceive_state(pn5180_t *pn5180)
{
    uint32_t status;
    if (!pn5180_read_register(pn5180, PN5180_RF_STATUS, &status)) {
        ESP_LOGE(TAG, "Failed to read RF_STATUS register");
        return PN5180_TS_RESERVED;
    }
    uint8_t state = ((status >> 24) & 0x07);
    return (pn5180_transceive_state_t)state;
}

bool pn5180_send_data(pn5180_t *pn5180, const uint8_t *data, int len, uint8_t valid_bits)
{
    if (len > 260) {
        ESP_LOGE(TAG, "send_data: Data length exceeds maximum allowed size of 260 bytes");
        return false;
    }
    if (valid_bits > 7) {
        ESP_LOGE(TAG, "send_data: valid_bits must be in the range 0-7");
        return false;
    }

    if (!pn5180_set_transceiver_idle(pn5180)) {
        ESP_LOGE(TAG, "send_data: Failed to set Idle/StopCom Command before sending data");
        return false;
    }
    if (!pn5180_write_register_or_mask(pn5180, PN5180_SYSTEM_CONFIG, 0x00000003)) {
        ESP_LOGE(TAG, "send_data: Failed to set Transceive Command before sending data");
        return false;
    }

    pn5180_transceive_state_t state;

    int64_t tstate_deadline = esp_timer_get_time() + (pn5180->timeout_ms * 1000LL);
    do {
        state = pn5180_get_transceive_state(pn5180);
        if (esp_timer_get_time() > tstate_deadline) {
            ESP_LOGE(TAG, "send_data: timeout waiting for transmitting state");
            return false;
        }
    } while (state != PN5180_TS_WAIT_TRANSMIT);

    pn5180_clear_all_irqs(pn5180);

    uint8_t  small_send_buf[32];
    uint8_t *send_buf;
    if (len + 2 <= sizeof(small_send_buf)) {
        send_buf = small_send_buf;
    } else {
        send_buf = (uint8_t *)malloc(len + 2);
        if (send_buf == NULL) {
            ESP_LOGE(TAG, "send_data: Failed to allocate memory for send buffer");
            return false;
        }
    }
    send_buf[0] = PN5180_SEND_DATA;
    send_buf[1] = valid_bits;
    if (len != 0 && data != NULL) {
        memcpy(&send_buf[2], data, len);
    }

    bool ret = transceive_command(pn5180, send_buf, len + 2, NULL, 0);
    if (!ret) {
        ESP_LOGE(TAG, "send_data: Failed to send data");
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
bool pn5180_read_data(pn5180_t *pn5180, int len, uint8_t *buffer)
{
    if (len < 0 || len > 508) {
        ESP_LOGE(TAG, "Data length for read_data out of range: len=%d", len);
        return false;
    }
    if (buffer == NULL) {
        ESP_LOGE(TAG, "read_data: buffer pointer is NULL");
        return false;
    }
    uint8_t cmd_buf[2] = {PN5180_READ_DATA, 0};

    bool ret = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), buffer, len);
    if (!ret) {
        ESP_LOGE(TAG, "read_data: Failed to read data");
    }
    return ret;
}

void pn5180_deinit(pn5180_t *pn5180, bool free_spi_bus)
{
    if (pn5180) {
        pn5180_spi_deinit(pn5180->spi, free_spi_bus);
        pn5180_free(pn5180);
    }
}

// Writes one EEPROM byte only if it differs: the EEPROM has a limited number of write cycles.
static bool pn5180_eeprom_update_byte(pn5180_t *pn5180, uint8_t addr, uint8_t value, const char *name)
{
    uint8_t current = 0;
    if (!pn5180_read_eeprom(pn5180, addr, &current, 1)) {
        ESP_LOGE(TAG, "Failed to read %s", name);
        return false;
    }
    if (current == value) {
        PN5180_LOGD(TAG, "%s already 0x%02X", name, value);
        return true;
    }
    if (!pn5180_write_eeprom(pn5180, addr, &value, 1) || !pn5180_read_eeprom(pn5180, addr, &current, 1) || current != value) {
        ESP_LOGE(TAG, "Failed to set %s", name);
        return false;
    }
    PN5180_LOGD(TAG, "%s set to 0x%02X", name, value);
    return true;
}

bool pn5180_lpcd_prepare(pn5180_t *pn5180)
{
    // Field-on time 0xF0 * 8 us; threshold 3 (very sensitive); mode 01b = self calibration, GPO control off;
    // GPO toggle delays 0xF0 * 5 us.
    return pn5180_eeprom_update_byte(pn5180, LPCD_FIELD_ON_TIME, 0xF0, "LPCD Field On Time") &&
           pn5180_eeprom_update_byte(pn5180, LPCD_THRESHOLD_LEVEL, 0x03, "LPCD Threshold Level") &&
           pn5180_eeprom_update_byte(pn5180, LPCD_REFVAL_GPO_CONTROL, 0x01, "LPCD Reference Value Selection and GPO control") &&
           pn5180_eeprom_update_byte(pn5180, LPCD_GPO_TOGGLE_BEFORE_FIELD_ON, 0xF0, "LPCD GPO Toggle Before Field On") &&
           pn5180_eeprom_update_byte(pn5180, LPCD_GPO_TOGGLE_AFTER_FIELD_OFF, 0xF0, "LPCD GPO Toggle After Field Off");
}

uint32_t pn5180_get_irq_status(pn5180_t *pn5180)
{
    uint32_t irq_status = 0;
    if (!pn5180_read_register(pn5180, PN5180_IRQ_STATUS, &irq_status)) {
        ESP_LOGE(TAG, "Failed to read IRQ_STATUS register");
        return 0;
    }
    return irq_status;
}

bool pn5180_clear_irq_status(pn5180_t *pn5180, uint32_t irq_mask)
{
    bool ret = pn5180_write_register(pn5180, PN5180_IRQ_CLEAR, irq_mask);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to clear IRQ status with mask 0x%08" PRIX32, irq_mask);
    }
    return ret;
}

bool pn5180_lpcd_enter(pn5180_t *pn5180, uint16_t wakeup_counter_ms)
{
    if (wakeup_counter_ms == 0 || wakeup_counter_ms > PN5180_MAX_WAKEUP_COUNTER_MS) {
        ESP_LOGE(TAG, "Invalid LPCD wakeup counter: %u ms", (unsigned)wakeup_counter_ms);
        return false;
    }

    // Firmware 3.A and later: with LPCD mode 01b (self calibration, set by pn5180_lpcd_prepare()) the
    // reference is taken from AGC_REF_CONFIG. Reading the register runs the calibration, and the value read
    // has to be written back before LPCD is started (datasheet rev. 4.0, tables 73 and 112).
    // Earlier firmware gives the mode bits another meaning and measures the reference by itself when LPCD
    // starts; there the step would only switch the field on once more, so it is skipped.
    if (pn5180->firmware_version >= PN5180_FIRMWARE_VERSION_3_A) {
        uint32_t agc_ref = 0;
        if (!pn5180_read_register(pn5180, PN5180_AGC_REF_CONFIG, &agc_ref) || !pn5180_write_register(pn5180, PN5180_AGC_REF_CONFIG, agc_ref)) {
            ESP_LOGE(TAG, "Failed to set the LPCD reference value");
            return false;
        }
        PN5180_LOGD(TAG, "LPCD reference AGC_REF_CONFIG=0x%08" PRIx32, agc_ref);
    }

    // LPCD_IRQ and GENERAL_ERROR_IRQ are non-maskable; writing IRQ_ENABLE still takes the flags of the last
    // RF exchange off the IRQ pin, and is what the NXP reader library does before entering LPCD.
    pn5180_clear_all_irqs(pn5180);
    pn5180_write_register(pn5180, PN5180_IRQ_ENABLE, PN5180_LPCD_IRQ_STAT | PN5180_GENERAL_ERROR_IRQ_STAT);
    if (pn5180->irq_sem != NULL) {
        xSemaphoreTake((SemaphoreHandle_t)pn5180->irq_sem, 0); // drop a stale notification
    }
    uint8_t cmd_buf[] = {
        PN5180_SWITCH_MODE,                         //
        0x01,                                       //
        (uint8_t)(wakeup_counter_ms & 0xFF),        //
        (uint8_t)((wakeup_counter_ms >> 8U) & 0xFF) //
    };
    bool ret = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), NULL, 0);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to switch to LPCD mode");
        return false;
    }
    // The PN5180 switches its field on and off by itself from now on.
    pn5180->is_rf_on = false;
    return true;
}

bool pn5180_lpcd_wait(pn5180_t *pn5180, int timeout_ms, uint32_t *irq_status)
{
    if (irq_status != NULL) {
        *irq_status = 0;
    }
    if (pn5180->irq_sem == NULL) {
        ESP_LOGE(TAG, "pn5180_lpcd_wait needs the IRQ pin (pn5180_irq_attach)");
        return false;
    }

    // No SPI access here: NSS activity would end LPCD mode.
    int64_t deadline = (timeout_ms < 0) ? INT64_MAX : esp_timer_get_time() + (1000LL * timeout_ms);
    while (gpio_get_level(pn5180->irq) != (pn5180->irq_active_high ? 1 : 0)) {
        int64_t now = esp_timer_get_time();
        if (now >= deadline) {
            return false;
        }
        // Wake up at least every 100 ms to re-check the pin level in case an edge was missed.
        int64_t wait_ms = (deadline - now) / 1000 + 1;
        if (wait_ms > 100) {
            wait_ms = 100;
        }
        xSemaphoreTake((SemaphoreHandle_t)pn5180->irq_sem, pdMS_TO_TICKS(wait_ms) + 1);
    }

    uint32_t status = pn5180_get_irq_status(pn5180);
    pn5180_clear_all_irqs(pn5180);
    if (irq_status != NULL) {
        *irq_status = status;
    }

    // Register settings do not survive LPCD mode: bring the RF configuration back.
    pn5180->is_rf_on = false;
    if (pn5180->rf_config_loaded && !pn5180_load_rf_config(pn5180, pn5180->tx_config)) {
        ESP_LOGE(TAG, "Failed to reload RF config after LPCD");
    }
    return (status & PN5180_LPCD_IRQ_STAT) != 0;
}

uint32_t pn5180_rx_bytes_received(pn5180_t *pn5180)
{
    uint32_t rx_status;
    uint32_t len = 0;

    if (!pn5180_read_register(pn5180, PN5180_RX_STATUS, &rx_status)) {
        ESP_LOGE(TAG, "Failed to read RX_STATUS register");
        return 0;
    }
    len = rx_status & PN5180_RX_BYTES_RECEIVED_MASK;
    return len;
}

int16_t pn5180_mifare_authenticate(pn5180_t *pn5180, uint8_t blockno, const uint8_t *key, uint8_t key_type, const uint8_t uid[4])
{
    if (key_type != 0x60 && key_type != 0x61) {
        ESP_LOGE(TAG, "Invalid key type 0x%02X for MIFARE authentication", key_type);
        return -1;
    }
    uint8_t cmd_buf[13];
    uint8_t rcv_buffer[1];

    // Format per PN5180 datasheet: [Cmd][Key(6)][KeyType][Block][UID(4)]
    cmd_buf[0] = PN5180_MIFARE_AUTHENTICATE;
    memcpy(&cmd_buf[1], key, 6);
    cmd_buf[7] = key_type; // 0x60 Key A, 0x61 Key B
    cmd_buf[8] = blockno;  // block within sector to auth
    memcpy(&cmd_buf[9], uid, 4);

    PN5180_LOGD(TAG,
                "AUTH cmd: [Cmd=0x%02X][Key=%02X %02X %02X %02X %02X %02X][KeyType=0x%02X][Block=0x%02X][UID=%02X %02X "
                "%02X %02X]",
                cmd_buf[0], cmd_buf[1], cmd_buf[2], cmd_buf[3], cmd_buf[4], cmd_buf[5], cmd_buf[6], cmd_buf[7], cmd_buf[8], cmd_buf[9], cmd_buf[10],
                cmd_buf[11], cmd_buf[12]);

    bool rc = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), rcv_buffer, 1);
    if (!rc) {
        ESP_LOGE(TAG, "Failed to perform MIFARE authentication SPI transaction");
        return -3;
    }
    PN5180_LOGD(TAG, "AUTH response byte: 0x%02X", rcv_buffer[0]);

    if ((rcv_buffer[0] & 0x01) != 0) {
        PN5180_LOGD(TAG, "Authentication rejected by PN5180 (response: 0x%02X)", rcv_buffer[0]);
    } else if ((rcv_buffer[0] & 0x02) != 0) {
        PN5180_LOGW(TAG, "Authentication timed out (response: 0x%02X)", rcv_buffer[0]);
    } else if (rcv_buffer[0] != 0x00) {
        PN5180_LOGW(TAG, "Authentication returned unexpected response 0x%02X", rcv_buffer[0]);
    } else {
        uint32_t system_config = 0;
        if (!pn5180_read_register(pn5180, PN5180_SYSTEM_CONFIG, &system_config)) {
            ESP_LOGE(TAG, "Failed to verify MIFARE authentication state");
            pn5180_write_register_and_mask(pn5180, PN5180_SYSTEM_CONFIG, PN5180_SYSTEM_CONFIG_CLEAR_CRYPTO_MASK);
            pn5180_set_transceiver_idle(pn5180);
            pn5180_clear_all_irqs(pn5180);
            return -4;
        }
        if ((system_config & PN5180_SYSTEM_CONFIG_MFC_CRYPTO_ON) != 0) {
            pn5180_transceive_state_t tstate;

            int64_t deadline = esp_timer_get_time() + 50 * 1000; // 50ms max
            do {
                tstate = pn5180_get_transceive_state(pn5180);
                if (tstate == PN5180_TS_WAIT_TRANSMIT || tstate == PN5180_TS_IDLE) {
                    break;
                }
                esp_rom_delay_us(10);
            } while (esp_timer_get_time() < deadline);

            pn5180_clear_all_irqs(pn5180);
            return 0x00;
        }

        PN5180_LOGW(TAG, "Authentication response was success but MFC_CRYPTO_ON is not set");
        rcv_buffer[0] = 0x01;
    }

    if (rcv_buffer[0] != 0x00) {
        PN5180_LOGD(TAG, "Authentication failed (response: 0x%02X) - resetting transceiver state", rcv_buffer[0]);
        // Clear Crypto1 bit and reset transceiver to clean state
        pn5180_write_register_and_mask(pn5180, PN5180_SYSTEM_CONFIG, PN5180_SYSTEM_CONFIG_CLEAR_CRYPTO_MASK); // Clear MFC_CRYPTO_ON
        pn5180_set_transceiver_idle(pn5180);

        // Flush any stale data from RX buffer
        uint32_t rx_status;
        if (pn5180_read_register(pn5180, PN5180_RX_STATUS, &rx_status)) {
            uint16_t rx_len = rx_status & PN5180_RX_BYTES_RECEIVED_MASK;
            if (rx_len > 0 && rx_len < 512) {
                uint8_t dummy[512];
                pn5180_read_data(pn5180, rx_len, dummy);
            }
        }

        pn5180_clear_all_irqs(pn5180);

        // Wait for transceiver to reach idle state before returning
        pn5180_transceive_state_t tstate;
        int64_t                   deadline = esp_timer_get_time() + 50 * 1000; // 50ms max
        do {
            tstate = pn5180_get_transceive_state(pn5180);
            if (tstate == PN5180_TS_IDLE) {
                break;
            }
            esp_rom_delay_us(10);
        } while (esp_timer_get_time() < deadline);

        return rcv_buffer[0];
    }

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

bool pn5180_load_rf_config(pn5180_t *pn5180, uint8_t tx_conf)
{
    uint8_t cmd_buf[3];
    cmd_buf[0] = PN5180_LOAD_RF_CONFIG;
    cmd_buf[1] = tx_conf;
    cmd_buf[2] = tx_conf | 0x80; // RX config is TX config + 0x80
    bool ret   = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), NULL, 0);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to load RF config");
    } else {
        pn5180->tx_config        = tx_conf;
        pn5180->rf_config_loaded = true;
    }
    return ret;
}

bool pn5180_set_rf_on(pn5180_t *pn5180)
{
    if (pn5180->is_rf_on) {
        return true; // already on
    }
    // Parameter bit 0 = 1 disables RF collision avoidance; bit 1 (active mode) stays 0.
    uint8_t  cmd_buf[]  = {PN5180_RF_ON, pn5180->rfca_disabled ? 0x01 : 0x00};
    uint32_t rf_status  = 0;
    uint32_t irq_status = 0;

    for (int attempt = 0; attempt < 3; attempt++) {
        // Clear RF-related IRQs before sending FIELD_ON
        pn5180_clear_irq_status(pn5180, PN5180_RF_ACTIVE_ERROR_IRQ_STAT | PN5180_TX_RFON_IRQ_STAT | PN5180_TX_RFOFF_IRQ_STAT | PN5180_RFON_DET_IRQ_STAT |
                                            PN5180_RFOFF_DET_IRQ_STAT);

        if (!transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), NULL, 0)) {
            ESP_LOGE(TAG, "RF_ON SPI command failed");
            pn5180_delay_ms(10);
            continue;
        }

        // FIELD_ON is synchronous — when SPI BUSY goes low the result is final.
        // Just read RF_STATUS once to check the outcome.
        if (!pn5180_read_register(pn5180, PN5180_RF_STATUS, &rf_status)) {
            ESP_LOGE(TAG, "Failed to read RF_STATUS after RF_ON");
            pn5180_delay_ms(10);
            continue;
        }

        if (rf_status & PN5180_RF_STATUS_TX_RF_STATUS_MASK) {
            pn5180->is_rf_on = true;
            // Guard time: cards need the unmodulated field before the first command.
            if (pn5180->rf_guard_time_us > 0) {
                pn5180_delay_us(pn5180->rf_guard_time_us);
            }
            return true;
        }

        // Field didn't come up — check why
        irq_status = pn5180_get_irq_status(pn5180);
        if (irq_status & PN5180_RF_ACTIVE_ERROR_IRQ_STAT) {
            ESP_LOGW(TAG, "RF_ON blocked by external RF field (RFCA)");
        } else {
            ESP_LOGW(TAG, "RF_ON failed, RF_STATUS=0x%08" PRIx32 " IRQ=0x%08" PRIx32, rf_status, irq_status);
        }
        pn5180_delay_ms(10);
    }

    ESP_LOGE(TAG, "RF field is NOT on! RF_STATUS=0x%08" PRIx32 " IRQ_STATUS=0x%08" PRIx32, rf_status, irq_status);
    return false;
}

bool pn5180_set_rf_off(pn5180_t *pn5180)
{
    uint32_t rf_status = 0;
    if (pn5180_read_register(pn5180, PN5180_RF_STATUS, &rf_status)) {
        if ((rf_status & PN5180_RF_STATUS_TX_RF_STATUS_MASK) == 0) {
            pn5180->is_rf_on = false;
            return true;
        }
    }

    pn5180_clear_irq_status(pn5180, PN5180_TX_RFOFF_IRQ_STAT | PN5180_RFOFF_DET_IRQ_STAT);

    uint8_t cmd_buf[] = {PN5180_RF_OFF, 0};
    bool    rc        = transceive_command(pn5180, cmd_buf, sizeof(cmd_buf), NULL, 0);
    if (!rc) {
        ESP_LOGE(TAG, "Failed to set RF off");
        return false;
    }

    int64_t deadline = esp_timer_get_time() + (1000LL * pn5180->timeout_ms);
    while (esp_timer_get_time() <= deadline) {
        if (pn5180_read_register(pn5180, PN5180_RF_STATUS, &rf_status)) {
            if ((rf_status & PN5180_RF_STATUS_TX_RF_STATUS_MASK) == 0) {
                pn5180->is_rf_on = false;
                pn5180_clear_irq_status(pn5180, PN5180_TX_RFOFF_IRQ_STAT | PN5180_RFOFF_DET_IRQ_STAT);
                return true;
            }
        }
        esp_rom_delay_us(50);
    }

    ESP_LOGE(TAG, "Timeout waiting for RF off, RF_STATUS=0x%08" PRIx32, rf_status);
    return false;
}

bool pn5180_send_command(pn5180_t *pn5180, uint8_t *send_buffer, size_t send_buffer_len, uint8_t *recv_buffer, size_t recv_buffer_len)
{
    bool ret = transceive_command(pn5180, send_buffer, send_buffer_len, recv_buffer, recv_buffer_len);
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
    // A reset clears every register: nothing loaded before is valid any more.
    pn5180->is_rf_on         = false;
    pn5180->rf_config_loaded = false;
    int64_t saved_timeout    = pn5180->timeout_ms;
    pn5180->timeout_ms       = 5000; // increase timeout for boot process
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
    while (0 == (PN5180_IDLE_IRQ_STAT & pn5180_get_irq_status(pn5180))) { // wait for system to start up (with timeout)
        if (esp_timer_get_time() > deadline) {
            // The IDLE IRQ after boot can be switched off in EEPROM. If the EEPROM answers and says so,
            // the PN5180 has booted and there is nothing to wait for.
            uint8_t idle_irq_after_boot = 0xFF;
            if (pn5180_read_eeprom(pn5180, PN5180_IDLE_IRQ_AFTER_BOOT, &idle_irq_after_boot, 1) && idle_irq_after_boot == 0x00) {
                PN5180_LOGD(TAG, "IDLE IRQ after boot is disabled in EEPROM, boot accepted");
                break;
            }
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
        vTaskDelay(1);
    }
    if (!wait_busy_level(pn5180, 0, "after reset")) {
        ESP_LOGE(TAG, "Failed to boot after reset (BUSY stuck High after IDLE IRQ)");
        return false;
    }
    return true;
}

bool pn5180_recover(pn5180_t *pn5180)
{
    bool    rf_was_on  = pn5180->is_rf_on;
    bool    was_loaded = pn5180->rf_config_loaded;
    uint8_t tx_config  = pn5180->tx_config;

    if (!pn5180_reset(pn5180)) {
        ESP_LOGE(TAG, "recover: reset failed");
        return false;
    }
    if (was_loaded && !pn5180_load_rf_config(pn5180, tx_config)) {
        ESP_LOGE(TAG, "recover: failed to reload RF config 0x%02X", tx_config);
        return false;
    }
    if (rf_was_on && !pn5180_set_rf_on(pn5180)) {
        ESP_LOGE(TAG, "recover: failed to switch the RF field back on");
        return false;
    }
    return true;
}

void pn5180_set_hw_rx_timeout(pn5180_t *pn5180, bool enable)
{
    pn5180->hw_rx_timeout = enable;
}

void pn5180_set_rf_guard_time_us(pn5180_t *pn5180, uint32_t guard_time_us)
{
    pn5180->rf_guard_time_us = guard_time_us;
}

void pn5180_set_rfca(pn5180_t *pn5180, bool enable)
{
    pn5180->rfca_disabled = !enable;
}

static void IRAM_ATTR pn5180_irq_isr(void *arg)
{
    BaseType_t higher_prio_woken = pdFALSE;
    xSemaphoreGiveFromISR((SemaphoreHandle_t)arg, &higher_prio_woken);
    if (higher_prio_woken == pdTRUE) {
        portYIELD_FROM_ISR();
    }
}

bool pn5180_irq_attach(pn5180_t *pn5180, gpio_num_t irq)
{
    if (pn5180->irq_sem != NULL) {
        ESP_LOGE(TAG, "IRQ pin is already attached");
        return false;
    }

    uint8_t pin_config = 0;
    if (!pn5180_read_eeprom(pn5180, PN5180_IRQ_PIN_CONFIG, &pin_config, 1)) {
        ESP_LOGE(TAG, "Failed to read IRQ_PIN_CONFIG");
        return false;
    }
    bool active_high = (pin_config & PN5180_IRQ_PIN_CONFIG_ACTIVE_HIGH) != 0;
    if (pin_config & PN5180_IRQ_PIN_CONFIG_AUTO_CLEAR_ON_READ) {
        ESP_LOGW(TAG, "IRQ_PIN_CONFIG=0x%02X: IRQ is cleared by reading IRQ_STATUS; the driver expects clearing through IRQ_CLEAR", pin_config);
    }

    SemaphoreHandle_t sem = xSemaphoreCreateBinary();
    if (sem == NULL) {
        ESP_LOGE(TAG, "Failed to create IRQ semaphore");
        return false;
    }

    // Weak pull towards the inactive level, so that the input does not float while the PN5180 is in reset.
    gpio_config_t irq_cfg = {
        .pin_bit_mask = (1ULL << irq),                                              //
        .mode         = GPIO_MODE_INPUT,                                            //
        .pull_up_en   = active_high ? GPIO_PULLUP_DISABLE : GPIO_PULLUP_ENABLE,     //
        .pull_down_en = active_high ? GPIO_PULLDOWN_ENABLE : GPIO_PULLDOWN_DISABLE, //
        .intr_type    = active_high ? GPIO_INTR_POSEDGE : GPIO_INTR_NEGEDGE         //
    };
    esp_err_t err = gpio_config(&irq_cfg);
    if (err == ESP_OK) {
        err = gpio_install_isr_service(0);
        if (err == ESP_ERR_INVALID_STATE) {
            err = ESP_OK; // the application has installed the service already
        }
    }
    if (err == ESP_OK) {
        err = gpio_isr_handler_add(irq, pn5180_irq_isr, sem);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set up IRQ pin %d: %s", (int)irq, esp_err_to_name(err));
        vSemaphoreDelete(sem);
        return false;
    }

    pn5180->irq             = irq;
    pn5180->irq_active_high = active_high;
    pn5180->irq_sem         = sem;
    PN5180_LOGD(TAG, "IRQ pin %d attached, active %s", (int)irq, active_high ? "high" : "low");
    return true;
}

// How long the wait keeps polling IRQ_STATUS back to back before it starts sleeping between polls.
#define PN5180_IRQ_SPIN_US 5000
// Sleep between polls after that; the CPU is released meanwhile.
#define PN5180_IRQ_POLL_US 1000
// With the IRQ pin the wait still wakes up this often to poll IRQ_STATUS, in case an edge was missed.
#define PN5180_IRQ_RECHECK_MS 20

typedef enum
{
    PN5180_WAIT_IRQ,      /**< One of the awaited flags is set */
    PN5180_WAIT_DEADLINE, /**< The deadline passed */
    PN5180_WAIT_SPI_ERROR /**< IRQ_STATUS could not be read */
} pn5180_wait_result_t;

// Waits until one of the irq_mask flags or GENERAL_ERROR is set, or the deadline passes.
// IRQ flags are left as they are; *irq_status gets the last IRQ_STATUS value read.
static pn5180_wait_result_t pn5180_wait_irq_until(pn5180_t *pn5180, uint32_t irq_mask, int64_t deadline, uint32_t *irq_status)
{
    irq_mask |= PN5180_GENERAL_ERROR_IRQ_STAT;
    if (pn5180->irq_sem != NULL) {
        // Route exactly the awaited flags to the pin. Flags that are set already raise it at once.
        pn5180_write_register(pn5180, PN5180_IRQ_ENABLE, irq_mask);
    }
    int64_t spin_until = esp_timer_get_time() + PN5180_IRQ_SPIN_US;
    while (true) {
        // A failed read must not look like "no flag set yet", which would end as an ordinary RF timeout.
        if (!pn5180_read_register(pn5180, PN5180_IRQ_STATUS, irq_status)) {
            *irq_status = 0;
            return PN5180_WAIT_SPI_ERROR;
        }
        if (*irq_status & irq_mask) {
            return PN5180_WAIT_IRQ;
        }
        int64_t now = esp_timer_get_time();
        if (now > deadline) {
            return PN5180_WAIT_DEADLINE;
        }
        if (pn5180->irq_sem != NULL) {
            int64_t wait_ms = (deadline - now) / 1000 + 1;
            if (wait_ms > PN5180_IRQ_RECHECK_MS) {
                wait_ms = PN5180_IRQ_RECHECK_MS;
            }
            xSemaphoreTake((SemaphoreHandle_t)pn5180->irq_sem, pdMS_TO_TICKS(wait_ms) + 1);
        } else if (now < spin_until) {
            esp_rom_delay_us(10);
        } else {
            pn5180_poll_sleep(pn5180, PN5180_IRQ_POLL_US);
        }
    }
}

bool pn5180_wait_for_irq(pn5180_t *pn5180, uint32_t irq_mask, const char *operation, uint32_t *irq_status)
{
    int64_t deadline = esp_timer_get_time() + (1000LL * pn5180->timeout_ms);
    bool    ret      = pn5180_wait_irq_until(pn5180, irq_mask, deadline, irq_status) == PN5180_WAIT_IRQ;
    if (!ret) {
        ESP_LOGE(TAG, "Timeout waiting for %s", operation);
    } else if (*irq_status & PN5180_GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGW(TAG, "General error detected during %s", operation);
    }
    // Clear IRQs to avoid stale bits leaking into the next transaction.
    pn5180_clear_all_irqs(pn5180);
    return ret;
}

// Timer1 clock without prescaler: 13.56 MHz, i.e. 13.56 ticks per microsecond.
#define PN5180_TIMER_MAX_US_NO_PRESCALER 77000u
// Time allowed on top of the response timeout for the frame itself to be transmitted and received.
#define PN5180_RF_FRAME_MARGIN_US 100000

// Arms Timer1 as receive timeout: it starts when the transmission ends and stops when a reception begins.
static bool pn5180_timer1_arm(pn5180_t *pn5180, uint32_t timeout_us)
{
    uint32_t config = PN5180_TIMER1_CONFIG_START_ON_TX_ENDED | PN5180_TIMER1_CONFIG_STOP_ON_RX_STARTED | PN5180_TIMER1_CONFIG_ENABLE;
    uint64_t reload;
    if (timeout_us <= PN5180_TIMER_MAX_US_NO_PRESCALER) {
        reload = ((uint64_t)timeout_us * 1356u) / 100u;
    } else {
        config |= PN5180_TIMER1_CONFIG_MODE_SEL | PN5180_TIMER1_CONFIG_PRESCALE_53KHZ;
        reload = ((uint64_t)timeout_us * 53u) / 1000u;
    }
    if (reload == 0) {
        reload = 1;
    }
    if (reload > PN5180_TIMER_RELOAD_MAX) {
        reload = PN5180_TIMER_RELOAD_MAX; // about 19.7 s
    }

    // WRITE_REGISTER_MULTIPLE: {register, action (1 = write), value LSB first} per element.
    // Stop the timer, load the reload value, then start it with the new configuration.
    uint8_t cmd[1 + 3 * 6];
    size_t  n = 0;
    cmd[n++]  = PN5180_WRITE_REGISTER_MULTIPLE;
    const struct
    {
        uint8_t  reg;
        uint32_t value;
    } writes[] = {
        {PN5180_TIMER1_CONFIG, 0               },
        {PN5180_TIMER1_RELOAD, (uint32_t)reload},
        {PN5180_TIMER1_CONFIG, config          },
    };
    for (size_t i = 0; i < sizeof(writes) / sizeof(writes[0]); i++) {
        cmd[n++] = writes[i].reg;
        cmd[n++] = 0x01;
        cmd[n++] = (uint8_t)(writes[i].value & 0xFF);
        cmd[n++] = (uint8_t)((writes[i].value >> 8) & 0xFF);
        cmd[n++] = (uint8_t)((writes[i].value >> 16) & 0xFF);
        cmd[n++] = (uint8_t)((writes[i].value >> 24) & 0xFF);
    }
    if (!transceive_command(pn5180, cmd, n, NULL, 0)) {
        ESP_LOGE(TAG, "Failed to arm Timer1");
        return false;
    }
    return true;
}

pn5180_rf_result_t pn5180_rf_transceive( //
    pn5180_t      *pn5180,               //
    const uint8_t *tx,                   //
    size_t         tx_len,               //
    uint8_t        tx_last_bits,         //
    uint8_t       *rx,                   //
    size_t         rx_size,              //
    size_t        *rx_len,               //
    uint32_t       timeout_us,           //
    uint32_t      *rx_status             //
)
{
    if (rx_len != NULL) {
        *rx_len = 0;
    }
    if (rx_status != NULL) {
        *rx_status = 0;
    }
    if (pn5180 == NULL || tx == NULL || tx_len == 0 || tx_len > 260) {
        return PN5180_RF_FATAL;
    }

    bool expect_rx = timeout_us != 0;
    bool use_timer = expect_rx && pn5180->hw_rx_timeout;

    if (use_timer && !pn5180_timer1_arm(pn5180, timeout_us)) {
        return PN5180_RF_FATAL;
    }

    pn5180_rf_result_t result;
    uint32_t           irq = 0;

    if (!pn5180_send_data(pn5180, tx, (int)tx_len, tx_last_bits)) {
        result = PN5180_RF_FATAL;
    } else {
        // The host-side deadline is a backstop: it also covers the time the frames take on air.
        int64_t  deadline = esp_timer_get_time() + (int64_t)timeout_us + PN5180_RF_FRAME_MARGIN_US;
        uint32_t mask     = expect_rx ? PN5180_RX_IRQ_STAT : PN5180_TX_IRQ_STAT;
        if (use_timer) {
            mask |= PN5180_TIMER1_IRQ_STAT;
        }
        pn5180_wait_result_t wait_result = pn5180_wait_irq_until(pn5180, mask, deadline, &irq);
        bool                 got_irq     = (wait_result == PN5180_WAIT_IRQ);

        if (wait_result == PN5180_WAIT_SPI_ERROR) {
            result = PN5180_RF_FATAL;
        } else if (!expect_rx) {
            if (!got_irq) {
                ESP_LOGE(TAG, "rf_transceive: transmission did not finish");
                result = PN5180_RF_FATAL;
            } else {
                result = (irq & PN5180_GENERAL_ERROR_IRQ_STAT) ? PN5180_RF_RX_ERROR : PN5180_RF_OK;
            }
        } else if (irq & PN5180_RX_IRQ_STAT) {
            uint32_t status = 0;
            if (!pn5180_read_register(pn5180, PN5180_RX_STATUS, &status)) {
                result = PN5180_RF_FATAL;
            } else {
                size_t len = (size_t)(status & PN5180_RX_BYTES_RECEIVED_MASK);
                if (rx_status != NULL) {
                    *rx_status = status;
                }
                if (status & PN5180_RX_COLLISION_DETECTED) {
                    result = PN5180_RF_COLLISION;
                } else if (irq & PN5180_GENERAL_ERROR_IRQ_STAT) {
                    result = PN5180_RF_RX_ERROR;
                    len    = 0; // the reception buffer is not trustworthy after a general error
                } else if (status & (PN5180_RX_PROTOCOL_ERROR | PN5180_RX_DATA_INTEGRITY_ERROR)) {
                    result = PN5180_RF_RX_ERROR;
                } else {
                    result = PN5180_RF_OK;
                }
                if (len > rx_size && result == PN5180_RF_COLLISION) {
                    len = rx_size; // bytes after the collision are not meaningful, the first ones are enough
                }
                if (len > 0 && rx != NULL) {
                    if (len > rx_size) {
                        result = PN5180_RF_OVERFLOW;
                    } else if (!pn5180_read_data(pn5180, (int)len, rx)) {
                        result = PN5180_RF_FATAL;
                    } else if (rx_len != NULL) {
                        *rx_len = len;
                    }
                }
            }
        } else if (irq & PN5180_GENERAL_ERROR_IRQ_STAT) {
            result = PN5180_RF_RX_ERROR;
        } else {
            result = PN5180_RF_TIMEOUT; // Timer1 expired, or the host-side deadline passed
        }
    }

    pn5180_clear_all_irqs(pn5180);
    if (use_timer) {
        pn5180_write_register(pn5180, PN5180_TIMER1_CONFIG, 0);
    }
    if (result == PN5180_RF_TIMEOUT) {
        // Stop the receiver, which is still waiting for a response.
        pn5180_set_transceiver_idle(pn5180);
    }
    return result;
}
