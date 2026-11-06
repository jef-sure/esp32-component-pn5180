#include "chip_sim.h"
#include "esp_err.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

chip_sim_t chip;

/* Opcodes of the host interface (datasheet table 7) */
#define OP_WRITE_REGISTER          0x00
#define OP_WRITE_REGISTER_OR_MASK  0x01
#define OP_WRITE_REGISTER_AND_MASK 0x02
#define OP_WRITE_REGISTER_MULTIPLE 0x03
#define OP_READ_REGISTER           0x04
#define OP_WRITE_EEPROM            0x06
#define OP_READ_EEPROM             0x07
#define OP_SEND_DATA               0x09
#define OP_READ_DATA               0x0A
#define OP_SWITCH_MODE             0x0B
#define OP_MIFARE_AUTHENTICATE     0x0C
#define OP_LOAD_RF_CONFIG          0x11
#define OP_RF_ON                   0x16
#define OP_RF_OFF                  0x17

#define TICK_US ((int64_t)portTICK_PERIOD_MS * 1000)

/* ---- SPI frames and the command they carry ---- */

static bool    s_nss_low;
static uint8_t s_frame[600];
static size_t  s_frame_len;
static bool    s_frame_pending;
static uint8_t s_response[600];
static size_t  s_response_len;
static bool    s_response_pending;
static bool    s_response_frame; // the frame now held is the read of an answer

void chip_answer_ex(const chip_answer_t *answer)
{
    if (chip.answer_count < CHIP_MAX_ANSWERS) {
        chip.answers[chip.answer_count++] = *answer;
    }
}

void chip_answer(const uint8_t *data, size_t len, uint32_t rx_status_flags)
{
    chip_answer_t answer = {.card_answers = true, .len = len, .rx_status_flags = rx_status_flags};
    if (len > 0) {
        memcpy(answer.data, data, len);
    }
    chip_answer_ex(&answer);
}

static void respond(const uint8_t *data, size_t len)
{
    memcpy(s_response, data, len);
    s_response_len     = len;
    s_response_pending = true;
}

static uint32_t read_register(uint8_t reg)
{
    if (reg == PN5180_RF_STATUS) {
        uint32_t value = chip.reg[reg] & PN5180_RF_STATUS_AGC_MASK;
        if (chip.field_on) {
            value |= PN5180_RF_STATUS_TX_RF_STATUS_MASK;
        }
        return value | ((uint32_t)chip.tstate << 24);
    }
    return chip.reg[reg & 0x3F];
}

static void write_register(uint8_t reg, uint32_t value)
{
    reg &= 0x3F;
    if (reg == PN5180_IRQ_CLEAR) {
        chip.reg[PN5180_IRQ_STATUS] &= ~value;
        return;
    }
    if (reg == PN5180_IRQ_STATUS) {
        return; // read only
    }
    chip.reg[reg] = value;
    if (reg == PN5180_SYSTEM_CONFIG) {
        // Command bits 2:0: 0 idle, 3 transceive (the transceiver then waits to transmit)
        uint32_t command = value & PN5180_SYSTEM_CONFIG_TX_MODE_MASK;
        if (command == PN5180_SYSTEM_CONFIG_TX_MODE_IDLE) {
            chip.tstate = PN5180_TS_IDLE;
        } else if (command == PN5180_SYSTEM_CONFIG_TX_MODE_TRANSCEIVE && chip.tstate == PN5180_TS_IDLE) {
            chip.tstate = PN5180_TS_WAIT_TRANSMIT;
        }
    }
}

static void modify_register(uint8_t action, uint8_t reg, uint32_t value)
{
    switch (action) {
    case 1:
        write_register(reg, value);
        break;
    case 2:
        write_register(reg, read_register(reg) | value);
        break;
    case 3:
        write_register(reg, read_register(reg) & value);
        break;
    default:
        chip.violations++;
        break;
    }
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void send_data(const uint8_t *frame, size_t len)
{
    if (chip.tstate != PN5180_TS_WAIT_TRANSMIT) {
        chip.send_without_transceive++;
        return;
    }
    chip.last_valid_bits = frame[1];
    chip.last_send_len   = len - 2;
    memcpy(chip.last_send, &frame[2], len - 2);
    chip.timer1_config_at_send = chip.reg[PN5180_TIMER1_CONFIG];
    chip.timer1_reload_at_send = chip.reg[PN5180_TIMER1_RELOAD];

    chip_answer_t answer = {0};
    if (chip.answer_next < chip.answer_count) {
        answer = chip.answers[chip.answer_next++];
    }
    if (!answer.no_tx_irq) {
        chip.reg[PN5180_IRQ_STATUS] |= PN5180_TX_IRQ_STAT;
    }
    if (answer.general_error) {
        chip.reg[PN5180_IRQ_STATUS] |= PN5180_GENERAL_ERROR_IRQ_STAT;
    }
    if (answer.card_answers && chip.field_on && !answer.no_tx_irq) {
        memcpy(chip.rx_data, answer.data, answer.len);
        chip.rx_len                 = answer.len;
        chip.reg[PN5180_RX_STATUS]  = (uint32_t)(answer.len & PN5180_RX_BYTES_RECEIVED_MASK) | answer.rx_status_flags;
        chip.reg[PN5180_IRQ_STATUS] |= PN5180_RX_IRQ_STAT;
        chip.tstate                 = PN5180_TS_WAIT_TRANSMIT;
    } else {
        chip.reg[PN5180_RX_STATUS] = 0;
        if ((chip.reg[PN5180_TIMER1_CONFIG] & PN5180_TIMER1_CONFIG_ENABLE) != 0 && !answer.no_tx_irq) {
            chip.reg[PN5180_IRQ_STATUS] |= PN5180_TIMER1_IRQ_STAT;
            chip.tstate = PN5180_TS_WAIT_TRANSMIT;
        } else {
            chip.tstate = PN5180_TS_WAIT_RECEIVE;
        }
    }
}

static void execute(const uint8_t *frame, size_t len)
{
    if (len == 0) {
        return;
    }
    uint8_t op = frame[0];
    chip.commands[op]++;
    switch (op) {
    case OP_WRITE_REGISTER:
    case OP_WRITE_REGISTER_OR_MASK:
    case OP_WRITE_REGISTER_AND_MASK:
        if (len != 6) {
            chip.violations++;
            return;
        }
        modify_register((uint8_t)(op + 1), frame[1], le32(&frame[2]));
        return;
    case OP_WRITE_REGISTER_MULTIPLE:
        if ((len - 1) % 6 != 0) {
            chip.violations++;
            return;
        }
        for (size_t i = 1; i + 6 <= len; i += 6) {
            modify_register(frame[i + 1], frame[i], le32(&frame[i + 2]));
        }
        return;
    case OP_READ_REGISTER: {
        uint32_t value    = read_register(frame[1]);
        uint8_t  bytes[4] = {(uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
        respond(bytes, sizeof(bytes));
        return;
    }
    case OP_WRITE_EEPROM:
        if (len < 3 || (size_t)frame[1] + (len - 2) > 256) {
            chip.violations++;
            return;
        }
        memcpy(&chip.eeprom[frame[1]], &frame[2], len - 2);
        chip.eeprom_bytes_written += (int)(len - 2);
        return;
    case OP_READ_EEPROM:
        if (len != 3 || (size_t)frame[1] + frame[2] > 256) {
            chip.violations++;
            return;
        }
        respond(&chip.eeprom[frame[1]], frame[2]);
        return;
    case OP_SEND_DATA:
        send_data(frame, len);
        return;
    case OP_READ_DATA:
        respond(chip.rx_data, chip.rx_len);
        return;
    case OP_SWITCH_MODE:
        if (len >= 2 && frame[1] == 0x01) {
            chip.lpcd_active = true;
            chip.field_on    = false;
        }
        return;
    case OP_MIFARE_AUTHENTICATE: {
        if (len != 13) {
            chip.violations++;
            return;
        }
        uint8_t status = chip.auth_status;
        if (status == 0) {
            chip.reg[PN5180_SYSTEM_CONFIG] |= PN5180_SYSTEM_CONFIG_MFC_CRYPTO_ON;
        } else if (chip.rx_after_auth > 0) {
            chip.rx_len                = chip.rx_after_auth;
            chip.reg[PN5180_RX_STATUS] = (uint32_t)chip.rx_after_auth;
        }
        respond(&status, 1);
        return;
    }
    case OP_LOAD_RF_CONFIG:
        chip.rf_config = frame[1];
        return;
    case OP_RF_ON:
        if (chip.rfca_blocks) {
            chip.reg[PN5180_IRQ_STATUS] |= PN5180_RF_ACTIVE_ERROR_IRQ_STAT;
        } else {
            chip.field_on = true;
            chip.reg[PN5180_IRQ_STATUS] |= PN5180_TX_RFON_IRQ_STAT;
        }
        return;
    case OP_RF_OFF:
        chip.field_on = false;
        chip.reg[PN5180_IRQ_STATUS] |= PN5180_TX_RFOFF_IRQ_STAT;
        return;
    default:
        chip.violations++;
        return;
    }
}

static void boot(void)
{
    memset(chip.reg, 0, sizeof(chip.reg));
    chip.field_on      = false;
    chip.tstate        = PN5180_TS_IDLE;
    chip.rx_len        = 0;
    chip.lpcd_active   = false;
    s_frame_pending    = false;
    s_response_pending = false;
    chip.boots++;
    if (chip.eeprom[PN5180_IDLE_IRQ_AFTER_BOOT] != 0) {
        chip.reg[PN5180_IRQ_STATUS] = PN5180_IDLE_IRQ_STAT;
    }
    chip.busy       = false;
    chip.busy_until = chip.now_us + 2000; // the boot itself
}

// How long a command keeps BUSY high after NSS was released.
static int64_t execution_us(uint8_t op)
{
    switch (op) {
    case OP_WRITE_EEPROM:
        return 5000;
    case OP_RF_ON:
    case OP_LOAD_RF_CONFIG:
    case OP_MIFARE_AUTHENTICATE:
        return 1000;
    default:
        return 20;
    }
}

// NSS goes high: the frame is complete; the PN5180 executes it and BUSY falls when it is done.
static void nss_released(void)
{
    int64_t busy_us = 10;
    if (s_response_frame) {
        s_response_frame   = false;
        s_response_pending = false;
    } else if (s_frame_pending) {
        s_frame_pending = false;
        execute(s_frame, s_frame_len);
        busy_us = execution_us(s_frame[0]);
    }
    chip.busy       = false;
    chip.busy_until = chip.now_us + busy_us;
}

/* ---- SPI master ---- */

struct host_spi_device
{
    spi_host_device_t host;
};

static struct
{
    bool   initialised[SPI_HOST_MAX];
    bool   driver_up[SPI_HOST_MAX];
    size_t max_transfer_sz[SPI_HOST_MAX];
    int    devices[SPI_HOST_MAX];
} s_spi;

bool chip_host_initialised(spi_host_device_t host)
{
    return s_spi.initialised[host];
}

esp_err_t spi_bus_initialize(spi_host_device_t host, const spi_bus_config_t *config, int dma_chan)
{
    (void)dma_chan;
    if (host < 0 || host >= SPI_HOST_MAX || s_spi.initialised[host]) {
        return ESP_ERR_INVALID_STATE;
    }
    s_spi.initialised[host]     = true;
    s_spi.max_transfer_sz[host] = (config->max_transfer_sz > 0) ? (size_t)config->max_transfer_sz : 4092;
    return ESP_OK;
}

esp_err_t chip_app_bus_init(spi_host_device_t host)
{
    spi_bus_config_t config = {.mosi_io_num = 23, .miso_io_num = 19, .sclk_io_num = 18, .quadwp_io_num = -1, .quadhd_io_num = -1,
                               .max_transfer_sz = (int)chip.max_transfer_sz};
    return spi_bus_initialize(host, &config, SPI_DMA_CH_AUTO);
}

esp_err_t spi_bus_free(spi_host_device_t host)
{
    if (!s_spi.initialised[host] || s_spi.devices[host] > 0) {
        return ESP_ERR_INVALID_STATE;
    }
    s_spi.initialised[host] = false;
    s_spi.driver_up[host]   = false;
    return ESP_OK;
}

esp_err_t spi_bus_add_device(spi_host_device_t host, const spi_device_interface_config_t *dev_config, spi_device_handle_t *handle)
{
    (void)dev_config;
    if (host < 0 || host >= SPI_HOST_MAX || !s_spi.initialised[host]) {
        return ESP_ERR_INVALID_STATE;
    }
    struct host_spi_device *dev = calloc(1, sizeof(*dev));
    dev->host                   = host;
    s_spi.devices[host]++;
    s_spi.driver_up[host] = true; // as in ESP-IDF: the master driver of a host comes up with its first device
    *handle               = dev;
    return ESP_OK;
}

esp_err_t spi_bus_remove_device(spi_device_handle_t handle)
{
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    s_spi.devices[handle->host]--;
    free(handle);
    return ESP_OK;
}

esp_err_t spi_bus_get_max_transaction_len(spi_host_device_t host, size_t *max_bytes)
{
    if (!s_spi.driver_up[host]) {
        return ESP_ERR_INVALID_STATE;
    }
    *max_bytes = s_spi.max_transfer_sz[host];
    return ESP_OK;
}

esp_err_t spi_device_acquire_bus(spi_device_handle_t device, TickType_t wait)
{
    (void)device;
    (void)wait;
    chip.bus_held++;
    return ESP_OK;
}

void spi_device_release_bus(spi_device_handle_t device)
{
    (void)device;
    chip.bus_held--;
}

esp_err_t spi_device_polling_transmit(spi_device_handle_t handle, spi_transaction_t *trans)
{
    chip.frames++;
    if (chip.spi_fails) {
        return ESP_FAIL;
    }
    size_t len = trans->length / 8;
    if (!s_nss_low || chip.bus_held <= 0 || len > s_spi.max_transfer_sz[handle->host] || len > sizeof(s_frame)) {
        chip.violations++;
        return ESP_ERR_INVALID_ARG;
    }
    if (chip.in_reset) {
        return ESP_OK; // nobody listens
    }
    if (chip.now_us < chip.busy_until) {
        chip.violations++; // the PN5180 is still busy with the last command
    }
    if (s_response_pending) {
        // The answer to the last command is clocked out; MOSI is ignored.
        uint8_t *rx = trans->rx_buffer;
        for (size_t i = 0; i < len; i++) {
            rx[i] = (i < s_response_len) ? s_response[i] : 0xFF;
        }
        s_response_frame = true;
    } else {
        memcpy(s_frame, trans->tx_buffer, len);
        s_frame_len     = len;
        s_frame_pending = true;
    }
    chip.busy = true;
    return ESP_OK;
}

/* ---- GPIO ---- */

static int        s_level[64];
static bool       s_isr_service;
static gpio_isr_t s_isr;
static void      *s_isr_arg;
static gpio_num_t s_isr_pin = GPIO_NUM_NC;

esp_err_t gpio_config(const gpio_config_t *config)
{
    chip.gpio_config_calls++;
    if (chip.gpio_config_fails) {
        return ESP_ERR_INVALID_ARG;
    }
    for (int pin = 0; pin < 64; pin++) {
        if ((config->pin_bit_mask >> pin) & 1u) {
            bool valid = (config->mode == GPIO_MODE_OUTPUT) ? GPIO_IS_VALID_OUTPUT_GPIO(pin) : GPIO_IS_VALID_GPIO(pin);
            if (!valid) {
                return ESP_ERR_INVALID_ARG;
            }
        }
    }
    return ESP_OK;
}

esp_err_t gpio_set_level(gpio_num_t pin, uint32_t level)
{
    if (!GPIO_IS_VALID_GPIO(pin)) {
        return ESP_ERR_INVALID_ARG;
    }
    int old      = s_level[pin];
    s_level[pin] = level ? 1 : 0;
    if (pin == CHIP_NSS) {
        if (old == 1 && level == 0) {
            if (chip.bus_held <= 0) {
                chip.violations++;
            }
            s_nss_low = true;
        } else if (old == 0 && level == 1) {
            s_nss_low = false;
            nss_released();
        }
    } else if (pin == CHIP_RST) {
        if (old == 1 && level == 0) {
            chip.in_reset = true;
            chip.busy     = false;
        } else if (old == 0 && level == 1) {
            chip.in_reset = false;
            boot();
        }
    }
    return ESP_OK;
}

static bool irq_asserted(void)
{
    return (chip.reg[PN5180_IRQ_STATUS] & (chip.reg[PN5180_IRQ_ENABLE] | PN5180_LPCD_IRQ_STAT | PN5180_GENERAL_ERROR_IRQ_STAT)) != 0;
}

int gpio_get_level(gpio_num_t pin)
{
    if (pin == CHIP_BUSY) {
        return (chip.busy || chip.busy_stuck || chip.now_us < chip.busy_until) ? 1 : 0;
    }
    if (pin == CHIP_IRQ) {
        bool active_high = (chip.eeprom[PN5180_IRQ_PIN_CONFIG] & PN5180_IRQ_PIN_CONFIG_ACTIVE_HIGH) != 0;
        return (irq_asserted() == active_high) ? 1 : 0;
    }
    return GPIO_IS_VALID_GPIO(pin) ? s_level[pin] : 0;
}

esp_err_t gpio_install_isr_service(int intr_alloc_flags)
{
    (void)intr_alloc_flags;
    if (s_isr_service) {
        return ESP_ERR_INVALID_STATE;
    }
    s_isr_service = true;
    return ESP_OK;
}

esp_err_t gpio_isr_handler_add(gpio_num_t pin, gpio_isr_t handler, void *arg)
{
    s_isr     = handler;
    s_isr_arg = arg;
    s_isr_pin = pin;
    return ESP_OK;
}

esp_err_t gpio_isr_handler_remove(gpio_num_t pin)
{
    if (pin == s_isr_pin) {
        s_isr     = NULL;
        s_isr_arg = NULL;
        s_isr_pin = GPIO_NUM_NC;
    }
    return ESP_OK;
}

/* ---- Time, esp_timer and semaphores ---- */

int64_t esp_timer_get_time(void)
{
    return chip.now_us;
}

void esp_rom_delay_us(uint32_t us)
{
    chip.now_us += us;
}

void vTaskDelay(TickType_t ticks)
{
    chip.now_us += (int64_t)ticks * TICK_US;
}

const char *esp_err_to_name(esp_err_t code)
{
    (void)code;
    return "ESP_ERR";
}

struct host_esp_timer
{
    esp_timer_cb_t callback;
    void          *arg;
    bool           active;
    int64_t        expiry;
    bool           in_use;
};

#define HOST_TIMERS 4
static struct host_esp_timer s_timers[HOST_TIMERS];

esp_err_t esp_timer_create(const esp_timer_create_args_t *args, esp_timer_handle_t *out)
{
    if (chip.timer_create_fails) {
        return ESP_ERR_NO_MEM;
    }
    for (int i = 0; i < HOST_TIMERS; i++) {
        if (!s_timers[i].in_use) {
            s_timers[i] = (struct host_esp_timer){.callback = args->callback, .arg = args->arg, .in_use = true};
            *out        = &s_timers[i];
            return ESP_OK;
        }
    }
    return ESP_ERR_NO_MEM;
}

esp_err_t esp_timer_start_once(esp_timer_handle_t timer, uint64_t timeout_us)
{
    if (timer->active) {
        return ESP_ERR_INVALID_STATE;
    }
    timer->active = true;
    timer->expiry = chip.now_us + (int64_t)timeout_us;
    return ESP_OK;
}

esp_err_t esp_timer_stop(esp_timer_handle_t timer)
{
    if (!timer->active) {
        return ESP_ERR_INVALID_STATE;
    }
    timer->active = false;
    return ESP_OK;
}

esp_err_t esp_timer_delete(esp_timer_handle_t timer)
{
    if (timer->active) {
        return ESP_ERR_INVALID_STATE;
    }
    timer->in_use = false;
    return ESP_OK;
}

struct host_semaphore
{
    bool given;
};

SemaphoreHandle_t xSemaphoreCreateBinary(void)
{
    return calloc(1, sizeof(struct host_semaphore));
}

void vSemaphoreDelete(SemaphoreHandle_t sem)
{
    free(sem);
}

BaseType_t xSemaphoreGive(SemaphoreHandle_t sem)
{
    if (sem->given) {
        return pdFALSE;
    }
    sem->given = true;
    return pdTRUE;
}

BaseType_t xSemaphoreGiveFromISR(SemaphoreHandle_t sem, BaseType_t *woken)
{
    if (woken != NULL) {
        *woken = pdFALSE;
    }
    return xSemaphoreGive(sem);
}

// Waiting is simulated: a timer that gives this semaphore fires if it expires within the wait, the
// IRQ pin interrupt fires if the pin is active, otherwise the whole wait passes.
BaseType_t xSemaphoreTake(SemaphoreHandle_t sem, TickType_t ticks)
{
    if (sem->given) {
        sem->given = false;
        return pdTRUE;
    }
    if (ticks == portMAX_DELAY) {
        fprintf(stderr, "chip_sim: xSemaphoreTake without timeout would block forever\n");
        abort();
    }
    int64_t until = chip.now_us + (int64_t)ticks * TICK_US;
    for (int i = 0; i < HOST_TIMERS; i++) {
        struct host_esp_timer *t = &s_timers[i];
        if (t->in_use && t->active && t->arg == sem && t->expiry <= until) {
            if (t->expiry > chip.now_us) {
                chip.now_us = t->expiry;
            }
            t->active = false;
            t->callback(t->arg);
            sem->given = false;
            return pdTRUE;
        }
    }
    if (s_isr != NULL && s_isr_arg == sem && gpio_get_level(s_isr_pin) == ((chip.eeprom[PN5180_IRQ_PIN_CONFIG] & 1u) ? 1 : 0)) {
        s_isr(s_isr_arg);
        sem->given = false;
        return pdTRUE;
    }
    chip.now_us = until;
    return pdFALSE;
}

/* ---- Power-on ---- */

void chip_sim_reset(void)
{
    memset(&chip, 0, sizeof(chip));
    memset(&s_spi, 0, sizeof(s_spi));
    memset(s_timers, 0, sizeof(s_timers));
    memset(s_level, 0, sizeof(s_level));
    s_nss_low          = false;
    s_frame_pending    = false;
    s_response_pending = false;
    s_response_frame   = false;
    s_isr_service      = false;
    s_isr              = NULL;
    s_isr_arg          = NULL;
    s_isr_pin          = GPIO_NUM_NC;
    // Pull-ups of the module keep NSS and RST high before the host drives them.
    s_level[CHIP_NSS] = 1;
    s_level[CHIP_RST] = 1;

    // Factory EEPROM of a PN5180 with firmware 3.6: versions LSB first, IDLE IRQ after boot,
    // IRQ pin active high.
    memset(chip.eeprom, 0, sizeof(chip.eeprom));
    chip.eeprom[PN5180_PRODUCT_VERSION]         = 0x06;
    chip.eeprom[PN5180_PRODUCT_VERSION + 1]     = 0x03;
    chip.eeprom[PN5180_FIRMWARE_VERSION]        = 0x06;
    chip.eeprom[PN5180_FIRMWARE_VERSION + 1]    = 0x03;
    chip.eeprom[PN5180_EEPROM_VERSION]          = 0x00;
    chip.eeprom[PN5180_EEPROM_VERSION + 1]      = 0x99;
    chip.eeprom[PN5180_IDLE_IRQ_AFTER_BOOT]     = 0x01;
    chip.eeprom[PN5180_IRQ_PIN_CONFIG]          = PN5180_IRQ_PIN_CONFIG_ACTIVE_HIGH;
    chip.eeprom[0x32]                           = 0x0A; // MFC_AUTH_TIMEOUT
    boot();
    chip.boots = 0;
}
