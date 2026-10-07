#include "fake_pn5180.h"
#include "esp_random.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/task.h"
#include <stdlib.h>
#include <string.h>

static fake_card_fn s_card;
static fake_auth_fn s_auth;
static void        *s_card_ctx;
static int          s_frame_count;
static int64_t      s_time_us;
static uint32_t     s_registers[64];

pn5180_t *fake_pn5180_create(void)
{
    pn5180_t *pn5180      = calloc(1, sizeof(pn5180_t));
    pn5180->timeout_ms    = 500;
    pn5180->hw_rx_timeout = true;
    s_frame_count         = 0;
    s_card                = NULL;
    s_auth                = NULL;
    s_card_ctx            = NULL;
    memset(s_registers, 0, sizeof(s_registers));
    return pn5180;
}

void fake_pn5180_destroy(pn5180_t *pn5180)
{
    free(pn5180);
}

void fake_set_card(fake_card_fn card, fake_auth_fn auth, void *ctx)
{
    s_card     = card;
    s_auth     = auth;
    s_card_ctx = ctx;
}

int fake_frame_count(void)
{
    return s_frame_count;
}

/* ---- The part of src/pn5180.c that the protocol code uses ---- */

pn5180_rf_result_t pn5180_rf_transceive(pn5180_t *pn5180, const uint8_t *tx, size_t tx_len, uint8_t tx_last_bits, uint8_t *rx, size_t rx_size, size_t *rx_len,
                                        uint32_t timeout_us, uint32_t *rx_status)
{
    (void)pn5180;
    size_t   local_len    = 0;
    uint32_t local_status = 0;
    uint8_t  local_rx[512];

    s_frame_count++;
    pn5180_rf_result_t result = PN5180_RF_TIMEOUT;
    if (s_card != NULL) {
        result = s_card(s_card_ctx, tx, tx_len, tx_last_bits, local_rx, sizeof(local_rx), &local_len, timeout_us, &local_status);
    }
    if (timeout_us == 0) {
        // Transmit only: the reader does not listen.
        result    = PN5180_RF_OK;
        local_len = 0;
    }
    // Same buffer rules as the real function.
    if (local_len > rx_size && result == PN5180_RF_COLLISION) {
        local_len = rx_size;
    }
    if (local_len > 0 && rx != NULL) {
        if (local_len > rx_size) {
            result    = PN5180_RF_OVERFLOW;
            local_len = 0;
        } else {
            memcpy(rx, local_rx, local_len);
        }
    } else {
        local_len = 0;
    }
    if (rx_len != NULL) {
        *rx_len = local_len;
    }
    if (rx_status != NULL) {
        *rx_status = local_status;
    }
    return result;
}

bool pn5180_write_register_or_mask(pn5180_t *pn5180, uint8_t addr, uint32_t mask)
{
    (void)pn5180;
    s_registers[addr & 0x3F] |= mask;
    return true;
}

bool pn5180_write_register_and_mask(pn5180_t *pn5180, uint8_t addr, uint32_t mask)
{
    (void)pn5180;
    s_registers[addr & 0x3F] &= mask;
    return true;
}

bool pn5180_read_register(pn5180_t *pn5180, uint8_t reg, uint32_t *value)
{
    (void)pn5180;
    *value = s_registers[reg & 0x3F];
    return true;
}

bool pn5180_clear_irq_status(pn5180_t *pn5180, uint32_t irq_mask)
{
    (void)pn5180;
    (void)irq_mask;
    return true;
}

bool pn5180_load_rf_config(pn5180_t *pn5180, uint8_t tx_conf)
{
    pn5180->tx_config        = tx_conf;
    pn5180->rf_config_loaded = true;
    return true;
}

bool pn5180_set_rf_on(pn5180_t *pn5180)
{
    pn5180->is_rf_on = true;
    return true;
}

bool pn5180_set_rf_off(pn5180_t *pn5180)
{
    pn5180->is_rf_on = false;
    return true;
}

int16_t pn5180_mifare_authenticate(pn5180_t *pn5180, uint8_t blockno, const uint8_t *key, uint8_t key_type, const uint8_t uid[4])
{
    (void)pn5180;
    if (s_auth == NULL) {
        return 0x02; // timeout: nothing in the field answers
    }
    return s_auth(s_card_ctx, blockno, key, key_type, uid);
}

void pn5180_delay_ms(int ms)
{
    s_time_us += (int64_t)ms * 1000;
}

/* ---- ESP-IDF functions used by the protocol sources ---- */

int64_t esp_timer_get_time(void)
{
    return s_time_us;
}

uint32_t esp_random(void)
{
    return 4; // any fixed value keeps the tests repeatable
}

void esp_rom_delay_us(uint32_t us)
{
    s_time_us += us;
}

void vTaskDelay(TickType_t ticks)
{
    s_time_us += (int64_t)ticks * 10000;
}
