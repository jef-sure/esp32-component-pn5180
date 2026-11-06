#include "fake_pn5180.h"
#include "esp_random.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/task.h"
#include "pn5180-internal.h"
#include <stdlib.h>
#include <string.h>

static fake_card_fn s_card;
static fake_auth_fn s_auth;
static void        *s_card_ctx;
static int          s_frame_count;
static int          s_rf_on_count;
static bool         s_field_on;     // the field really is on (pn5180->is_rf_on is the driver's cached view)
static bool         s_rf_on_fails;  // FIELD_ON does not bring the field up (RF collision avoidance)
static int64_t      s_time_us;
static uint32_t     s_registers[64];
static uint32_t     s_random_state;
pn5180_t *fake_pn5180_create(void)
{
    pn5180_t *pn5180      = calloc(1, sizeof(pn5180_t));
    pn5180->timeout_ms    = 500;
    pn5180->hw_rx_timeout = true;
    s_frame_count         = 0;
    s_rf_on_count         = 0;
    s_field_on            = false;
    s_rf_on_fails         = false;
    s_card                = NULL;
    s_auth                = NULL;
    s_card_ctx            = NULL;
    s_random_state        = 1;
    memset(s_registers, 0, sizeof(s_registers));
    // As the driver: no MIFARE authentication was sent yet.
    pn5180->iso14443_last_auth_status = PN5180_MIFARE_AUTH_NONE;
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

int fake_rf_on_count(void)
{
    return s_rf_on_count;
}

void fake_drop_field(bool stays_off)
{
    s_field_on    = false;
    s_rf_on_fails = stays_off;
}

bool fake_tx_crc_enabled(void)
{
    return (s_registers[PN5180_CRC_TX_CONFIG] & 0x01) != 0;
}

bool fake_rx_crc_enabled(void)
{
    return (s_registers[PN5180_CRC_RX_CONFIG] & 0x01) != 0;
}

/* ---- The part of src/pn5180.c that the protocol code uses ---- */

/* The CRC the PN5180 transceiver would append to or check in a frame: CRC-16/A per ISO 14443,
 * polynomial 0x8408 reflected, preset 0xFFFF, no final inversion. */
static uint16_t fake_crc16(const uint8_t *data, size_t len, uint16_t init)
{
    for (size_t i = 0; i < len; i++) {
        uint16_t reg = init ^ data[i];
        for (int bit = 0; bit < 8; bit++) {
            bool lsb = (reg & 1) != 0;
            reg >>= 1;
            if (lsb) {
                reg ^= 0x8408;
            }
        }
        init = reg;
    }
    return init;
}

// True when the frame ends with its own correct CRC.
static bool fake_crc_ok(const uint8_t *frame, size_t len)
{
    if (len < 2) {
        return false;
    }
    uint16_t check = fake_crc16(frame, len - 2, 0xFFFF);
    return (uint8_t)(check & 0xFF) == frame[len - 2] && (uint8_t)(check >> 8) == frame[len - 1];
}

pn5180_rf_result_t pn5180_rf_transceive(pn5180_t *pn5180, const uint8_t *tx, size_t tx_len, uint8_t tx_last_bits, uint8_t *rx, size_t rx_size, size_t *rx_len,
                                        uint32_t timeout_us, uint32_t *rx_status)
{
    (void)pn5180;
    size_t   local_len    = 0;
    uint32_t local_status = 0;
    uint8_t  local_rx[512];

    s_frame_count++;
    pn5180_rf_result_t result = PN5180_RF_TIMEOUT;
    // Without the field no card can answer.
    if (s_card != NULL && s_field_on) {
        result = s_card(s_card_ctx, tx, tx_len, tx_last_bits, local_rx, sizeof(local_rx), &local_len, timeout_us, &local_status);
    }
    if (timeout_us == 0) {
        // Transmit only: the reader does not listen.
        result    = PN5180_RF_OK;
        local_len = 0;
    }

    // The CRC bits of CRC_TX_CONFIG / CRC_RX_CONFIG decide what went on the air and what the
    // receiver accepts, like in the real transceiver. The simulated card sees the frame the
    // driver built and answers with logical bytes; the fake adds the CRC the card would append
    // and checks the one the card would be judged by, so a wrong CRC ordering in the driver
    // shows up as an RX error instead of going unnoticed.
    const bool tx_crc = fake_tx_crc_enabled() && tx_last_bits == 0;
    // The 4-bit ACK/NAK answers (reported by the cards as an RX error) never carry a CRC;
    // every other answer to a CRC request does.
    if (result != PN5180_RF_TIMEOUT && result != PN5180_RF_COLLISION && result != PN5180_RF_RX_ERROR && local_len > 0 && timeout_us != 0) {
        if (tx_crc) {
            // The card received a CRC frame and answers with its own CRC appended.
            if (local_len + 2 > sizeof(local_rx)) {
                result    = PN5180_RF_OVERFLOW;
                local_len = 0;
            } else {
                uint16_t crc     = fake_crc16(local_rx, local_len, 0xFFFF);
                local_rx[local_len]     = (uint8_t)(crc & 0xFF);
                local_rx[local_len + 1] = (uint8_t)(crc >> 8);
                local_len += 2;
            }
        }
        if (result == PN5180_RF_OK && fake_rx_crc_enabled()) {
            // The transceiver checks the CRC of the answer and strips it. The 4-bit ACK/NAK
            // (reported by the card as an RX error) never reaches this branch.
            if (!fake_crc_ok(local_rx, local_len)) {
                local_status |= PN5180_RX_DATA_INTEGRITY_ERROR;
                result = PN5180_RF_RX_ERROR;
            } else {
                local_len -= 2;
            }
        }
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
    if (tx_conf != 0xFF) {
        pn5180->tx_config        = tx_conf;
        pn5180->rf_config_loaded = true;
    }
    return true;
}

// As the driver: without field a card loses its ISO14443-4 session.
static void fake_session_lost(pn5180_t *pn5180)
{
    pn5180->iso14443_layer4_active = false;
    pn5180->iso14443_block_number  = 0;
}

bool pn5180_set_rf_on(pn5180_t *pn5180)
{
    // As the driver: the cached flag is checked against the real field.
    if (pn5180->is_rf_on) {
        if (s_field_on) {
            return true;
        }
        pn5180->is_rf_on = false;
        fake_session_lost(pn5180);
    }
    if (s_rf_on_fails) {
        return false;
    }
    s_field_on       = true;
    pn5180->is_rf_on = true;
    s_rf_on_count++;
    return true;
}

bool pn5180_set_rf_off(pn5180_t *pn5180)
{
    fake_session_lost(pn5180);
    s_field_on       = false;
    pn5180->is_rf_on = false;
    return true;
}

int16_t pn5180_mifare_authenticate(pn5180_t *pn5180, uint8_t blockno, const uint8_t *key, uint8_t key_type, const uint8_t uid[4])
{
    // As the driver: the status is kept in the device. Without a card nothing in the field answers.
    int16_t status = PN5180_MIFARE_AUTH_NO_ANSWER;
    if (s_auth != NULL) {
        status = s_auth(s_card_ctx, blockno, key, key_type, uid);
    }
    pn5180->iso14443_last_auth_status = status;
    return status;
}

void pn5180_delay_ms(int ms)
{
    s_time_us += (int64_t)ms * 1000;
}

void pn5180_sleep_us(pn5180_t *pn5180, uint32_t us)
{
    (void)pn5180;
    s_time_us += us;
}

void pn5180_delay_us(uint32_t us)
{
    s_time_us += us;
}

/* ---- ESP-IDF functions used by the protocol sources ---- */

int64_t esp_timer_get_time(void)
{
    return s_time_us;
}

uint32_t esp_random(void)
{
    // xorshift32 from a fixed start: every bit varies and the tests stay repeatable
    s_random_state ^= s_random_state << 13;
    s_random_state ^= s_random_state >> 17;
    s_random_state ^= s_random_state << 5;
    return s_random_state;
}

void esp_rom_delay_us(uint32_t us)
{
    s_time_us += us;
}

void vTaskDelay(TickType_t ticks)
{
    s_time_us += (int64_t)ticks * 10000;
}
