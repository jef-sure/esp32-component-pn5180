#include "pn5180-14443.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "pn5180-internal.h"
#include "pn5180-mifare.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "pn5180-14443";

#define PN5180_14443A_RF_CONFIG 0x00 // ISO14443-A 106 kbit/s

static const uint16_t pn5180_iso14443_4_fs_table[] = {16, 24, 32, 40, 48, 64, 96, 128, 256, 512, 1024, 2048, 4096};

typedef enum
{
    RX_RESULT_OK,
    RX_RESULT_TIMEOUT,
    RX_RESULT_PROTOCOL_ERROR,
    RX_RESULT_FATAL,
} rx_result_t;

static pn5180_uids_array_t *pn5180_14443_poll(pn5180_t *pn5180, pn5180_poll_status_t *status);

static bool pn5180_mifare_halt(pn5180_t *pn5180);

static bool        pn5180_14443_select_by_uid(pn5180_t *pn5180, pn5180_uid_t *uid);
static bool        pn5180_14443_detect_ultralight_variant(pn5180_t *pn5180, pn5180_uid_t *uid, pn5180_card_type_t *subtype, int *blocks_count);
static bool        pn5180_14443_setup_rf(pn5180_t *pn5180);
static void        pn5180_iso14443_4_reset_state(pn5180_t *pn5180);
static rx_result_t pn5180_iso14443_4_exchange_frame(pn5180_t *pn5180, const char *operation, const uint8_t *tx, size_t tx_len, int64_t timeout_ms,
                                                    uint8_t *rx_buf, size_t rx_buf_size, uint16_t *received);
static bool        pn5180_iso14443_4_apply_ats(pn5180_t *pn5180, const uint8_t *ats, uint16_t ats_len, uint8_t *sfgi_out);
static bool        _pn5180_14443_detect_card_type_and_capacity( //
    pn5180_t     *pn5180,                                //
    pn5180_uid_t *uid,                                   //
    int          *blocks_count,                          //
    int          *block_size                             //
);

static void pn5180_iso14443_4_reset_state(pn5180_t *pn5180)
{
    pn5180->iso14443_layer4_active = false;
    pn5180->iso14443_block_number  = 0;
    pn5180->iso14443_frame_size    = 0;
    pn5180->iso14443_fwt_ms        = 0;
}

// Sends one ISO14443-4 block and receives the answer. timeout_ms is the frame waiting time.
static rx_result_t pn5180_iso14443_4_exchange_frame(pn5180_t *pn5180, const char *operation, const uint8_t *tx, size_t tx_len, int64_t timeout_ms,
                                                    uint8_t *rx_buf, size_t rx_buf_size, uint16_t *received)
{
    // The hardware timer covers about 19.7 s; longer waiting times (large WTX multipliers) are capped there.
    uint32_t timeout_us = (timeout_ms > 19000) ? 19000000u : (uint32_t)(timeout_ms * 1000);
    size_t   rx_len     = 0;

    pn5180_rf_result_t result = pn5180_rf_transceive(pn5180, tx, tx_len, 0, rx_buf, rx_buf_size, &rx_len, timeout_us, NULL);
    switch (result) {
    case PN5180_RF_OK:
        break;
    case PN5180_RF_TIMEOUT:
        return RX_RESULT_TIMEOUT;
    case PN5180_RF_FATAL:
        return RX_RESULT_FATAL;
    default:
        ESP_LOGW(TAG, "%s: protocol error (result=%d)", operation, (int)result);
        return RX_RESULT_PROTOCOL_ERROR;
    }
    if (rx_len == 0) {
        ESP_LOGE(TAG, "%s returned an empty frame", operation);
        return RX_RESULT_PROTOCOL_ERROR;
    }

    *received = (uint16_t)rx_len;
    return RX_RESULT_OK;
}

static bool pn5180_iso14443_4_apply_ats(pn5180_t *pn5180, const uint8_t *ats, uint16_t ats_len, uint8_t *sfgi_out)
{
    uint8_t  fsci = 2;
    uint8_t  fwi  = 4;
    uint8_t  sfgi = 0;
    uint16_t idx  = 1;

    if (ats == NULL || ats_len < 1) {
        return false;
    }
    if (ats[0] > ats_len) {
        ESP_LOGE(TAG, "ATS length mismatch: TL=%u rx=%" PRIu16, ats[0], ats_len);
        return false;
    }
    if (ats[0] >= 2) {
        uint8_t t0 = ats[idx++];
        fsci       = (uint8_t)(t0 & 0x0F);
        if (fsci >= (sizeof(pn5180_iso14443_4_fs_table) / sizeof(pn5180_iso14443_4_fs_table[0]))) {
            // Reserved values: use the largest defined frame size instead of refusing the card.
            fsci = (uint8_t)((sizeof(pn5180_iso14443_4_fs_table) / sizeof(pn5180_iso14443_4_fs_table[0])) - 1u);
        }

        if (t0 & 0x10) {
            if (idx >= ats[0]) {
                ESP_LOGE(TAG, "ATS missing TA1");
                return false;
            }
            idx++;
        }
        if (t0 & 0x20) {
            if (idx >= ats[0]) {
                ESP_LOGE(TAG, "ATS missing TB1");
                return false;
            }
            fwi  = (uint8_t)((ats[idx] >> 4) & 0x0F);
            sfgi = (uint8_t)(ats[idx] & 0x0F);
            idx++;
        }
        if (t0 & 0x40) {
            if (idx >= ats[0]) {
                ESP_LOGE(TAG, "ATS missing TC1");
                return false;
            }
            idx++;
        }
    }

    pn5180->iso14443_frame_size = (uint16_t)(pn5180_iso14443_4_fs_table[fsci] - 2u);
    if (fwi > 14) {
        fwi = 14;
    }
    pn5180->iso14443_fwt_ms = (((302LL << fwi) + 3625LL) + 999LL) / 1000LL;
    if (pn5180->iso14443_fwt_ms < 1) {
        pn5180->iso14443_fwt_ms = 1;
    }

    // SFGI 15 is reserved and read as 0, as are all values without a guard time need.
    *sfgi_out = (sfgi > 14) ? 0 : sfgi;
    PN5180_LOGD(TAG, "ATS applied: FSCI=%u frame=%u FWI=%u FWT=%" PRId64 "ms SFGI=%u", fsci, pn5180->iso14443_frame_size, fwi, pn5180->iso14443_fwt_ms, sfgi);
    return true;
}

static bool _pn5180_14443_setup_rf(pn5180_proto_t *proto)
{
    return pn5180_14443_setup_rf(proto->pn5180);
}

static pn5180_uids_array_t *_pn5180_14443_get_all_uids(pn5180_proto_t *proto)
{
    pn5180_poll_status_t status;
    return pn5180_14443_poll(proto->pn5180, &status);
}

static bool _pn5180_14443_select_by_uid(pn5180_proto_t *proto, pn5180_uid_t *uid)
{
    return pn5180_14443_select_by_uid(proto->pn5180, uid);
}

static bool _pn5180_14443_mifare_block_read(pn5180_proto_t *proto, int blockno, uint8_t *buffer, size_t buffer_len)
{
    if (proto->pn5180->iso14443_current_card_type == PN5180_MIFARE_DESFIRE) {
        // ISO14443-4 card: READ BINARY on the file the application selected, blockno is the file offset.
        if (buffer_len == 0 || buffer_len > 255 || blockno < 0 || blockno > 0x7FFF) {
            return false;
        }
        size_t got = buffer_len;
        // A shorter answer (end of file) would leave the rest of the buffer unset.
        return pn5180_14443_4_read_binary(proto->pn5180, (uint16_t)blockno, (uint8_t)buffer_len, buffer, &got) && got == buffer_len;
    }
    return pn5180_mifare_block_read(proto->pn5180, blockno, buffer, buffer_len);
}

static int _pn5180_14443_mifare_block_write(pn5180_proto_t *proto, int blockno, const uint8_t *buffer, size_t buffer_len)
{
    if (proto->pn5180->iso14443_layer4_active) {
        // A raw MIFARE frame would break the ISO14443-4 session; such cards are written with APDUs.
        ESP_LOGE(TAG, "block_write is not available while ISO14443-4 is active");
        return -1;
    }
    return pn5180_mifare_block_write(proto->pn5180, blockno, buffer, buffer_len);
}

static bool _pn5180_14443_halt(pn5180_proto_t *proto)
{
    return pn5180_mifare_halt(proto->pn5180);
}

static bool _pn5180_14443_authenticate( //
    pn5180_proto_t     *proto,          //
    const uint8_t      *key,            //
    uint8_t             key_type,       //
    const pn5180_uid_t *uid,            //
    int                 blockno         //
)
{
    // MIFARE authentication for already selected card
    // subtype indicates card type (Classic 1K/4K, Plus, etc.)
    // key_type: 0x60 for Key A, 0x61 for Key B

    if (uid->subtype == PN5180_MIFARE_ULTRALIGHT || uid->subtype == PN5180_MIFARE_ULTRALIGHT_C || uid->subtype == PN5180_MIFARE_ULTRALIGHT_EV1 ||
        uid->subtype == PN5180_MIFARE_NTAG210 || uid->subtype == PN5180_MIFARE_NTAG212 || uid->subtype == PN5180_MIFARE_NTAG213 ||
        uid->subtype == PN5180_MIFARE_NTAG215 || uid->subtype == PN5180_MIFARE_NTAG216) {
        // Ultralight variants don't require MIFARE authentication
        return true;
    }

    if (uid->subtype == PN5180_MIFARE_DESFIRE) {
        // DESFire uses ISO 14443-4 authentication, not MIFARE Crypto1
        return true;
    }

    // MIFARE Classic/Plus authentication with Crypto1
    // Extract last 4 bytes of UID for authentication
    // - 4-byte UIDs: use all 4 bytes
    // - 7-byte UIDs: use bytes [3:6] (last 4 bytes)
    // - 10-byte UIDs: use bytes [6:9] (last 4 bytes)
    const uint8_t *uid_for_auth;
    if (uid->uid_length <= 4) {
        uid_for_auth = uid->uid;
    } else if (uid->uid_length == 7) {
        uid_for_auth = &uid->uid[3]; // Last 4 bytes of 7-byte UID
    } else if (uid->uid_length == 10) {
        uid_for_auth = &uid->uid[6]; // Last 4 bytes of 10-byte UID
    } else {
        ESP_LOGE(TAG, "Invalid UID length %d for MIFARE authentication", uid->uid_length);
        return false;
    }

    PN5180_LOGD(TAG, "Authenticating: KeyType=0x%02X Block=%d Key=[%02X %02X %02X %02X %02X %02X] UID_Auth=[%02X %02X %02X %02X]", key_type, blockno, key[0],
                key[1], key[2], key[3], key[4], key[5], uid_for_auth[0], uid_for_auth[1], uid_for_auth[2], uid_for_auth[3]);

    // Send AUTH command immediately - DO NOT manipulate registers between SELECT and AUTH
    // The working reference implementation sends AUTH with no register touches
    int16_t auth_result = pn5180_mifare_authenticate(proto->pn5180, (uint8_t)blockno, key, key_type, uid_for_auth);

    if (auth_result < 0) {
        ESP_LOGE(TAG, "MIFARE authentication error code %d", auth_result);
        return false;
    }

    // Check authentication status (0x00 = success)
    if (auth_result != 0x00) {
        PN5180_LOGD(TAG, "MIFARE authentication rejected (status: 0x%02X)", auth_result);
        // On failed authentication, disable Crypto1 and reset to clean state
        pn5180_write_register_and_mask(proto->pn5180, PN5180_SYSTEM_CONFIG,
                                       PN5180_SYSTEM_CONFIG_CLEAR_CRYPTO_MASK); // Clear MFC_CRYPTO_ON
        pn5180_disable_crc(proto->pn5180);
        return false;
    }

    PN5180_LOGD(TAG, "MIFARE authentication successful for block %d", blockno);

    // pn5180_delay_ms(1);

    // Enable CRC for subsequent authenticated read/write operations
    // pn5180_enable_crc(proto->pn5180);
    return true;
}

pn5180_proto_t *pn5180_14443_init(pn5180_t *pn5180)
{
    pn5180_proto_t *proto = (pn5180_proto_t *)calloc(1, sizeof(pn5180_proto_t));
    if (proto == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for PN5180 14443 protocol");
        return NULL;
    }
    proto->rf_config                     = PN5180_14443A_RF_CONFIG;
    proto->pn5180                        = pn5180;
    proto->setup_rf                      = _pn5180_14443_setup_rf;
    proto->get_all_uids                  = _pn5180_14443_get_all_uids;
    proto->select_by_uid                 = _pn5180_14443_select_by_uid;
    proto->block_read                    = _pn5180_14443_mifare_block_read;
    proto->block_write                   = _pn5180_14443_mifare_block_write;
    proto->authenticate                  = _pn5180_14443_authenticate;
    proto->detect_card_type_and_capacity = _pn5180_14443_detect_card_type_and_capacity;
    proto->halt                          = _pn5180_14443_halt;
    return proto;
}

static bool pn5180_14443_setup_rf(pn5180_t *pn5180)
{
    if (pn5180->is_rf_on) {
        if (pn5180->rf_config_loaded && pn5180->tx_config == PN5180_14443A_RF_CONFIG) {
            return true;
        }
        pn5180_set_rf_off(pn5180);
        // Cards return to their idle state only after the field was off long enough.
        pn5180_delay_us(PN5180_RF_OFF_TIME_US);
    }
    bool ret = pn5180_load_rf_config(pn5180, PN5180_14443A_RF_CONFIG);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to load RF config for 14443A");
        return false;
    }
    ret = pn5180_set_rf_on(pn5180);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to turn RF on for 14443A");
        return false;
    }
    return true;
}

// Sends a 7-bit short frame (REQA or WUPA) and reads the 2-byte ATQA.
static bool pn5180_14443_send_short_frame(pn5180_t *pn5180, uint8_t cmd, const char *name, uint8_t *atqa, bool *fatal)
{
    if (fatal != NULL) {
        *fatal = false;
    }
    // Clear MFC_CRYPTO_ON bit to ensure clean state for new card discovery
    pn5180_write_register_and_mask(pn5180, PN5180_SYSTEM_CONFIG, PN5180_SYSTEM_CONFIG_CLEAR_CRYPTO_MASK);
    pn5180_disable_crc(pn5180);
    PN5180_LOGD(TAG, "Sending %s: 0x%02X (7 bits)", name, cmd);

    size_t             rx_len = 0;
    pn5180_rf_result_t result = pn5180_rf_transceive(pn5180, &cmd, 1, 7, atqa, 2, &rx_len, PN5180_TIMEOUT_14443A_ACTIVATION_US, NULL);
    if (result == PN5180_RF_FATAL) {
        ESP_LOGE(TAG, "Failed to send %s command", name);
        if (fatal != NULL) {
            *fatal = true;
        }
        return false;
    }
    // Several cards answering at once make the ATQA collide; that still means cards are present.
    if (result != PN5180_RF_OK && result != PN5180_RF_COLLISION && result != PN5180_RF_RX_ERROR) {
        PN5180_LOGD(TAG, "No response to %s (result=%d)", name, (int)result);
        return false;
    }
    if (rx_len == 0) {
        return false;
    }
    PN5180_LOGD(TAG, "%s Success, ATQA: 0x%02X%02X", name, atqa[0], atqa[1]);
    return true;
}

static bool pn5180_14443_send_reqa(pn5180_t *pn5180, uint8_t *atqa, bool *fatal)
{
    return pn5180_14443_send_short_frame(pn5180, 0x26, "REQA", atqa, fatal);
}

static bool pn5180_14443_send_wupa(pn5180_t *pn5180, uint8_t *atqa)
{
    return pn5180_14443_send_short_frame(pn5180, 0x52, "WUPA", atqa, NULL);
}

static bool prepare_14443A_activation(pn5180_t *pn5180)
{
    if (!pn5180_14443_setup_rf(pn5180)) {
        ESP_LOGE(TAG, "Failed to setup RF for 14443A activation");
        return false;
    }

    // Full transceiver reset to clear both software and hardware Crypto1 state
    // This matches the working log initialization sequence:

    // 1. Clear MFC_CRYPTO_ON software bit (bit 6) only
    if (!pn5180_write_register_and_mask(pn5180, PN5180_SYSTEM_CONFIG, PN5180_SYSTEM_CONFIG_CLEAR_CRYPTO_MASK)) {
        ESP_LOGE(TAG, "Failed to clear MFC_CRYPTO_ON");
        return false;
    }

    // 2. Disable TX/RX CRC
    pn5180_disable_crc(pn5180);

    // 3. Force transceiver to IDLE state (clears bits [2:0])
    if (!pn5180_write_register_and_mask(pn5180, PN5180_SYSTEM_CONFIG, PN5180_SYSTEM_CONFIG_CLEAR_TX_MODE_MASK)) {
        ESP_LOGE(TAG, "Failed to set transceiver to IDLE");
        return false;
    }

    // 4. Set to Transceive state
    if (!pn5180_write_register_or_mask(pn5180, PN5180_SYSTEM_CONFIG, PN5180_SYSTEM_CONFIG_TX_MODE_TRANSCEIVE)) {
        ESP_LOGE(TAG, "Failed to set Transceive state");
        return false;
    }

    // 5. Clear all IRQ flags
    pn5180_clear_all_irqs(pn5180);

    return true;
}

static bool pn5180_14443_send_select(pn5180_t *pn5180, int cascade_level, uint8_t *level_data, uint8_t *sak)
{
    pn5180_enable_crc(pn5180);
    uint8_t cmd_buf[7];
    cmd_buf[0] = 0x93 + ((cascade_level - 1) * 2); // 0x93, 0x95, 0x97 for cascade levels 1,2,3
    cmd_buf[1] = 0x70;                             // NVB = 0x70 (full 5 bytes)
    memcpy(&cmd_buf[2], level_data, 5);            // Copy UID CLn + BCC
    PN5180_LOGD(TAG, "Sending Select command %d", cascade_level);
    PN5180_LOGD(TAG, "SELECT data: %02X %02X %02X %02X %02X %02X %02X", cmd_buf[0], cmd_buf[1], cmd_buf[2], cmd_buf[3], cmd_buf[4], cmd_buf[5], cmd_buf[6]);
    size_t             rx_len = 0;
    pn5180_rf_result_t result = pn5180_rf_transceive(pn5180, cmd_buf, 7, 0, sak, 1, &rx_len, PN5180_TIMEOUT_14443A_ACTIVATION_US, NULL);
    if (result != PN5180_RF_OK) {
        pn5180_disable_crc(pn5180);
        if (result == PN5180_RF_TIMEOUT) {
            ESP_LOGE(TAG, "Timeout waiting for Select response at level %d", cascade_level);
        } else {
            ESP_LOGE(TAG, "Select failed at level %d (result=%d, possibly CRC mismatch)", cascade_level, (int)result);
        }
        return false;
    }
    if (rx_len != 1) {
        ESP_LOGE(TAG, "SAK frame error: expected 1 byte, got %u", (unsigned)rx_len);
        pn5180_disable_crc(pn5180);
        return false;
    }
    return true;
}

// Configure RX bit alignment for anticollision split-byte reception.
// When align > 0, also enables VALUES_AFTER_COLLISION so received bits
// up to the collision point retain their sampled value.
static void pn5180_set_rx_align(pn5180_t *pn5180, uint8_t align)
{
    // Clear RX_BIT_ALIGN and VALUES_AFTER_COLLISION
    pn5180_write_register_and_mask(pn5180, PN5180_CRC_RX_CONFIG, ~(PN5180_CRC_RX_CONFIG_RX_BIT_ALIGN_MASK | PN5180_CRC_RX_CONFIG_VALUES_AFTER_COLLISION_MASK));
    if (align > 0) {
        // Set new RX_BIT_ALIGN value and enable VALUES_AFTER_COLLISION
        pn5180_write_register_or_mask(pn5180, PN5180_CRC_RX_CONFIG,
                                      ((uint32_t)align << PN5180_CRC_RX_CONFIG_RX_BIT_ALIGN_POS) | PN5180_CRC_RX_CONFIG_VALUES_AFTER_COLLISION_MASK);
    }
}

// Merge received FIFO bytes into uid_cl at the correct byte offset,
// handling the split-byte overlap when known_extra_bits > 0.
static void pn5180_merge_rx_uid(uint8_t *uid_cl, uint8_t known_bytes, uint8_t known_extra_bits, const uint8_t *rx_buf, uint8_t rx_count)
{
    if (rx_count == 0) return;
    if (known_extra_bits > 0) {
        // Split-byte merge: keep known low bits, take received high bits
        uid_cl[known_bytes] = (uid_cl[known_bytes] & (uint8_t)((1u << known_extra_bits) - 1u)) | (rx_buf[0] & (uint8_t)(0xFFu << known_extra_bits));
    } else {
        uid_cl[known_bytes] = rx_buf[0];
    }
    for (uint8_t i = 1; i < rx_count && (known_bytes + i) < 5; i++) {
        uid_cl[known_bytes + i] = rx_buf[i];
    }
}

// ISO 14443-3A anticollision for a single cascade level.
// Iteratively narrows the UID by setting RXALIGN, sending partial prefixes,
// merging received continuation bytes, and resolving collisions bit-by-bit.
static bool pn5180_14443_anticollision_level(pn5180_t *pn5180, uint8_t cascade_level, uint8_t temp_uid[5], uint8_t *uid_len)
{
    uint8_t sel             = 0x93 + (2 * (cascade_level - 1));
    uint8_t uid_cl[5]       = {0}; // 4 UID bytes + BCC for this cascade level
    uint8_t known_bits      = 0;
    uint8_t collision_count = 0;

    while (known_bits < 40 && collision_count < 32) {
        uint8_t known_bytes      = known_bits / 8;
        uint8_t known_extra_bits = known_bits % 8;

        // Build anticollision frame: SEL + NVB + known UID bits
        uint8_t cmd_buf[9];
        cmd_buf[0] = sel;
        cmd_buf[1] = ((known_bytes + 2) << 4) | known_extra_bits;
        if (known_bytes > 0) {
            memcpy(&cmd_buf[2], uid_cl, known_bytes);
        }
        if (known_extra_bits > 0) {
            cmd_buf[2 + known_bytes] = uid_cl[known_bytes] & (uint8_t)((1u << known_extra_bits) - 1u);
        }
        uint8_t cmd_len = 2 + known_bytes + (known_extra_bits > 0 ? 1 : 0);

        // Tell the receiver where to place the first incoming bit within the FIFO byte
        pn5180_set_rx_align(pn5180, known_extra_bits);

        PN5180_LOGD(TAG, "Anticollision CL%" PRIu8 ": known=%" PRIu8 " NVB=0x%02X", cascade_level, known_bits, cmd_buf[1]);

        // Up to 5 bytes are expected (4 UID bytes and BCC).
        uint8_t            rx_raw[8] = {0};
        size_t             rx_count  = 0;
        uint32_t           rx_status = 0;
        pn5180_rf_result_t result    = pn5180_rf_transceive(pn5180, cmd_buf, cmd_len, known_extra_bits, rx_raw, sizeof(rx_raw), &rx_count,
                                                            PN5180_TIMEOUT_14443A_ACTIVATION_US, &rx_status);

        // Reset RX alignment before any further register access
        pn5180_set_rx_align(pn5180, 0);

        if (result == PN5180_RF_FATAL) {
            ESP_LOGE(TAG, "Failed to send anticollision at level %" PRIu8, cascade_level);
            return false;
        }
        if (result == PN5180_RF_TIMEOUT) {
            ESP_LOGE(TAG, "Timeout in anticollision at level %" PRIu8, cascade_level);
            return false;
        }
        if (result == PN5180_RF_OVERFLOW) {
            ESP_LOGE(TAG, "Invalid response length at level %" PRIu8, cascade_level);
            return false;
        }
        uint16_t rx_bytes = (uint16_t)rx_count;
        bool     has_coll = (result == PN5180_RF_COLLISION);

        // --- Collision path ---
        if (has_coll) {
            // RX_COLL_POS includes the RX_BIT_ALIGN offset, so it is relative to
            // the first FIFO byte (not the first received bit on the air).
            // Total UID bits resolved = known_bytes * 8 + coll_pos.
            uint8_t coll_pos = (rx_status >> PN5180_RX_COLL_POS_START) & PN5180_RX_COLL_POS_MASK;

            // Use the received FIFO data (may include bytes past collision)
            uint8_t rx_buf[5] = {0};
            uint8_t to_read   = (rx_bytes > 5) ? 5 : (uint8_t)rx_bytes;
            memcpy(rx_buf, rx_raw, to_read);

            // Merge received data at the correct byte offset
            pn5180_merge_rx_uid(uid_cl, known_bytes, known_extra_bits, rx_buf, to_read);

            // Advance known_bits to the collision point
            known_bits = known_bytes * 8 + coll_pos;

            // Force the collision bit to 1 (choose higher UID branch) and advance
            if (known_bits / 8 < 5) {
                uid_cl[known_bits / 8] |= (uint8_t)(1u << (known_bits % 8));
            }
            known_bits++;
            collision_count++;

            PN5180_LOGD(TAG, "Collision at CL%" PRIu8 " bit %" PRIu8 ", resolved %" PRIu8 " bits", cascade_level, (uint8_t)(known_bits - 1), known_bits);
            continue;
        }

        // --- Error without collision flag ---
        if (result == PN5180_RF_RX_ERROR && rx_bytes == 0) {
            ESP_LOGE(TAG, "General error during anticollision at level %" PRIu8, cascade_level);
            return false;
        }

        // --- Success path (no collision) ---
        // A parity error still delivers data here; the BCC check below decides whether it is usable.
        if (rx_bytes == 0 || rx_bytes > 5) {
            ESP_LOGE(TAG, "Invalid response length %" PRIu16 " at level %" PRIu8, rx_bytes, cascade_level);
            return false;
        }

        uint8_t rx_buf[5] = {0};
        memcpy(rx_buf, rx_raw, rx_bytes);

        // Merge received data at the correct byte offset
        pn5180_merge_rx_uid(uid_cl, known_bytes, known_extra_bits, rx_buf, (uint8_t)rx_bytes);

        // We need 5 bytes total (4 UID + BCC)
        if (known_bytes + rx_bytes < 5) {
            ESP_LOGE(TAG, "Incomplete UID at level %" PRIu8 ": got %" PRIu16 " bytes at offset %" PRIu8, cascade_level, rx_bytes, known_bytes);
            return false;
        }

        // BCC check
        uint8_t bcc = uid_cl[0] ^ uid_cl[1] ^ uid_cl[2] ^ uid_cl[3];
        if (bcc != uid_cl[4]) {
            ESP_LOGE(TAG, "BCC check failed at level %" PRIu8 " (computed 0x%02X, got 0x%02X)", cascade_level, bcc, uid_cl[4]);
            return false;
        }

        *uid_len = 4;
        memcpy(temp_uid, uid_cl, 5);
        return true;
    }

    ESP_LOGE(TAG, "Anticollision failed at level %" PRIu8 " after %" PRIu8 " collisions", cascade_level, collision_count);
    return false;
}

static bool pn5180_14443_resolve_full_uid_cascade(pn5180_t *pn5180, uint8_t *full_uid, int8_t *full_uid_len, uint8_t *sak)
{
    uint8_t cascade_level = 1;
    *full_uid_len         = 0;
    pn5180_disable_crc(pn5180);
    while (cascade_level <= 3) {
        uint8_t level_data[5]; // UID + BCC
        uint8_t len;
        if (!pn5180_14443_anticollision_level(pn5180, cascade_level, level_data, &len)) {
            PN5180_LOGD(TAG, "Anticollision failed at level %" PRIu8, cascade_level);
            return false;
        }
        if (!pn5180_14443_send_select(pn5180, cascade_level, level_data, sak)) {
            ESP_LOGE(TAG, "Select command failed at level %" PRIu8, cascade_level);
            return false;
        }
        // SAK Bit 3 (0x04) indicates if another cascade level follows
        if (*sak & 0x04) {
            // It's a 7 or 10 byte UID. Skip CT (0x88) and take 3 bytes.
            if (level_data[0] != 0x88) {
                ESP_LOGE(TAG, "Protocol Error: Expected Cascade Tag 0x88, got 0x%02X", level_data[0]);
                return false;
            }
            memcpy(&full_uid[*full_uid_len], &level_data[1], 3);
            *full_uid_len += 3;
            cascade_level++;
            // Disable CRC before next anticollision level
            pn5180_disable_crc(pn5180);
        } else {
            // Final level. Take all 4 bytes.
            memcpy(&full_uid[*full_uid_len], level_data, 4);
            *full_uid_len += 4;
            return true;
        }
    }
    return false;
}

static pn5180_uids_array_t *pn5180_14443_poll(pn5180_t *pn5180, pn5180_poll_status_t *status)
{
    pn5180_uids_array_t *uids       = NULL;
    uint8_t              card_count = 0;

    *status = PN5180_POLL_NO_TARGET;
    if (!prepare_14443A_activation(pn5180)) {
        *status = PN5180_POLL_TRANSPORT_ERROR;
        return NULL;
    }
    while (card_count < 14) {
        uint8_t atqa[2] = {0, 0};
        bool    fatal   = false;
        if (!pn5180_14443_send_reqa(pn5180, atqa, &fatal)) {
            if (fatal && uids == NULL) {
                *status = PN5180_POLL_TRANSPORT_ERROR;
            }
            PN5180_LOGD(TAG, "No more cards found.");
            break;
        }

        uint8_t full_uid[12];
        int8_t  full_uid_len = 0;
        uint8_t sak;
        if (!pn5180_14443_resolve_full_uid_cascade(pn5180, full_uid, &full_uid_len, &sak)) {
            // A card answered REQA but could not be singled out.
            if (uids == NULL) {
                *status = PN5180_POLL_PROTOCOL_ERROR;
            }
            break;
        }
        // A card that shows up again did not take the HLTA: the scan would find it forever.
        bool duplicate = false;
        for (int i = 0; uids != NULL && i < uids->uids_count; i++) {
            if (uids->uids[i].uid_length == full_uid_len && memcmp(uids->uids[i].uid, full_uid, (size_t)full_uid_len) == 0) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            ESP_LOGW(TAG, "Card answered again after HLTA, ending the scan");
            pn5180_mifare_halt(pn5180);
            break;
        }
        card_count++;
        ESP_LOGI(TAG, "Found Card %d: UID Len %d", card_count, full_uid_len);
        uint32_t agc_reg     = 0;
        uint16_t current_agc = 0;
        if (pn5180_read_register(pn5180, PN5180_RF_STATUS, &agc_reg)) {
            current_agc = (uint16_t)(agc_reg & PN5180_RF_STATUS_AGC_MASK);
        }

        // pn5180_uids_array_t holds one entry itself; further entries follow it.
        int                  count    = (uids == NULL) ? 0 : uids->uids_count;
        pn5180_uids_array_t *new_uids = realloc(uids, sizeof(pn5180_uids_array_t) + ((size_t)count * sizeof(pn5180_uid_t)));
        if (new_uids == NULL) {
            ESP_LOGE(TAG, "Memory allocation failed for UIDs");
            if (uids == NULL) {
                *status = PN5180_POLL_NO_MEMORY;
            }
            pn5180_mifare_halt(pn5180);
            break;
        }
        uids                = new_uids;
        pn5180_uid_t *entry = &uids->uids[count];
        memset(entry, 0, sizeof(*entry));
        entry->uid_length = full_uid_len;
        entry->sak        = sak;
        entry->agc        = current_agc;
        entry->subtype    = PN5180_MIFARE_UNKNOWN;
        entry->atqa[0]    = atqa[0];
        entry->atqa[1]    = atqa[1];
        memcpy(entry->uid, full_uid, full_uid_len);
        uids->uids_count = count + 1;

        // Halt the card so that the next REQA finds the remaining ones.
        pn5180_mifare_halt(pn5180);
    }
    if (uids != NULL) {
        *status = PN5180_POLL_FOUND;
    }
    return uids;
}

pn5180_uids_array_t *pn5180_14443_get_all_uids_ex(pn5180_proto_t *proto, pn5180_poll_status_t *status)
{
    pn5180_poll_status_t local_status = PN5180_POLL_INVALID_ARGUMENT;
    pn5180_uids_array_t *uids         = NULL;
    if (proto != NULL && proto->pn5180 != NULL) {
        uids = pn5180_14443_poll(proto->pn5180, &local_status);
    }
    if (status != NULL) {
        *status = local_status;
    }
    return uids;
}

// Brings the card back to the selected state after a command left it in IDLE or HALT.
// Ultralight family cards reset to IDLE after every NAK, and after an abandoned authentication.
static bool pn5180_14443_reselect(pn5180_t *pn5180, pn5180_uid_t *uid)
{
    pn5180_mifare_halt(pn5180);
    return pn5180_14443_select_by_uid(pn5180, uid);
}

/*
    Tells the Ultralight family members apart. Returns true if the card has to be selected again
    afterwards, which is always the case: GET_VERSION is followed by a halt, and the probes that
    fail leave the card in IDLE.
*/
static bool pn5180_14443_detect_ultralight_variant(pn5180_t *pn5180, pn5180_uid_t *uid, pn5180_card_type_t *subtype, int *blocks_count)
{
    uint8_t response[10];
    uint8_t get_version_cmd = 0x60;

    // Set defaults
    *subtype      = PN5180_MIFARE_ULTRALIGHT;
    *blocks_count = 16;

    // Attempt GET_VERSION command via RF transmission
    pn5180_enable_crc(pn5180);

    PN5180_LOGD(TAG, "Sending GET_VERSION: 0x%02X", get_version_cmd);
    size_t             rx_len = 0;
    pn5180_rf_result_t result = pn5180_rf_transceive(pn5180, &get_version_cmd, 1, 0, response, sizeof(response), &rx_len, PN5180_TIMEOUT_MIFARE_READ_US, NULL);
    if (result != PN5180_RF_OK || rx_len < 8) {
        // No GET_VERSION: an original Ultralight or an Ultralight C. They share ATQA and SAK; only the
        // Ultralight C answers AUTHENTICATE (1Ah) with AFh and an 8-byte challenge. The failed GET_VERSION
        // has reset the card to IDLE, so it is selected again first.
        PN5180_LOGD(TAG, "GET_VERSION failed (result=%d, rx_len=%u)", (int)result, (unsigned)rx_len);
        pn5180_disable_crc(pn5180);
        if (!pn5180_14443_reselect(pn5180, uid)) {
            PN5180_LOGD(TAG, "Reselect after GET_VERSION failed - assuming standard Ultralight");
            return true;
        }
        const uint8_t auth_cmd[2] = {0x1A, 0x00};
        pn5180_enable_crc(pn5180);
        result = pn5180_rf_transceive(pn5180, auth_cmd, sizeof(auth_cmd), 0, response, sizeof(response), &rx_len, PN5180_TIMEOUT_MIFARE_READ_US, NULL);
        pn5180_disable_crc(pn5180);
        if (result == PN5180_RF_OK && rx_len == 9 && response[0] == 0xAF) {
            PN5180_LOGD(TAG, "Detected MIFARE Ultralight C");
            *subtype = PN5180_MIFARE_ULTRALIGHT_C;
            // 48 pages, of which READ addresses 00h..2Bh; the key pages 2Ch..2Fh cannot be read.
            *blocks_count = 44;
        } else {
            PN5180_LOGD(TAG, "No Ultralight C challenge (result=%d) - assuming standard Ultralight", (int)result);
        }
        // The authentication is not completed, so the card drops out of the selected state. Halting it
        // here leaves every path of this function in the same state: the caller selects the card again.
        pn5180_mifare_halt(pn5180);
        return true;
    }
    pn5180_disable_crc(pn5180);

    // GET_VERSION response: header, vendor, product type, subtype, major, minor, storage size, protocol
    uint8_t product_type = response[2];
    uint8_t storage_size = response[6];
    bool    is_ntag      = (product_type == 0x04);

    switch (storage_size) {
    case 0x0B: // 48 bytes user memory, 20 pages: Ultralight EV1 MF0UL11 or NTAG210
        *subtype      = is_ntag ? PN5180_MIFARE_NTAG210 : PN5180_MIFARE_ULTRALIGHT_EV1;
        *blocks_count = 20;
        break;
    case 0x0E: // 128 bytes user memory, 41 pages: Ultralight EV1 MF0UL21 or NTAG212
        *subtype      = is_ntag ? PN5180_MIFARE_NTAG212 : PN5180_MIFARE_ULTRALIGHT_EV1;
        *blocks_count = 41;
        break;
    case 0x0F: // NTAG213, 45 pages
        *subtype      = PN5180_MIFARE_NTAG213;
        *blocks_count = 45;
        break;
    case 0x11: // NTAG215, 135 pages
        *subtype      = PN5180_MIFARE_NTAG215;
        *blocks_count = 135;
        break;
    case 0x13: // NTAG216, 231 pages
        *subtype      = PN5180_MIFARE_NTAG216;
        *blocks_count = 231;
        break;
    default:
        PN5180_LOGD(TAG, "Unknown GET_VERSION storage size: 0x%02X - assuming standard Ultralight", storage_size);
        *subtype      = PN5180_MIFARE_ULTRALIGHT;
        *blocks_count = 16;
        break;
    }
    PN5180_LOGD(TAG, "GET_VERSION: product type 0x%02X, storage 0x%02X, %d pages", product_type, storage_size, *blocks_count);
    pn5180_mifare_halt(pn5180);
    return true;
}

static bool pn5180_14443_send_rats(pn5180_t *pn5180)
{
    // FSDI=8 (the reader accepts frames of up to 256 bytes), CID=0
    uint8_t rats_cmd[2] = {0xE0, 0x80};

    PN5180_LOGD(TAG, "Sending RATS");
    pn5180_enable_crc(pn5180); // ATS has CRC

    uint8_t            ats[256];
    size_t             rx_len = 0;
    pn5180_rf_result_t result = pn5180_rf_transceive(pn5180, rats_cmd, 2, 0, ats, sizeof(ats), &rx_len, PN5180_TIMEOUT_14443A_RATS_US, NULL);
    if (result != PN5180_RF_OK) {
        ESP_LOGE(TAG, "RATS failed (result=%d)", (int)result);
        return false;
    }
    if (rx_len == 0) {
        return false;
    }
    PN5180_LOGD(TAG, "Received ATS (%u bytes)", (unsigned)rx_len);
    uint8_t sfgi = 0;
    if (!pn5180_iso14443_4_apply_ats(pn5180, ats, (uint16_t)rx_len, &sfgi)) {
        return false;
    }
    if (sfgi > 0) {
        // Start-up frame guard time: the card needs (256 * 16 / fc) * 2^SFGI, about 302 us * 2^SFGI,
        // after its ATS before it can take the first block.
        pn5180_delay_us((uint32_t)302 << sfgi);
    }
    pn5180->iso14443_block_number = 0;
    return true;
}

// Activates ISO14443-4 on the selected card: RATS, with retries.
static bool pn5180_14443_4_activate(pn5180_t *pn5180)
{
    if (pn5180->iso14443_layer4_active) {
        return true;
    }
    for (int attempt = 0; attempt < 3; attempt++) {
        if (pn5180_14443_send_rats(pn5180)) {
            pn5180->iso14443_layer4_active = true;
            return true;
        }
        pn5180_delay_ms(5);
    }
    ESP_LOGE(TAG, "RATS failed after retries");
    return false;
}

#define ISO_DEP_PCB_I_BLOCK    0x02 // I-block; bit 0 is the block number, bit 4 the chaining flag
#define ISO_DEP_PCB_CHAINING   0x10
#define ISO_DEP_PCB_R_ACK      0xA2 // R(ACK); bit 0 is the block number
#define ISO_DEP_PCB_R_NAK      0xB2 // R(NAK); bit 0 is the block number
#define ISO_DEP_PCB_S_WTX      0xF2
#define ISO_DEP_PCB_S_DESELECT 0xC2
#define ISO_DEP_MAX_RETRIES    3
// Longest frame waiting time ISO14443-4 allows (FWI 14); a waiting time extension cannot go beyond it.
#define ISO_DEP_FWT_MAX_MS 4949
// Waiting time extensions accepted in a row for one block. The standard sets no limit, but a card that
// keeps asking must not hold the caller forever; a legitimate card needs a few at most.
#define ISO_DEP_MAX_WTX 10
// The PN5180 transmit buffer holds 260 bytes, the receive buffer below 260: keep blocks within 256 bytes.
#define ISO_DEP_MAX_INF 253

// State of one command/response exchange
typedef struct
{
    const uint8_t *apdu;
    size_t         apdu_len;
    size_t         max_inf;
    size_t         tx_offset;                    // start of the APDU part carried by i_block
    size_t         tx_chunk;                     // length of that part
    bool           tx_chaining;                  // i_block is not the last block of the command
    uint8_t        i_block[1 + ISO_DEP_MAX_INF]; // the I-block being sent, kept for retransmission
    size_t         i_block_len;
} iso_dep_tx_t;

// Builds the I-block that carries the APDU part starting at tx_offset.
static void pn5180_iso_dep_build_i_block(pn5180_t *pn5180, iso_dep_tx_t *tx)
{
    tx->tx_chunk    = tx->apdu_len - tx->tx_offset;
    tx->tx_chaining = tx->tx_chunk > tx->max_inf;
    if (tx->tx_chaining) {
        tx->tx_chunk = tx->max_inf;
    }
    tx->i_block[0] = (uint8_t)(ISO_DEP_PCB_I_BLOCK | (pn5180->iso14443_block_number & 0x01) | (tx->tx_chaining ? ISO_DEP_PCB_CHAINING : 0));
    memcpy(&tx->i_block[1], &tx->apdu[tx->tx_offset], tx->tx_chunk);
    tx->i_block_len = 1 + tx->tx_chunk;
}

// Releases an ISO14443-4 card with S(DESELECT), which the card answers with S(DESELECT) before it halts.
static bool pn5180_14443_4_deselect(pn5180_t *pn5180)
{
    uint8_t deselect = ISO_DEP_PCB_S_DESELECT;
    uint8_t answer[4];
    size_t  answer_len = 0;
    pn5180_enable_crc(pn5180);
    pn5180_rf_result_t result = pn5180_rf_transceive(pn5180, &deselect, 1, 0, answer, sizeof(answer), &answer_len, PN5180_TIMEOUT_14443A_RATS_US, NULL);
    return result == PN5180_RF_OK && answer_len >= 1 && answer[0] == ISO_DEP_PCB_S_DESELECT;
}

bool pn5180_14443_4_transceive(pn5180_t *pn5180, const uint8_t *apdu, size_t apdu_len, uint8_t *rx, size_t *rx_len)
{
    if (pn5180 == NULL || apdu == NULL || apdu_len == 0 || rx == NULL || rx_len == NULL || *rx_len == 0) {
        return false;
    }
    if (!pn5180->iso14443_layer4_active) {
        ESP_LOGE(TAG, "ISO14443-4 is not active: select an ISO14443-4 card first");
        return false;
    }

    size_t rx_capacity = *rx_len;
    *rx_len            = 0;

    iso_dep_tx_t *tx = calloc(1, sizeof(iso_dep_tx_t));
    if (tx == NULL) {
        return false;
    }
    tx->apdu     = apdu;
    tx->apdu_len = apdu_len;
    // Largest INF field the card accepts: FSC minus PCB and CRC (iso14443_frame_size is FSC without CRC).
    tx->max_inf = (pn5180->iso14443_frame_size > 1) ? (size_t)(pn5180->iso14443_frame_size - 1) : 13;
    if (tx->max_inf > ISO_DEP_MAX_INF) {
        tx->max_inf = ISO_DEP_MAX_INF;
    }

    pn5180_enable_crc(pn5180);

    uint8_t ctrl_block[2]; // R- or S-block being sent
    uint8_t rx_buf[260];

    int64_t fwt_ms        = pn5180->iso14443_fwt_ms > 0 ? pn5180->iso14443_fwt_ms : pn5180->timeout_ms;
    int64_t timeout_ms    = fwt_ms;
    bool    rx_chaining   = false; // the card is sending a chained response
    size_t  total_payload = 0;
    int     retries       = 0;
    int     wtx_count     = 0;
    bool    ok            = false;
    bool    fatal         = false;

    pn5180_iso_dep_build_i_block(pn5180, tx);
    const uint8_t *next_tx     = tx->i_block;
    size_t         next_tx_len = tx->i_block_len;

    while (true) {
        uint16_t    received = 0;
        rx_result_t rx_rc    = pn5180_iso14443_4_exchange_frame(pn5180, "ISO-DEP", next_tx, next_tx_len, timeout_ms, rx_buf, sizeof(rx_buf), &received);
        timeout_ms           = fwt_ms; // a waiting time extension covers one block only

        if (rx_rc == RX_RESULT_FATAL) {
            fatal = true;
            break;
        }

        if (rx_rc == RX_RESULT_TIMEOUT || rx_rc == RX_RESULT_PROTOCOL_ERROR) {
            if (++retries > ISO_DEP_MAX_RETRIES) {
                ESP_LOGE(TAG, "ISO-DEP exchange failed after %d retries", ISO_DEP_MAX_RETRIES);
                break;
            }
            // ISO14443-4 rules 4 and 5: ask with R(NAK) for the last block again; while the card is
            // chaining, R(ACK) does that.
            PN5180_LOGD(TAG, "ISO-DEP receive error (rc=%d), attempt %d", (int)rx_rc, retries);
            ctrl_block[0] = (uint8_t)((rx_chaining ? ISO_DEP_PCB_R_ACK : ISO_DEP_PCB_R_NAK) | (pn5180->iso14443_block_number & 0x01));
            next_tx       = ctrl_block;
            next_tx_len   = 1;
            continue;
        }

        uint8_t rx_pcb = rx_buf[0];

        // Blocks with CID or NAD are not for this exchange (neither was negotiated), and the fixed bits of
        // I- and R-blocks must be right: anything else is an invalid block, handled like a damaged one.
        bool is_i_block    = (rx_pcb & 0xC0) == 0x00;
        bool is_r_block    = (rx_pcb & 0xC0) == 0x80;
        bool is_s_block    = (rx_pcb & 0xC0) == 0xC0;
        bool invalid_block = (is_i_block && (rx_pcb & 0x2E) != 0x02) || (is_r_block && (rx_pcb & 0x2E) != 0x22) || (is_s_block && (rx_pcb & 0x08) != 0) ||
                             (rx_pcb & 0xC0) == 0x40;
        if (invalid_block) {
            if (++retries > ISO_DEP_MAX_RETRIES) {
                ESP_LOGE(TAG, "ISO-DEP exchange failed: invalid block 0x%02X", rx_pcb);
                break;
            }
            ctrl_block[0] = (uint8_t)((rx_chaining ? ISO_DEP_PCB_R_ACK : ISO_DEP_PCB_R_NAK) | (pn5180->iso14443_block_number & 0x01));
            next_tx       = ctrl_block;
            next_tx_len   = 1;
            continue;
        }
        if (rx_pcb != ISO_DEP_PCB_S_WTX) {
            wtx_count = 0;
        }

        if ((rx_pcb & 0xC0) == 0x00) { // I-block
            if (tx->tx_chaining) {
                ESP_LOGE(TAG, "ISO-DEP: I-block received while the command is still being chained");
                break;
            }
            if ((rx_pcb & 0x01) != (pn5180->iso14443_block_number & 0x01)) {
                ESP_LOGE(TAG, "Unexpected I-Block number: got=%u expected=%u", rx_pcb & 0x01, pn5180->iso14443_block_number & 0x01);
                break;
            }

            size_t payload_len = (size_t)received - 1;
            if ((total_payload + payload_len) > rx_capacity) {
                ESP_LOGE(TAG, "Layer 4 response too large: %zu > %zu", total_payload + payload_len, rx_capacity);
                break;
            }
            if (payload_len == 0 && (rx_pcb & ISO_DEP_PCB_CHAINING) != 0) {
                // A chained block without data makes no progress; a card that keeps sending them
                // would keep this loop running, since only the buffer size bounds a chain.
                ESP_LOGE(TAG, "ISO-DEP: chained I-block without data");
                break;
            }
            memcpy(&rx[total_payload], &rx_buf[1], payload_len);
            total_payload += payload_len;
            pn5180->iso14443_block_number ^= 0x01;
            retries = 0;

            if ((rx_pcb & ISO_DEP_PCB_CHAINING) != 0) {
                // Chained response: acknowledge to get the next part
                rx_chaining   = true;
                ctrl_block[0] = (uint8_t)(ISO_DEP_PCB_R_ACK | (pn5180->iso14443_block_number & 0x01));
                next_tx       = ctrl_block;
                next_tx_len   = 1;
                continue;
            }

            *rx_len = total_payload;
            ok      = true;
            break;
        }

        if ((rx_pcb & 0xC0) == 0x80) { // R-block
            if ((rx_pcb & 0x10) != 0 || rx_chaining) {
                // A card never sends R(NAK), and answers our R(ACK) with an I-block.
                ESP_LOGE(TAG, "ISO-DEP: unexpected R-block 0x%02X", rx_pcb);
                break;
            }
            if ((rx_pcb & 0x01) == (pn5180->iso14443_block_number & 0x01)) {
                // The card acknowledges the I-block just sent: continue the command chain.
                if (!tx->tx_chaining) {
                    ESP_LOGE(TAG, "ISO-DEP: R(ACK) for an unchained block");
                    break;
                }
                pn5180->iso14443_block_number ^= 0x01;
                tx->tx_offset += tx->tx_chunk;
                retries = 0;
                pn5180_iso_dep_build_i_block(pn5180, tx);
                next_tx     = tx->i_block;
                next_tx_len = tx->i_block_len;
                continue;
            }
            // R(ACK) with the other block number: the card did not get the last I-block (rule 6).
            if (++retries > ISO_DEP_MAX_RETRIES) {
                ESP_LOGE(TAG, "ISO-DEP exchange failed after %d retries", ISO_DEP_MAX_RETRIES);
                break;
            }
            PN5180_LOGD(TAG, "ISO-DEP: retransmitting I-block, attempt %d", retries);
            next_tx     = tx->i_block;
            next_tx_len = tx->i_block_len;
            continue;
        }

        // S-block
        if (rx_pcb == ISO_DEP_PCB_S_WTX) {
            uint8_t wtxm = (received >= 2) ? (uint8_t)(rx_buf[1] & 0x3F) : 0;
            if (wtxm == 0 || wtxm > 59) {
                ESP_LOGE(TAG, "Invalid WTX frame received");
                break;
            }
            if (++wtx_count > ISO_DEP_MAX_WTX) {
                ESP_LOGE(TAG, "ISO-DEP: card asked for more time %d times in a row, giving up", wtx_count);
                break;
            }
            ctrl_block[0] = ISO_DEP_PCB_S_WTX;
            ctrl_block[1] = wtxm;
            next_tx       = ctrl_block;
            next_tx_len   = 2;
            timeout_ms    = fwt_ms * wtxm;
            if (timeout_ms > ISO_DEP_FWT_MAX_MS) {
                // Never below the plain frame waiting time, which rounding puts a little above the cap for FWI 14
                timeout_ms = (fwt_ms > ISO_DEP_FWT_MAX_MS) ? fwt_ms : ISO_DEP_FWT_MAX_MS;
            }
            continue;
        }
        ESP_LOGE(TAG, "Unsupported ISO14443-4 block 0x%02X", rx_pcb);
        break;
    }

    free(tx);
    if (!ok) {
        // An exchange that was given up leaves reader and card out of step: block numbers no longer match,
        // or the card still waits for an answer. The session cannot be continued, so it is closed here.
        // The card is told with S(DESELECT) where possible (it then halts); if that does not get through,
        // only switching the field off brings the card back.
        if (!fatal) {
            pn5180_14443_4_deselect(pn5180);
        }
        pn5180_disable_crc(pn5180);
        pn5180_set_transceiver_idle(pn5180);
        pn5180_iso14443_4_reset_state(pn5180);
    }
    return ok;
}

static bool pn5180_14443_4_select(pn5180_t *pn5180, uint8_t p1, uint8_t p2, const uint8_t *file_id, size_t file_id_len, bool *card_refused)
{
    uint8_t apdu[5 + 16];
    apdu[0] = 0x00;                 // CLA
    apdu[1] = 0xA4;                 // INS = SELECT
    apdu[2] = p1;                   // P1
    apdu[3] = p2;                   // P2
    apdu[4] = (uint8_t)file_id_len; // Lc
    memcpy(&apdu[5], file_id, file_id_len);

    *card_refused = false;

    uint8_t rx[260];
    size_t  rx_len = sizeof(rx);
    if (!pn5180_14443_4_transceive(pn5180, apdu, 5u + file_id_len, rx, &rx_len)) {
        return false;
    }

    pn5180_apdu_response_t response;
    if (pn5180_apdu_parse_response(rx, rx_len, &response) != ESP_OK) {
        return false;
    }
    if (pn5180_apdu_get_status(&response) == PN5180_APDU_SW_SUCCESS) {
        return true;
    }
    PN5180_LOGD(TAG, "SELECT P1=%02X P2=%02X failed SW=%02X%02X", p1, p2, response.sw1, response.sw2);
    *card_refused = true;
    return false;
}

bool pn5180_14443_4_select_file(pn5180_t *pn5180, const uint8_t *file_id, size_t file_id_len)
{
    if (pn5180 == NULL || file_id == NULL || file_id_len == 0 || file_id_len > 16) {
        return false;
    }

    bool card_refused = false;
    if (file_id_len > 2) {
        // By AID: first or only occurrence, FCI optional.
        return pn5180_14443_4_select(pn5180, 0x04, 0x00, file_id, file_id_len, &card_refused);
    }

    // By file identifier. NFC Forum Type 4 Tag mapping 2.0 mandates P2=0x0C (no response data);
    // mapping 1.0 cards expect P2=0x00, so that is tried once when the card itself refuses the first form.
    if (pn5180_14443_4_select(pn5180, 0x00, 0x0C, file_id, file_id_len, &card_refused)) {
        return true;
    }
    return card_refused && pn5180_14443_4_select(pn5180, 0x00, 0x00, file_id, file_id_len, &card_refused);
}

bool pn5180_14443_4_read_binary(pn5180_t *pn5180, uint16_t offset, uint8_t le, uint8_t *buffer, size_t *got)
{
    if (pn5180 == NULL || buffer == NULL || got == NULL) {
        return false;
    }
    // P1/P2 carry a 15-bit offset (bit 8 of P1 must stay 0, ISO 7816-4). Reject instead of wrapping.
    if (offset > 0x7FFFu) {
        ESP_LOGE(TAG, "READ BINARY offset 0x%04X exceeds the 0x7FFF limit", offset);
        return false;
    }

    uint8_t apdu[5];
    apdu[0] = 0x00;                            // CLA
    apdu[1] = 0xB0;                            // INS = READ BINARY
    apdu[2] = (uint8_t)((offset >> 8) & 0x7F); // P1: offset high byte
    apdu[3] = (uint8_t)(offset & 0xFF);        // P2: offset low byte
    apdu[4] = le;                              // Le

    uint8_t rx[260];
    size_t  rx_len = sizeof(rx);
    if (!pn5180_14443_4_transceive(pn5180, apdu, sizeof(apdu), rx, &rx_len)) {
        return false;
    }

    pn5180_apdu_response_t response;
    if (pn5180_apdu_parse_response(rx, rx_len, &response) != ESP_OK) {
        return false;
    }
    if (pn5180_apdu_get_status(&response) != PN5180_APDU_SW_SUCCESS) {
        PN5180_LOGD(TAG, "READ BINARY @0x%04X len=%u SW=%02X%02X", offset, le, response.sw1, response.sw2);
        return false;
    }

    if (response.data_len > *got) {
        // Report the required size instead of silently truncating.
        ESP_LOGE(TAG, "READ BINARY @0x%04X: %u bytes arrived, buffer holds %u", offset, (unsigned)response.data_len, (unsigned)*got);
        *got = response.data_len;
        return false;
    }
    memcpy(buffer, response.data, response.data_len);
    *got = response.data_len;
    return true;
}

static bool _pn5180_14443_detect_card_type_and_capacity( //
    pn5180_t     *pn5180,                                //
    pn5180_uid_t *uid,                                   //
    int          *blocks_count,                          //
    int          *block_size                             //
)
{
    bool need_reselection = false;
    // Determine card type from SAK
    uint8_t card_type = uid->sak & 0x7F;
    switch (card_type) {
    case 0x00: // MIFARE Ultralight or Ultralight C
        uid->subtype  = PN5180_MIFARE_ULTRALIGHT;
        *blocks_count = 16;
        *block_size   = 4;
        // GET_VERSION can change card state; caller may need to reselect afterwards.
        need_reselection = pn5180_14443_detect_ultralight_variant(pn5180, uid, &uid->subtype, blocks_count);
        break;
    case 0x08:
        PN5180_LOGD(TAG, "Detected MIFARE Classic 1K");
        uid->subtype  = PN5180_MIFARE_CLASSIC_1K;
        *blocks_count = 64; // 16 sectors * 4 blocks
        *block_size   = 16;
        break;
    case 0x09: // MIFARE Mini
        PN5180_LOGD(TAG, "Detected MIFARE Classic Mini");
        uid->subtype  = PN5180_MIFARE_CLASSIC_MINI;
        *blocks_count = 20; // 5 sectors * 4 blocks
        *block_size   = 16;
        break;
    case 0x10: // MIFARE Plus 2K in security level 2 (AN10833)
        PN5180_LOGD(TAG, "Detected MIFARE Plus 2K");
        uid->subtype  = PN5180_MIFARE_PLUS_2K;
        *blocks_count = 128; // 32 sectors * 4 blocks
        *block_size   = 16;
        break;
    case 0x11: // MIFARE Plus 4K in security level 2 (AN10833)
        PN5180_LOGD(TAG, "Detected MIFARE Plus 4K");
        uid->subtype  = PN5180_MIFARE_PLUS_4K;
        *blocks_count = 256; // 32 sectors * 4 blocks + 8 sectors * 16 blocks
        *block_size   = 16;
        break;
    case 0x18:
        PN5180_LOGD(TAG, "Detected MIFARE Classic 4K");
        uid->subtype  = PN5180_MIFARE_CLASSIC_4K;
        *blocks_count = 256; // 32 sectors * 4 blocks + 8 sectors * 16 blocks
        *block_size   = 16;
        break;
    case 0x20: // ISO 14443-4 (DESFire family)
        PN5180_LOGD(TAG, "Detected MIFARE DESFire (ISO 14443-4)");
        uid->subtype  = PN5180_MIFARE_DESFIRE;
        *block_size   = 1;
        *blocks_count = 0;
        break;
    case 0x28:
        PN5180_LOGD(TAG, "Detected MIFARE Classic 1K emulation on an ISO 14443-4 card");
        uid->subtype  = PN5180_MIFARE_CLASSIC_1K; // Emulated 1K
        *blocks_count = 64;
        *block_size   = 16;
        break;
    case 0x38:
        PN5180_LOGD(TAG, "Detected MIFARE Classic 4K emulation on an ISO 14443-4 card");
        uid->subtype  = PN5180_MIFARE_CLASSIC_4K; // Emulated 4K
        *blocks_count = 256;
        *block_size   = 16;
        break;
    default:
        if (uid->sak & 0x20) {
            // SAK bit 6: ISO 14443-4 compliant, whatever the other bits say (e.g. 0x60 with NFC-DEP)
            PN5180_LOGD(TAG, "Detected ISO 14443-4 card (SAK: 0x%02X)", uid->sak);
            uid->subtype  = PN5180_MIFARE_DESFIRE;
            *block_size   = 1;
            *blocks_count = 0;
        } else {
            PN5180_LOGD(TAG, "Unknown or unsupported MIFARE type (SAK: 0x%02X)", uid->sak);
            uid->subtype  = PN5180_MIFARE_UNKNOWN;
            *blocks_count = 0;
            *block_size   = 0;
        }
        break;
    }
    uid->blocks_count = *blocks_count;
    uid->block_size   = *block_size;

    // Update global state for Read dispatcher
    pn5180->iso14443_current_card_type = uid->subtype;

    return need_reselection;
}

static bool pn5180_14443_select_by_uid( //
    pn5180_t     *pn5180,               //
    pn5180_uid_t *uid                   //
)
{
    uint8_t current_level = 1;
    uint8_t uid_offset    = 0;
    uint8_t sak           = 0;
    uint8_t level_data[5]; // 4 data bytes + 1 BCC
    uint8_t atqa[2] = {0, 0};

    // Reset Layer 4 state for new selection
    pn5180_iso14443_4_reset_state(pn5180);

    prepare_14443A_activation(pn5180);
    if (!pn5180_14443_send_wupa(pn5180, atqa)) {
        ESP_LOGE(TAG, "No card in field for direct selection");
        pn5180_clear_all_irqs(pn5180);
        return false;
    }

    while (current_level <= 3) {
        // Validate we have enough UID bytes remaining
        if (uid_offset >= uid->uid_length) {
            ESP_LOGE(TAG, "UID offset %d exceeds UID length %d at level %d", uid_offset, uid->uid_length, current_level);
            pn5180_clear_all_irqs(pn5180);
            return false;
        }

        // Construct the 4-byte UID segment for this level
        if (uid->uid_length > 4 && current_level < 3 && (uid->uid_length - uid_offset) > 4) {
            // For 7 or 10 byte UIDs, we need the Cascade Tag (0x88)
            level_data[0] = 0x88;
            memcpy(&level_data[1], &uid->uid[uid_offset], 3);
            uid_offset += 3;
        } else {
            // Final segment (or 4-byte UID)
            uint8_t remaining = uid->uid_length - uid_offset;
            if (remaining < 4) {
                ESP_LOGE(TAG, "Insufficient UID bytes at level %d: need 4, have %d", current_level, remaining);
                pn5180_clear_all_irqs(pn5180);
                return false;
            }
            memcpy(level_data, &uid->uid[uid_offset], 4);
            uid_offset += 4;
        }

        // Calculate BCC for this level's segment
        level_data[4] = level_data[0] ^ level_data[1] ^ level_data[2] ^ level_data[3];

        // 2. Perform Selection (NVB = 0x70)
        if (!pn5180_14443_send_select(pn5180, current_level, level_data, &sak)) {
            ESP_LOGE(TAG, "Direct Select failed at Level %d", current_level);
            pn5180_clear_all_irqs(pn5180);
            return false;
        }

        // 3. Check if UID is complete
        if (!(sak & 0x04)) {
            ESP_LOGI(TAG, "Card successfully selected via direct path!");
            // Determine card type and capacity from SAK
            if (uid->sak != sak) {
                uid->sak = sak;
            }
            uid->atqa[0] = atqa[0];
            uid->atqa[1] = atqa[1];
            // SAK bit 6: the card supports ISO14443-4. A card that also emulates MIFARE Classic
            // (SAK 0x28 / 0x38) accepts MIFARE commands only while it stays on ISO14443-3, so it is
            // activated as ISO14443-4 only when the caller asks for it by setting the subtype to
            // PN5180_MIFARE_DESFIRE before selecting.
            bool classic_emulation = (sak & 0x08) != 0 && uid->subtype != PN5180_MIFARE_DESFIRE;
            if ((sak & 0x20) != 0 && !classic_emulation) {
                PN5180_LOGD(TAG, "Card supports ISO 14443-4, activating Layer 4...");
                if (!pn5180_14443_4_activate(pn5180)) {
                    return false;
                }
                pn5180->iso14443_current_card_type = PN5180_MIFARE_DESFIRE;
            } else if (pn5180->iso14443_current_card_type == PN5180_MIFARE_DESFIRE) {
                // block_read must not go through ISO14443-4 for this card
                pn5180->iso14443_current_card_type = uid->subtype;
            }

            return true;
        }
        current_level++;
    }
    return false;
}

static bool pn5180_mifare_halt(pn5180_t *pn5180)
{
    if (pn5180->iso14443_layer4_active) {
        if (pn5180_14443_4_deselect(pn5180)) {
            pn5180_disable_crc(pn5180);
            pn5180_set_transceiver_idle(pn5180);
            pn5180_iso14443_4_reset_state(pn5180);
            return true;
        }
        PN5180_LOGD(TAG, "S(DESELECT) not acknowledged, sending HLTA");
    }
    pn5180_enable_tx_crc(pn5180);
    pn5180_disable_rx_crc(pn5180);
    uint8_t cmd_buf[2];
    cmd_buf[0] = 0x50;
    cmd_buf[1] = 0x00;
    PN5180_LOGD(TAG, "Sending MIFARE Halt command");
    PN5180_LOGD(TAG, "HALT data: 0x%02X 0x%02X", cmd_buf[0], cmd_buf[1]);
    // HLTA has no response: the frame is done once the transmission has ended.
    pn5180_rf_result_t result = pn5180_rf_transceive(pn5180, cmd_buf, 2, 0, NULL, 0, NULL, 0, NULL);
    bool               ret    = (result == PN5180_RF_OK);
    if (!ret) {
        ESP_LOGE(TAG, "HLTA transmission failed (result=%d)", (int)result);
    }
    // The card needs about 1 ms to act on HLTA before the next command (the NXP reader library waits 1100 us).
    esp_rom_delay_us(1100);
    pn5180_disable_crc(pn5180);
    pn5180_set_transceiver_idle(pn5180);
    pn5180_write_register_and_mask(pn5180, PN5180_SYSTEM_CONFIG, PN5180_SYSTEM_CONFIG_CLEAR_CRYPTO_MASK);
    pn5180_iso14443_4_reset_state(pn5180);
    return ret;
}
