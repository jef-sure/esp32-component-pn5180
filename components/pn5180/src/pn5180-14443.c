#include "pn5180-14443.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "pn5180-internal.h"
#include "pn5180-mifare.h"
#include <string.h>

static const char *TAG = "pn5180-14443";

static nfc_uids_array_t *pn5180_14443_get_all_uids(pn5180_t *pn5180);

static bool pn5180_mifare_halt(pn5180_t *pn5180);

static bool pn5180_14443_select_by_uid(pn5180_t *pn5180, nfc_uid_t *uid);
static bool pn5180_14443_detect_ultralight_variant(pn5180_t *pn5180, nfc_type_t *subtype, int *blocks_count);
static void pn5180_14443_detect_desfire_capacity(pn5180_t *pn5180, int *blocks_count);
static bool pn5180_iso14443_4_transceive(pn5180_t *pn5180, const uint8_t *tx, size_t tx_len, uint8_t *rx, size_t *rx_len);
static bool pn5180_iso14443_4_select_file(pn5180_t *pn5180, const uint8_t *file_id, size_t file_id_len);
static bool pn5180_14443_setupRF(pn5180_t *pn5180);
static bool _pn5180_14443_detect_card_type_and_capacity( //
    pn5180_t  *pn5180,                                   //
    nfc_uid_t *uid,                                      //
    int       *blocks_count,                             //
    int       *block_size                                //
);

static bool _pn5180_14443_setupRF(pn5180_proto_t *proto)
{
    return pn5180_14443_setupRF(proto->pn5180);
}

static nfc_uids_array_t *_pn5180_14443_get_all_uids(pn5180_proto_t *proto)
{
    return pn5180_14443_get_all_uids(proto->pn5180);
}

static bool _pn5180_14443_select_by_uid(pn5180_proto_t *proto, nfc_uid_t *uid)
{
    return pn5180_14443_select_by_uid(proto->pn5180, uid);
}

// Helper to read blocks via ISO 14443-4 APDU (Read Binary)
static bool pn5180_iso14443_4_read_binary(pn5180_t *pn5180, int blockno, uint8_t *buffer, size_t buffer_len)
{
    if (buffer_len == 0 || buffer_len > 250) {
        // Keep Le safe (some cards dislike 256/00 on short APDU, or buffer is too big)
        return false;
    }

    uint8_t apdu[5];
    apdu[0] = 0x00;                  // CLA
    apdu[1] = 0xB0;                  // INS (Read Binary)
    apdu[2] = (blockno >> 8) & 0xFF; // P1
    apdu[3] = blockno & 0xFF;        // P2
    apdu[4] = (uint8_t)buffer_len;   // Le

    // We need a temp buffer because we receive Data + SW1SW2 (2 bytes)
    // and the caller provided buffer might be exactly buffer_len.
    uint8_t temp_rx[260];
    size_t  temp_len = sizeof(temp_rx);

    if (!pn5180_iso14443_4_transceive(pn5180, apdu, 5, temp_rx, &temp_len)) {
        ESP_LOGE(TAG, "ReadBinary transceive failed");
        return false;
    }

    // Check Response Status Word (SW1 SW2)
    if (temp_len < 2) return false;

    uint8_t sw1 = temp_rx[temp_len - 2];
    uint8_t sw2 = temp_rx[temp_len - 1];

    if (sw1 == 0x90 && sw2 == 0x00) {
        size_t data_len = temp_len - 2;
        // Verify we got what we asked for (or less if EOF)
        if (data_len > buffer_len) data_len = buffer_len;
        memcpy(buffer, temp_rx, data_len);
        // If we read less than expected, should we zero pad?
        // Standard block read usually implies full block.
        // But for file read, less is valid (EOF).
        return true;
    }

    ESP_LOGW(TAG, "ReadBinary failed: SW=%02X %02X", sw1, sw2);
    return false;
}

static bool _pn5180_14443_mifareBlockRead(pn5180_proto_t *proto, int blockno, uint8_t *buffer, size_t buffer_len)
{
    if (proto->pn5180->iso14443_current_card_type == PN5180_MIFARE_DESFIRE) {
        return pn5180_iso14443_4_read_binary(proto->pn5180, blockno, buffer, buffer_len);
    }
    return pn5180_mifare_block_read(proto->pn5180, blockno, buffer, buffer_len);
}

static int _pn5180_14443_mifareBlockWrite(pn5180_proto_t *proto, int blockno, const uint8_t *buffer, size_t buffer_len)
{
    return pn5180_mifare_block_write(proto->pn5180, blockno, buffer, buffer_len);
}

static bool _pn5180_14443_halt(pn5180_proto_t *proto)
{
    return pn5180_mifare_halt(proto->pn5180);
}

static bool _pn5180_14443_authenticate( //
    pn5180_proto_t  *proto,             //
    const uint8_t   *key,               //
    uint8_t          keyType,           //
    const nfc_uid_t *uid,               //
    int              blockno            //
)
{
    // MIFARE authentication for already selected card
    // subtype indicates card type (Classic 1K/4K, Plus, etc.)
    // keyType: 0x60 for Key A, 0x61 for Key B

    if (uid->subtype == PN5180_MIFARE_ULTRALIGHT || uid->subtype == PN5180_MIFARE_ULTRALIGHT_C || uid->subtype == PN5180_MIFARE_ULTRALIGHT_EV1 ||
        uid->subtype == PN5180_MIFARE_NTAG213 || uid->subtype == PN5180_MIFARE_NTAG215 || uid->subtype == PN5180_MIFARE_NTAG216) {
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

    PN5180_LOGD(TAG, "Authenticating: KeyType=0x%02X Block=%d Key=[%02X %02X %02X %02X %02X %02X] UID_Auth=[%02X %02X %02X %02X]", keyType, blockno, key[0],
                key[1], key[2], key[3], key[4], key[5], uid_for_auth[0], uid_for_auth[1], uid_for_auth[2], uid_for_auth[3]);

    // Send AUTH command immediately - DO NOT manipulate registers between SELECT and AUTH
    // The working reference implementation sends AUTH with no register touches
    int16_t auth_result = pn5180_mifareAuthenticate(proto->pn5180, (uint8_t)blockno, key, keyType, uid_for_auth);

    if (auth_result < 0) {
        ESP_LOGE(TAG, "MIFARE authentication error code %d", auth_result);
        return false;
    }

    // Check authentication status (0x00 = success)
    if (auth_result != 0x00) {
        ESP_LOGD(TAG, "MIFARE authentication rejected (status: 0x%02X)", auth_result);
        // On failed authentication, disable Crypto1 and reset to clean state
        pn5180_writeRegisterWithAndMask(proto->pn5180, SYSTEM_CONFIG,
                                        SYSTEM_CONFIG_CLEAR_CRYPTO_MASK); // Clear MFC_CRYPTO_ON
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
    pn5180->rf_config                    = 0x00; // ISO14443-A 106kbit/s
    proto->pn5180                        = pn5180;
    proto->setup_rf                      = _pn5180_14443_setupRF;
    proto->get_all_uids                  = _pn5180_14443_get_all_uids;
    proto->select_by_uid                 = _pn5180_14443_select_by_uid;
    proto->block_read                    = _pn5180_14443_mifareBlockRead;
    proto->block_write                   = _pn5180_14443_mifareBlockWrite;
    proto->authenticate                  = _pn5180_14443_authenticate;
    proto->detect_card_type_and_capacity = _pn5180_14443_detect_card_type_and_capacity;
    proto->halt                          = _pn5180_14443_halt;
    return proto;
}

static bool pn5180_14443_setupRF(pn5180_t *pn5180)
{
    if (pn5180->is_rf_on) {
        if (pn5180->tx_config == pn5180->rf_config) {
            return true;
        }
        pn5180_setRF_off(pn5180);
    }
    bool ret = pn5180_loadRFConfig(pn5180, pn5180->rf_config);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to load RF config for 14443A");
        return false;
    }
    ret = pn5180_setRF_on(pn5180);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to turn RF on for 14443A");
        return false;
    }
    return true;
}

static bool pn5180_14443_sendREQA(pn5180_t *pn5180, uint8_t *atqa)
{
    // REQA is a 7-bit command (0x26)
    uint8_t cmd_buf[1] = {0x26};

    // Clear MFC_CRYPTO_ON bit to ensure clean state for new card discovery
    pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_CLEAR_CRYPTO_MASK);
    pn5180_clearAllIRQs(pn5180);
    pn5180_disable_crc(pn5180);
    PN5180_LOGD(TAG, "Sending REQA: 0x%02X (7 bits)", cmd_buf[0]);
    if (!pn5180_sendData(pn5180, cmd_buf, 1, 7)) {
        ESP_LOGE(TAG, "Failed to send REQA command");
        return false;
    }

    // Wait for ATQA response (RX) or command completion (IDLE)
    uint32_t irqStatus = 0;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | IDLE_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "REQA ATQA", &irqStatus)) {
        PN5180_LOGD(TAG, "No response to REQA (no cards in IDLE state)");
        return false;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        pn5180_clearAllIRQs(pn5180);
        return false;
    }

    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen > 0) {
        if (!pn5180_readData(pn5180, rxLen, atqa)) {
            ESP_LOGE(TAG, "Failed to read ATQA from FIFO");
            return false;
        }
        PN5180_LOGD(TAG, "REQA Success, ATQA: 0x%02X%02X", atqa[0], atqa[1]);
    }
    pn5180_clearAllIRQs(pn5180);
    return (rxLen > 0);
}

static bool pn5180_14443_sendWUPA(pn5180_t *pn5180, uint8_t *atqa)
{
    // WUPA is a 7-bit command (0x52)
    uint8_t cmd_buf[1] = {0x52};

    // Clear MFC_CRYPTO_ON bit to ensure clean state
    // Don't manually set transceive state - let pn5180_sendData() handle it
    pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_CLEAR_CRYPTO_MASK);
    pn5180_clearAllIRQs(pn5180);
    pn5180_disable_crc(pn5180);
    PN5180_LOGD(TAG, "Sending WUPA: 0x%02X (7 bits)", cmd_buf[0]);
    if (!pn5180_sendData(pn5180, cmd_buf, 1, 7)) {
        ESP_LOGE(TAG, "Failed to send WUPA command");
        return false;
    }

    // Wait for ATQA response (RX) or command completion (IDLE)
    uint32_t irqStatus = 0;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | IDLE_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "WUPA ATQA", &irqStatus)) {
        PN5180_LOGD(TAG, "No response to WUPA");
        return false;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        pn5180_clearAllIRQs(pn5180);
        return false;
    }

    // Read ATQA (2 bytes)
    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen > 0) {
        if (!pn5180_readData(pn5180, rxLen, atqa)) {
            ESP_LOGE(TAG, "Failed to read ATQA from FIFO");
            return false;
        }
        PN5180_LOGD(TAG, "WUPA Success, ATQA: 0x%02X%02X", atqa[0], atqa[1]);
    }

    pn5180_clearAllIRQs(pn5180);
    return (rxLen > 0);
}

static bool prepare_14443A_activation(pn5180_t *pn5180)
{
    if (!pn5180_14443_setupRF(pn5180)) {
        ESP_LOGE(TAG, "Failed to setup RF for 14443A activation");
        return false;
    }

    // Full transceiver reset to clear both software and hardware Crypto1 state
    // This matches the working log initialization sequence:

    // 1. Clear MFC_CRYPTO_ON software bit (bit 6) only
    if (!pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_CLEAR_CRYPTO_MASK)) {
        ESP_LOGE(TAG, "Failed to clear MFC_CRYPTO_ON");
        return false;
    }

    // 2. Disable TX/RX CRC
    pn5180_disable_crc(pn5180);

    // 3. Force transceiver to IDLE state (clears bits [2:0])
    if (!pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_CLEAR_TX_MODE_MASK)) {
        ESP_LOGE(TAG, "Failed to set transceiver to IDLE");
        return false;
    }

    // 4. Set to Transceive state
    if (!pn5180_writeRegisterWithOrMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_TX_MODE_TRANSCEIVE)) {
        ESP_LOGE(TAG, "Failed to set Transceive state");
        return false;
    }

    // 5. Clear all IRQ flags
    pn5180_clearAllIRQs(pn5180);

    return true;
}

static bool pn5180_14443_sendSelect(pn5180_t *pn5180, int cascade_level, uint8_t *level_data, uint8_t *sak)
{
    pn5180_enable_crc(pn5180);
    uint8_t cmd_buf[7];
    cmd_buf[0] = 0x93 + ((cascade_level - 1) * 2); // 0x93, 0x95, 0x97 for cascade levels 1,2,3
    cmd_buf[1] = 0x70;                             // NVB = 0x70 (full 5 bytes)
    memcpy(&cmd_buf[2], level_data, 5);            // Copy UID CLn + BCC
    PN5180_LOGD(TAG, "Sending Select command %d", cascade_level);
    PN5180_LOGD(TAG, "SELECT data: %02X %02X %02X %02X %02X %02X %02X", cmd_buf[0], cmd_buf[1], cmd_buf[2], cmd_buf[3], cmd_buf[4], cmd_buf[5], cmd_buf[6]);
    if (!pn5180_sendData(pn5180, cmd_buf, 7, 0x00)) {
        pn5180_disable_crc(pn5180);
        ESP_LOGE(TAG, "Failed to send Select command %d", cascade_level);
        return false;
    }
    uint32_t irqStatus;
    bool     got_response = pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "Select response", &irqStatus);
    pn5180_clearAllIRQs(pn5180);
    if (!got_response) {
        pn5180_disable_crc(pn5180);
        ESP_LOGE(TAG, "Timeout waiting for Select response at level %d", cascade_level);
        return false;
    }
    // Check for Protocol/CRC errors
    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "General error during Select (possibly CRC mismatch)");
        pn5180_disable_crc(pn5180);
        return false;
    }
    uint32_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen != 1) {
        ESP_LOGE(TAG, "SAK frame error: expected 1 byte, got %d", rxLen);
        pn5180_disable_crc(pn5180);
        return false;
    }

    if (!pn5180_readData(pn5180, 1, sak)) {
        ESP_LOGE(TAG, "Failed to read SAK");
        pn5180_disable_crc(pn5180);
        return false;
    }
    return true;
}

// Helper function to resolve collisions in anticollision sequence
static bool pn5180_14443_resolve_collision(pn5180_t *pn5180, uint8_t cascadeLevel, uint8_t sel, uint8_t collisionPos, uint8_t rxLen, uint8_t *active_uid,
                                           uint8_t *temp_uid, uint8_t *uidLen)
{
    // Force the initial collision bit to 1 (choose the higher UID branch)
    uint8_t byte_idx = collisionPos / 8;
    uint8_t bit_idx  = collisionPos % 8;
    active_uid[byte_idx] |= (1 << bit_idx);

    uint8_t  known_bits         = collisionPos + 1;
    uint8_t  collision_attempts = 0;
    uint32_t irqStatus;
    uint8_t  cmd_buf[12];

    while (known_bits < 32 && collision_attempts < 64) {
        collision_attempts++;

        // Calculate NVB with +2 for SEL and NVB header bytes
        uint8_t bytes_count       = known_bits / 8;
        uint8_t bits_in_last_byte = known_bits % 8;
        uint8_t current_nvb       = ((bytes_count + 2) << 4) | bits_in_last_byte;

        PN5180_LOGD(TAG, "Collision retry %d: known_bits=%d, NVB=0x%02X", collision_attempts, known_bits, current_nvb);

        // Re-force the collision bit (may have been overwritten by new data reads)
        uint8_t forced_byte_idx = (known_bits - 1) / 8;
        uint8_t forced_bit_idx  = (known_bits - 1) % 8;
        active_uid[forced_byte_idx] |= (1 << forced_bit_idx);

        // Build command: SEL + NVB + known UID bits
        cmd_buf[0] = sel;
        cmd_buf[1] = current_nvb;

        if (bytes_count > 0) {
            memcpy(&cmd_buf[2], active_uid, bytes_count);
        }

        // Mask partial byte
        if (bits_in_last_byte > 0) {
            uint8_t mask             = (1 << bits_in_last_byte) - 1;
            cmd_buf[2 + bytes_count] = active_uid[bytes_count] & mask;
        }

        int cmd_len = 2 + bytes_count + (bits_in_last_byte > 0 ? 1 : 0);

        // Send anticollision command
        PN5180_LOGD(TAG, "Collision retry: sending %d bytes, %d bits in last byte", cmd_len, bits_in_last_byte);
        if (!pn5180_sendData(pn5180, cmd_buf, cmd_len, bits_in_last_byte)) {
            ESP_LOGE(TAG, "Failed to send anticollision retry at level %d", cascadeLevel);
            return false;
        }

        // Wait for response
        if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT | IDLE_IRQ_STAT, "collision retry", &irqStatus)) {
            ESP_LOGE(TAG, "Timeout in collision retry at level %d", cascadeLevel);
            return false;
        }

        // Check for collision
        if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
            uint32_t newRxStatus;
            if (!pn5180_readRegister(pn5180, RX_STATUS, &newRxStatus)) {
                ESP_LOGE(TAG, "Failed to read RX_STATUS in collision retry at level %d", cascadeLevel);
                pn5180_clearAllIRQs(pn5180);
                return false;
            }

            if (newRxStatus & (RX_COLLISION_DETECTED | RX_PROTOCOL_ERROR | RX_DATA_INTEGRITY_ERROR)) {
                // Still colliding - extract new position and retry
                uint8_t  newCollisionPos = (newRxStatus >> RX_COLL_POS_START) & RX_COLL_POS_MASK;
                uint16_t newRxLen        = pn5180_rxBytesReceived(pn5180);

                if (newRxLen > 0 && newRxLen <= 5) {
                    if (!pn5180_readData(pn5180, newRxLen, active_uid)) {
                        ESP_LOGE(TAG, "Failed to read partial UID in retry at level %d", cascadeLevel);
                        pn5180_clearAllIRQs(pn5180);
                        return false;
                    }
                }

                pn5180_clearAllIRQs(pn5180);

                // Force new collision bit and continue
                uint8_t new_byte_idx = newCollisionPos / 8;
                uint8_t new_bit_idx  = newCollisionPos % 8;
                active_uid[new_byte_idx] |= (1 << new_bit_idx);
                known_bits = newCollisionPos + 1;
                continue;
            }
        }

        // No collision - read complete response
        rxLen = pn5180_rxBytesReceived(pn5180);
        if (rxLen == 0 || rxLen > 10) {
            pn5180_clearAllIRQs(pn5180);
            ESP_LOGE(TAG, "Invalid response length %d after collision resolution", rxLen);
            return false;
        }

        if (!pn5180_readData(pn5180, rxLen, cmd_buf)) {
            pn5180_clearAllIRQs(pn5180);
            ESP_LOGE(TAG, "Failed to read UID+BCC after collision resolution at level %d", cascadeLevel);
            return false;
        }

        pn5180_clearAllIRQs(pn5180);

        // Validate BCC and return
        if (rxLen == 5) {
            uint8_t bcc = cmd_buf[0] ^ cmd_buf[1] ^ cmd_buf[2] ^ cmd_buf[3];
            if (bcc != cmd_buf[4]) {
                ESP_LOGE(TAG, "BCC check failed after resolution at level %d", cascadeLevel);
                return false;
            }
            *uidLen = 4;
            memcpy(temp_uid, cmd_buf, 5);
            return true;
        }
    }

    ESP_LOGE(TAG, "Failed to resolve collision at level %d after %d attempts", cascadeLevel, collision_attempts);
    return false;
}

static bool pn5180_14443_anticollision_level(pn5180_t *pn5180, uint8_t cascadeLevel, uint8_t temp_uid[5], uint8_t *uidLen)
{
    uint8_t sel = 0x93 + (2 * (cascadeLevel - 1));
    uint8_t nvb = 0x20;
    uint8_t cmd_buf[12];
    cmd_buf[0] = sel;
    cmd_buf[1] = nvb;

    PN5180_LOGD(TAG, "Sending Anti-collision command for cascade level %d", cascadeLevel);
    PN5180_LOGD(TAG, "Anti-collision: SEL=0x%02X NVB=0x%02X", sel, nvb);
    if (!pn5180_sendData(pn5180, cmd_buf, 2, 0)) {
        ESP_LOGE(TAG, "Failed to send Anti-collision command at level %d", cascadeLevel);
        return false;
    }

    // Wait for response
    uint32_t irqStatus;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | IDLE_IRQ_STAT, "anticollision response", &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for anticollision response at level %d", cascadeLevel);
        return false;
    }

    // Get response length
    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen == 0 || rxLen > 10) {
        pn5180_clearAllIRQs(pn5180);
        ESP_LOGE(TAG, "Invalid response length %d at level %d", rxLen, cascadeLevel);
        return false;
    }

    // Read response
    if (!pn5180_readData(pn5180, rxLen, cmd_buf)) {
        pn5180_clearAllIRQs(pn5180);
        ESP_LOGE(TAG, "Failed to read response at level %d", cascadeLevel);
        return false;
    }

    pn5180_clearAllIRQs(pn5180);

    // Check for collision
    if ((irqStatus & GENERAL_ERROR_IRQ_STAT) == 0) {
        // No collision - validate and return
        if (rxLen != 5) {
            PN5180_LOGD(TAG, "Unexpected response length %d at level %d (expected 5)", rxLen, cascadeLevel);
            return false;
        }

        uint8_t bcc = cmd_buf[0] ^ cmd_buf[1] ^ cmd_buf[2] ^ cmd_buf[3];
        if (bcc != cmd_buf[4]) {
            ESP_LOGE(TAG, "BCC check failed at level %d", cascadeLevel);
            return false;
        }

        *uidLen = 4;
        memcpy(temp_uid, cmd_buf, 5);
        return true;
    }

    // Collision detected - resolve it
    uint32_t rxStatus;
    if (!pn5180_readRegister(pn5180, RX_STATUS, &rxStatus) || 0 == (rxStatus & (RX_COLLISION_DETECTED | RX_PROTOCOL_ERROR | RX_DATA_INTEGRITY_ERROR))) {
        ESP_LOGE(TAG, "Failed to read RX_STATUS at level %d", cascadeLevel);
        return false;
    }

    uint8_t collisionPos = (rxStatus >> RX_COLL_POS_START) & RX_COLL_POS_MASK;
    PN5180_LOGD(TAG, "Collision at level %d, bit position %d", cascadeLevel, collisionPos);

    // Copy received partial UID
    uint8_t active_uid[5] = {0};
    if (rxLen > 0 && rxLen <= 5) {
        memcpy(active_uid, cmd_buf, rxLen);
    }

    // Resolve collision iteratively
    return pn5180_14443_resolve_collision(pn5180, cascadeLevel, sel, collisionPos, rxLen, active_uid, temp_uid, uidLen);
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
            PN5180_LOGD(TAG, "Anticollision failed at level %d", cascade_level);
            return false;
        }
        if (!pn5180_14443_sendSelect(pn5180, cascade_level, level_data, sak)) {
            ESP_LOGE(TAG, "Select command failed at level %d", cascade_level);
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

static nfc_uids_array_t *pn5180_14443_get_all_uids(pn5180_t *pn5180)
{
    nfc_uids_array_t *uids       = NULL;
    uint8_t           card_count = 0;
    bool              need_break = false;
    prepare_14443A_activation(pn5180);
    while (card_count < 14 && !need_break) {
        uint8_t atqa[2];
        if (!pn5180_14443_sendREQA(pn5180, atqa)) {
            ESP_LOGI(TAG, "No more cards found.");
            break;
        }

        uint8_t full_uid[12];
        int8_t  full_uid_len = 0;
        uint8_t sak;
        if (pn5180_14443_resolve_full_uid_cascade(pn5180, full_uid, &full_uid_len, &sak)) {
            ESP_LOGI(TAG, "Found Card %d: UID Len %d", ++card_count, full_uid_len);
            if (uids == NULL) {
                uids = calloc(1, sizeof(nfc_uids_array_t));
                if (uids == NULL) {
                    ESP_LOGE(TAG, "Memory allocation failed for UIDs");
                    need_break = true;
                } else {
                    uids->uids_count         = 1;
                    uids->uids[0].uid_length = full_uid_len;
                    uids->uids[0].sak        = sak;
                    uids->uids[0].agc        = 0;
                    uids->uids[0].subtype    = PN5180_MIFARE_UNKNOWN;
                    memcpy(uids->uids[0].uid, full_uid, full_uid_len);
                }
            } else {
                nfc_uids_array_t *new_uids = realloc(uids, sizeof(nfc_uids_array_t) + (uids->uids_count * sizeof(nfc_uid_t)));
                if (new_uids == NULL) {
                    ESP_LOGE(TAG, "Memory allocation failed for UIDs");
                    need_break = true;
                } else {
                    uids                                    = new_uids;
                    uids->uids[uids->uids_count].uid_length = full_uid_len;
                    uids->uids[uids->uids_count].sak        = sak;
                    uids->uids[uids->uids_count].agc        = 0;
                    uids->uids[uids->uids_count].subtype    = PN5180_MIFARE_UNKNOWN;
                    memcpy(uids->uids[uids->uids_count].uid, full_uid, full_uid_len);
                    uids->uids_count++;
                }
            }
            pn5180_mifare_halt(pn5180);
        } else {
            break;
        }
    }
    return uids;
}

/*
    Returns true if card required reselection
*/
static bool pn5180_14443_detect_ultralight_variant(pn5180_t *pn5180, nfc_type_t *subtype, int *blocks_count)
{
    uint8_t response[8];
    uint8_t get_version_cmd = 0x60;

    // Set defaults
    *subtype      = PN5180_MIFARE_ULTRALIGHT;
    *blocks_count = 16;

    // Attempt GET_VERSION command via RF transmission
    pn5180_enable_crc(pn5180);

    PN5180_LOGD(TAG, "Sending GET_VERSION: 0x%02X", get_version_cmd);
    if (!pn5180_sendData(pn5180, &get_version_cmd, 1, 0)) {
        PN5180_LOGD(TAG, "GET_VERSION send failed - assuming standard Ultralight");
        pn5180_disable_crc(pn5180);
        return true;
    }

    // Wait for card response
    uint32_t irqStatus;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "GET_VERSION", &irqStatus)) {
        PN5180_LOGD(TAG, "GET_VERSION timeout - assuming standard Ultralight");
        pn5180_clearAllIRQs(pn5180);
        pn5180_disable_crc(pn5180);
        return true;
    }

    // Check for errors
    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        PN5180_LOGD(TAG, "GET_VERSION general error - assuming standard Ultralight");
        pn5180_clearAllIRQs(pn5180);
        pn5180_disable_crc(pn5180);
        return true;
    }

    // Read response
    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen < 8 || !pn5180_readData(pn5180, 8, response)) {
        PN5180_LOGD(TAG, "GET_VERSION read failed (rxLen=%d) - assuming standard Ultralight", rxLen);
        pn5180_clearAllIRQs(pn5180);
        pn5180_disable_crc(pn5180);
        return true;
    }

    pn5180_clearAllIRQs(pn5180);
    pn5180_disable_crc(pn5180);

    // Extract and map storage size byte (response[6])
    uint8_t storage_size = response[6];

    switch (storage_size) {
    case 0x0B: // Ultralight EV1 48 bytes (20 pages)
        PN5180_LOGD(TAG, "Detected MIFARE Ultralight EV1 (48 bytes, 20 pages)");
        *subtype      = PN5180_MIFARE_ULTRALIGHT_EV1;
        *blocks_count = 20;
        break;
    case 0x0E: // Ultralight EV1 128 bytes (41 pages)
        PN5180_LOGD(TAG, "Detected MIFARE Ultralight EV1 (128 bytes, 41 pages)");
        *subtype      = PN5180_MIFARE_ULTRALIGHT_EV1;
        *blocks_count = 41;
        break;
    case 0x0F: // NTAG variant with ~142 bytes (45 pages)
        PN5180_LOGD(TAG, "Detected NTAG variant (storage_size=0x0F, ~142 bytes, 45 pages)");
        *subtype      = PN5180_MIFARE_NTAG213;
        *blocks_count = 45;
        break;
    case 0x11: // NTAG213 180 bytes total (45 pages)
        PN5180_LOGD(TAG, "Detected NTAG213 (180 bytes total, 45 pages)");
        *subtype      = PN5180_MIFARE_NTAG213;
        *blocks_count = 45;
        break;
    case 0x13: // NTAG215 540 bytes total (135 pages)
        PN5180_LOGD(TAG, "Detected NTAG215 (540 bytes total, 135 pages)");
        *subtype      = PN5180_MIFARE_NTAG215;
        *blocks_count = 135;
        break;
    case 0x15: // NTAG216 924 bytes total (231 pages)
        PN5180_LOGD(TAG, "Detected NTAG216 (924 bytes total, 231 pages)");
        *subtype      = PN5180_MIFARE_NTAG216;
        *blocks_count = 231;
        break;
    default:
        PN5180_LOGD(TAG, "Unknown GET_VERSION storage size: 0x%02X - assuming standard Ultralight", storage_size);
        *subtype      = PN5180_MIFARE_ULTRALIGHT;
        *blocks_count = 16;
        break;
    }
    pn5180_mifare_halt(pn5180);
    return true;
}

static bool pn5180_14443_sendRATS(pn5180_t *pn5180)
{
    // FSDI=5 (64 bytes), CID=0
    uint8_t rats_cmd[2] = {0xE0, 0x50};

    PN5180_LOGD(TAG, "Sending RATS");
    pn5180_enable_crc(pn5180); // ATS has CRC

    if (!pn5180_sendData(pn5180, rats_cmd, 2, 0)) {
        ESP_LOGE(TAG, "Failed to send RATS");
        return false;
    }

    uint32_t irqStatus = 0;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "RATS", &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for ATS");
        return false;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "RATS failed (Protocol Error?)");
        return false;
    }

    uint8_t  ats[64];
    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen > 0) {
        pn5180_readData(pn5180, rxLen, ats);
        PN5180_LOGD(TAG, "Received ATS (%d bytes)", rxLen);
        // We are now in ISO 14443-4 Layer 4
        pn5180->iso14443_block_number = 0;
        return true;
    }
    return false;
}

// Send RATS and optionally Select NDEF Application
// Returns true if RATS success
static bool pn5180_activate_layer4_ndef(pn5180_t *pn5180)
{
    // Use cached NDEF result if already checked in this session
    if (pn5180->iso14443_layer4_active && pn5180->iso14443_ndef_checked) {
        return pn5180->iso14443_ndef_detected;
    }

    // 1. Send RATS (only if not already active)
    if (!pn5180->iso14443_layer4_active) {
        uint8_t rats_retries = 3;
        bool    rats_ok      = false;
        while (rats_retries--) {
            if (pn5180_14443_sendRATS(pn5180)) {
                rats_ok = true;
                break;
            }
            pn5180_delay_ms(5);
        }

        if (!rats_ok) {
            ESP_LOGE(TAG, "RATS failed after retries");
            return false;
        }
        pn5180->iso14443_layer4_active = true;
        // RATS implies new session, ensure NDEF checked is false
        pn5180->iso14443_ndef_checked = false;
    }

    // 2. Select NDEF Tag Application (AID: D2 76 00 00 85 01 01)
    const uint8_t ndef_aid[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    if (!pn5180_iso14443_4_select_file(pn5180, ndef_aid, sizeof(ndef_aid))) {
        PN5180_LOGD(TAG, "Failed to select NDEF Application");
        // Not fatal for "activation" (might use other App), but fatal for NDEF read.
        pn5180->iso14443_ndef_checked  = true;
        pn5180->iso14443_ndef_detected = false;
        return false;
    }

    // 3. Select NDEF File (E1 04)
    const uint8_t ndef_file_id[] = {0xE1, 0x04};
    if (!pn5180_iso14443_4_select_file(pn5180, ndef_file_id, 2)) {
        PN5180_LOGD(TAG, "Failed to select NDEF File");
        pn5180->iso14443_ndef_checked  = true;
        pn5180->iso14443_ndef_detected = false;
        return false;
    }

    pn5180->iso14443_ndef_checked  = true;
    pn5180->iso14443_ndef_detected = true;
    return true;
}

static bool pn5180_iso14443_4_transceive(pn5180_t *pn5180, const uint8_t *tx, size_t tx_len, uint8_t *rx, size_t *rx_len)
{
    // Wrap APDU in I-Block (PCB | INF)
    // PCB I-Block: 0000001b (0x02) or 00000011b (0x03)
    // Bit 1 toggles (Block Number)
    uint8_t pcb = 0x02 | (pn5180->iso14443_block_number & 0x01);

    // Allocate temp buffer for Frame (PCB + INF)
    uint16_t frame_len = tx_len + 1;
    uint8_t *frame     = malloc(frame_len);
    if (!frame) return false;

    frame[0] = pcb;
    memcpy(&frame[1], tx, tx_len);

    // For ISO-DEP / Layer 4, the PN5180 automatically handles the CRC if enabled.
    // However, some datasheets suggest RX_CRC is not used in "Transceive" state
    // depending on config. Let's ensure it is enabled.
    pn5180_enable_crc(pn5180);

    // Transceive (CMD 0x09)
    // PN5180 transmits exactly what we give it (plus CRC)
    bool ret = pn5180_sendData(pn5180, frame, frame_len, 0);
    free(frame);

    if (!ret) return false;

    uint32_t irqStatus = 0;
    // Standard T=CL wait: RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT
    // Note: ISO 14443-4 cards can take time. Increase timeout if needed in caller logic
    // (but pn5180_wait_for_irq handles the configured timeout).
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "T4T Transceive", &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for T4T Transceive (PCB=0x%02X)", pcb);
        return false;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "Layer 4 Protocol Error (IRQ=0x%08" PRIx32 ")", irqStatus);
        return false;
    }

    uint16_t received = pn5180_rxBytesReceived(pn5180);

    // Read raw response (PCB + INF + CRC dropped by HW usually)
    uint8_t rx_buf[260];
    if (received > sizeof(rx_buf)) received = sizeof(rx_buf);

    if (received > 0) {
        pn5180_readData(pn5180, received, rx_buf);

        // Response format: [PCB] [INF...] [CRC? No, HW usually strips it]

        // Check PCB
        uint8_t rx_pcb = rx_buf[0];

        // Basic check: is it an I-Block? (00xxxxxx)
        if ((rx_pcb & 0xC0) == 0x00) {
            // It is an I-Block.
            // Toggle local block number ONLY if the received block number matches what we sent?
            // Standard says: Acknowledge valid I-Block by toggle.
            pn5180->iso14443_block_number = !pn5180->iso14443_block_number;
        } else if ((rx_pcb & 0xC0) == 0x80) {
            // R-Block (ACK/NAK)
            // If we receive an ACK, we might need to retransmit or fetch next.
            // This simple implementation does not handle chaining/retries yet.
            ESP_LOGW(TAG, "Received R-Block (0x%02X), not fully supported", rx_pcb);
            // We can treat it as failure for now or try to extract data if any.
            // R-Block has no INF usually.
            return false;
        } else if ((rx_pcb & 0xC0) == 0xC0) {
            // S-Block (WTX, DESELECT)
            // WTX is crucial for slow operations.
            if ((rx_pcb & 0x30) == 0x30) { // WTX
                ESP_LOGW(TAG, "Received WTX request, not supported yet");
            }
            return false;
        }

        // Copy payload (skip PCB)
        if (received >= 1) {
            size_t payload_len = received - 1;
            if (rx_len && payload_len > *rx_len) payload_len = *rx_len;
            memcpy(rx, &rx_buf[1], payload_len);
            if (rx_len) *rx_len = payload_len;
            return true;
        }
    }
    return false;
}

static bool pn5180_iso14443_4_select_file(pn5180_t *pn5180, const uint8_t *file_id, size_t file_id_len)
{
    // ISO 7816-4 Select File: 00 A4 00 00 Lc FileID
    // CLA=00, INS=A4, P1=00 (Select by ID), P2=0C (First or only occurrence, return no data)
    // Wait, NDEF usually uses P2=00 (First or only), P1=04 (Select by DF Name/AID) or P1=00 (Select by File ID)

    // For AID (Application): P1=04, P2=00
    // For File ID: P1=00, P2=00 or P2=0C

    uint8_t apdu[20];
    apdu[0] = 0x00;
    apdu[1] = 0xA4;

    if (file_id_len > 2) {
        apdu[2] = 0x04; // Select by DF Name (AID)
    } else {
        apdu[2] = 0x00; // Select by File ID
    }

    apdu[3] = 0x00; // P2 (00 = return FCI optional/default) mention: 0C for "no response data" but usually we want to check SW
    apdu[4] = (uint8_t)file_id_len;
    memcpy(&apdu[5], file_id, file_id_len);

    uint8_t rx[32];
    size_t  rx_len = sizeof(rx);

    // Need to append Le=00 sometimes? Not for Select usually unless we want FCI.
    // Let's assume just wrapper.

    if (!pn5180_iso14443_4_transceive(pn5180, apdu, 5 + file_id_len, rx, &rx_len)) {
        ESP_LOGE(TAG, "Select APDU failed to transmit/receive");
        return false;
    }

    // Check SW1 SW2 (last 2 bytes)
    if (rx_len < 2) return false;
    uint8_t sw1 = rx[rx_len - 2];
    uint8_t sw2 = rx[rx_len - 1];

    if (sw1 == 0x90 && sw2 == 0x00) return true;

    ESP_LOGD(TAG, "Select failed with SW: %02X %02X", sw1, sw2);
    return false;
}

static void pn5180_14443_detect_desfire_capacity(pn5180_t *pn5180, int *blocks_count)
{
    // Activate Layer 4 and try to select NDEF app
    if (pn5180_activate_layer4_ndef(pn5180)) {
        // Assume default NDEF capacity if activation worked
        *blocks_count = 4096;
    } else {
        *blocks_count = 0;
    }
}

static bool _pn5180_14443_detect_card_type_and_capacity( //
    pn5180_t  *pn5180,                                   //
    nfc_uid_t *uid,                                      //
    int       *blocks_count,                             //
    int       *block_size                                //
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
        need_reselection = pn5180_14443_detect_ultralight_variant(pn5180, &uid->subtype, blocks_count);
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
    case 0x10: // MIFARE Plus S (2K)
    case 0x11: // MIFARE Plus X (2K)
        PN5180_LOGD(TAG, "Detected MIFARE Plus 2K");
        uid->subtype  = PN5180_MIFARE_PLUS_2K;
        *blocks_count = 128; // 32 sectors * 4 blocks
        *block_size   = 16;
        break;
    case 0x18:
        PN5180_LOGD(TAG, "Detected MIFARE Classic 4K");
        uid->subtype  = PN5180_MIFARE_CLASSIC_4K;
        *blocks_count = 256; // 32 sectors * 4 blocks + 8 sectors * 16 blocks
        *block_size   = 16;
        break;
    case 0x20: // ISO 14443-4 (DESFire family)
    case 0x24: // DESFire EV1/EV2/EV3
        PN5180_LOGD(TAG, "Detected MIFARE DESFire (ISO 14443-4)");
        uid->subtype  = PN5180_MIFARE_DESFIRE;
        *block_size   = 1;
        *blocks_count = 0;
        pn5180_14443_detect_desfire_capacity(pn5180, blocks_count);
        break;
    case 0x28:
        PN5180_LOGD(TAG, "Detected MIFARE Plus 4K");
        uid->subtype  = PN5180_MIFARE_CLASSIC_1K; // Emulated 1K
        *blocks_count = 64;
        *block_size   = 16;
        break;
    case 0x38:
        PN5180_LOGD(TAG, "Detected MIFARE Plus 4K");
        uid->subtype  = PN5180_MIFARE_CLASSIC_4K; // Emulated 4K
        *blocks_count = 256;
        *block_size   = 16;
        break;
    default:
        PN5180_LOGD(TAG, "Unknown or unsupported MIFARE type (SAK: 0x%02X), defaulting to Classic 1K", uid->sak);
        uid->subtype  = PN5180_MIFARE_CLASSIC_1K;
        *blocks_count = 64;
        *block_size   = 16;
        break;
    }
    uid->blocks_count = *blocks_count;
    uid->block_size   = *block_size;

    // Update global state for Read dispatcher
    pn5180->iso14443_current_card_type = uid->subtype;

    return need_reselection;
}

static bool pn5180_14443_select_by_uid( //
    pn5180_t  *pn5180,                  //
    nfc_uid_t *uid                      //
)
{
    uint8_t current_level = 1;
    uint8_t uid_offset    = 0;
    uint8_t sak           = 0;
    uint8_t level_data[5]; // 4 data bytes + 1 BCC
    uint8_t atqa[2];

    // Reset Layer 4 state for new selection
    pn5180->iso14443_layer4_active = false;
    pn5180->iso14443_block_number  = 0;
    pn5180->iso14443_ndef_checked  = false;
    pn5180->iso14443_ndef_detected = false;

    prepare_14443A_activation(pn5180);
    if (!pn5180_14443_sendWUPA(pn5180, atqa)) {
        ESP_LOGE(TAG, "No card in field for direct selection");
        pn5180_clearAllIRQs(pn5180);
        return false;
    }

    while (current_level <= 3) {
        // Validate we have enough UID bytes remaining
        if (uid_offset >= uid->uid_length) {
            ESP_LOGE(TAG, "UID offset %d exceeds UID length %d at level %d", uid_offset, uid->uid_length, current_level);
            pn5180_clearAllIRQs(pn5180);
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
                pn5180_clearAllIRQs(pn5180);
                return false;
            }
            memcpy(level_data, &uid->uid[uid_offset], 4);
            uid_offset += 4;
        }

        // Calculate BCC for this level's segment
        level_data[4] = level_data[0] ^ level_data[1] ^ level_data[2] ^ level_data[3];

        // 2. Perform Selection (NVB = 0x70)
        if (!pn5180_14443_sendSelect(pn5180, current_level, level_data, &sak)) {
            ESP_LOGE(TAG, "Direct Select failed at Level %d", current_level);
            pn5180_clearAllIRQs(pn5180);
            return false;
        }

        // 3. Check if UID is complete
        if (!(sak & 0x04)) {
            ESP_LOGI(TAG, "Card successfully selected via direct path!");
            // Determine card type and capacity from SAK
            if (uid->sak != sak) {
                uid->sak = sak;
            }
            // Check if card supports ISO 14443-4 (Layer 4)
            if (sak & 0x20) {
                PN5180_LOGD(TAG, "Card supports ISO 14443-4, activating Layer 4...");
                pn5180->iso14443_current_card_type = PN5180_MIFARE_DESFIRE; // Ensure type is set based on SAK

                // Perform RATS and setup NDEF context
                if (!pn5180_activate_layer4_ndef(pn5180)) {
                    PN5180_LOGD(TAG, "NDEF activation failed (card might be unformatted)");
                }
            } else {
                // Not a Layer 4 card (e.g. Ultralight, Classic)
                // s_active_card_type should be set by detect() or default logic
                // But if we just selected by UID, we might need to infer it.
                // Classic 1K = 0x08, 4K = 0x18.
                // We rely on 'detect' having run previously to set subtype precise,
                // but we can set a fallback here if needed.
            }

            return true;
        }
        current_level++;
    }
    return false;
}

static bool pn5180_mifare_halt(pn5180_t *pn5180)
{
    pn5180_enable_tx_crc(pn5180);
    pn5180_disable_rx_crc(pn5180);
    uint8_t cmd_buf[2];
    cmd_buf[0] = 0x50;
    cmd_buf[1] = 0x00;
    PN5180_LOGD(TAG, "Sending MIFARE Halt command");
    PN5180_LOGD(TAG, "HALT data: 0x%02X 0x%02X", cmd_buf[0], cmd_buf[1]);
    bool ret = pn5180_sendData(pn5180, cmd_buf, 2, 0x00);
    if (ret) {
        uint32_t mask = TX_IRQ_STAT | IDLE_IRQ_STAT | GENERAL_ERROR_IRQ_STAT;
        uint32_t irqStatus;
        ret = pn5180_wait_for_irq(pn5180, mask, "HLTA Transmission", &irqStatus);
        if (!ret) {
            ESP_LOGE(TAG, "Timeout waiting for HLTA response");
        } else if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
            ESP_LOGE(TAG, "General error during HLTA");
            ret = false;
        }
    }
    pn5180_disable_crc(pn5180);
    pn5180_set_transceiver_idle(pn5180);
    pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, SYSTEM_CONFIG_CLEAR_CRYPTO_MASK);
    pn5180->iso14443_layer4_active = false;
    return ret;
}
