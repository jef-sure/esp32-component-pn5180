#include "pn5180-mifare.h"
#include "esp_log.h"
#include "pn5180-internal.h"
#include <inttypes.h>
#include <string.h>

static const char *TAG = "pn5180-mifare";

bool pn5180_mifare_block_read(pn5180_t *pn5180, int blockno, uint8_t *buffer, size_t buffer_len)
{
    uint8_t cmd_buf[2];
    cmd_buf[0] = 0x30; // MIFARE Read command
    cmd_buf[1] = (uint8_t)blockno;
    PN5180_LOGD(TAG, "READ data: 0x%02X 0x%02X", cmd_buf[0], cmd_buf[1]);

    uint8_t            rx_buf[16];
    size_t             rx_len = 0;
    pn5180_rf_result_t result = pn5180_rf_transceive(pn5180, cmd_buf, sizeof(cmd_buf), 0, rx_buf, sizeof(rx_buf), &rx_len, PN5180_TIMEOUT_MIFARE_READ_US, NULL);
    if (result != PN5180_RF_OK) {
        // A NAK (4 bits) arrives as an RX error; a missing answer as a timeout.
        PN5180_LOGD(TAG, "MIFARE block %d read failed (result=%d)", blockno, (int)result);
        return false;
    }

    // TODO: If Ultralight field issues resurface, re-check whether some readers return
    // 16 bytes here with only the first 4 bytes valid and the trailing bytes undefined.
    if (rx_len != 16 && rx_len != 4) {
        ESP_LOGE(TAG, "MIFARE block %d read returned incorrect length: %u (expected 16 for Classic or 4 for Ultralight)", blockno, (unsigned)rx_len);
        return false;
    }
    PN5180_LOGD(TAG, "MIFARE block %d read returned %u bytes", blockno, (unsigned)rx_len);

    memcpy(buffer, rx_buf, (rx_len <= buffer_len) ? rx_len : buffer_len);
    return true;
}

// Sends one frame of a write sequence and checks the 4-bit ACK that answers it.
// Returns 0 on ACK, -1 if there was no usable answer, -2 if the answer is not a 4-bit frame, -3 on NAK.
static int pn5180_mifare_send_expect_ack(pn5180_t *pn5180, const uint8_t *frame, size_t frame_len, uint32_t timeout_us, const char *what, int blockno)
{
    uint8_t            ack    = 0;
    size_t             rx_len = 0;
    pn5180_rf_result_t result = pn5180_rf_transceive(pn5180, frame, frame_len, 0, &ack, 1, &rx_len, timeout_us, NULL);
    // The ACK is a 4-bit frame without CRC, so with RX CRC enabled it is reported as an RX error.
    if (result != PN5180_RF_OK && result != PN5180_RF_RX_ERROR) {
        if (result == PN5180_RF_OVERFLOW) {
            ESP_LOGE(TAG, "%s %d: ACK has incorrect length", what, blockno);
            return -2;
        }
        ESP_LOGE(TAG, "%s %d: no ACK (result=%d)", what, blockno, (int)result);
        return -1;
    }
    if (rx_len != 1) {
        ESP_LOGE(TAG, "%s %d: ACK returned incorrect length: %u", what, blockno, (unsigned)rx_len);
        return -2;
    }
    if ((ack & 0x0F) != 0x0A) {
        ESP_LOGE(TAG, "%s %d: NACK received: 0x%02X", what, blockno, ack);
        return -3;
    }
    return 0;
}

// Ultralight/NTAG WRITE (0xA2): one frame with the page address and 4 data bytes, answered by a 4-bit ACK.
static int pn5180_mifare_page_write(pn5180_t *pn5180, int pageno, const uint8_t *buffer)
{
    uint8_t cmd_buf[6];
    cmd_buf[0] = 0xA2; // Ultralight Write command
    cmd_buf[1] = (uint8_t)pageno;
    memcpy(&cmd_buf[2], buffer, 4);
    PN5180_LOGD(TAG, "Sending Ultralight Write command: 0x%02X 0x%02X", cmd_buf[0], cmd_buf[1]);
    return pn5180_mifare_send_expect_ack(pn5180, cmd_buf, sizeof(cmd_buf), PN5180_TIMEOUT_MIFARE_WRITE_US, "Ultralight write page", pageno);
}

int pn5180_mifare_block_write(pn5180_t *pn5180, int blockno, const uint8_t *buffer, size_t buffer_len)
{
    if (buffer_len == 4) {
        return pn5180_mifare_page_write(pn5180, blockno, buffer);
    }
    if (buffer_len < 16) {
        ESP_LOGE(TAG, "MIFARE block %d write buffer too small: %zu", blockno, buffer_len);
        return -1;
    }
    uint8_t cmd_buf[2];
    cmd_buf[0] = 0xA0; // MIFARE Write command
    cmd_buf[1] = (uint8_t)blockno;
    PN5180_LOGD(TAG, "Sending MIFARE Write command: 0x%02X 0x%02X", cmd_buf[0], cmd_buf[1]);
    int rc = pn5180_mifare_send_expect_ack(pn5180, cmd_buf, sizeof(cmd_buf), PN5180_TIMEOUT_MIFARE_READ_US, "MIFARE write block", blockno);
    if (rc != 0) {
        return rc; // -1, -2 or -3
    }

    PN5180_LOGD(TAG, "Sending 16 bytes of write data for block %d", blockno);
    rc = pn5180_mifare_send_expect_ack(pn5180, buffer, 16, PN5180_TIMEOUT_MIFARE_WRITE_US, "MIFARE write data block", blockno);
    switch (rc) {
    case 0:
        return 0;
    case -1:
        return -5; // no final ACK
    case -2:
        return -6; // final ACK with incorrect length
    default:
        return -8; // final NACK
    }
}

bool pn5180_mifare_value_read(pn5180_t *pn5180, uint8_t blockno, int32_t *value)
{
    uint8_t buf[16];
    if (value == NULL || !pn5180_mifare_block_read(pn5180, blockno, buf, sizeof(buf))) {
        return false;
    }
    /*
     * MIFARE Classic value block layout:
     *   bytes 0..3   : value (LSB first)
     *   bytes 4..7   : ~value
     *   bytes 8..11  : value (again)
     *   byte  12     : addr
     *   byte  13     : ~addr
     *   byte  14     : addr
     *   byte  15     : ~addr
     */
    uint32_t v0  = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    uint32_t v2  = (uint32_t)buf[8] | ((uint32_t)buf[9] << 8) | ((uint32_t)buf[10] << 16) | ((uint32_t)buf[11] << 24);
    uint32_t inv = ~((uint32_t)buf[4] | ((uint32_t)buf[5] << 8) | ((uint32_t)buf[6] << 16) | ((uint32_t)buf[7] << 24));
    if (v0 != v2 || v0 != inv) {
        ESP_LOGE(TAG, "MIFARE block %u is not a value block", (unsigned)blockno);
        return false;
    }
    if ((uint8_t)(buf[12] ^ 0xFF) != buf[13] || (uint8_t)(buf[14] ^ 0xFF) != buf[15] || buf[12] != buf[14]) {
        ESP_LOGE(TAG, "MIFARE value block %u has invalid address bytes", (unsigned)blockno);
        return false;
    }
    *value = (int32_t)v0;
    return true;
}

bool pn5180_mifare_value_write(pn5180_t *pn5180, uint8_t blockno, int32_t value, uint8_t addr)
{
    uint8_t  buf[16];
    uint32_t v = (uint32_t)value;
    uint32_t i = ~v;

    for (int n = 0; n < 4; n++) {
        buf[n]     = (uint8_t)((v >> (8 * n)) & 0xFF);
        buf[4 + n] = (uint8_t)((i >> (8 * n)) & 0xFF);
        buf[8 + n] = buf[n];
    }
    buf[12] = addr;
    buf[13] = (uint8_t)~addr;
    buf[14] = addr;
    buf[15] = (uint8_t)~addr;
    return pn5180_mifare_block_write(pn5180, blockno, buf, sizeof(buf)) == 0;
}

#define MIFARE_CMD_DECREMENT 0xC0
#define MIFARE_CMD_INCREMENT 0xC1
#define MIFARE_CMD_RESTORE   0xC2
#define MIFARE_CMD_TRANSFER  0xB0

// Increment, Decrement and Restore: the command is acknowledged, then the 4-byte operand is sent.
// The card does not answer the operand unless it rejects it, so silence means success.
static bool pn5180_mifare_value_op(pn5180_t *pn5180, uint8_t cmd, uint8_t blockno, uint32_t delta)
{
    uint8_t cmd_buf[2] = {cmd, blockno};
    if (pn5180_mifare_send_expect_ack(pn5180, cmd_buf, sizeof(cmd_buf), PN5180_TIMEOUT_MIFARE_READ_US, "MIFARE value operation on block", blockno) != 0) {
        return false;
    }

    uint8_t            operand[4] = {(uint8_t)(delta & 0xFF), (uint8_t)((delta >> 8) & 0xFF), (uint8_t)((delta >> 16) & 0xFF), (uint8_t)((delta >> 24) & 0xFF)};
    uint8_t            nak        = 0;
    size_t             rx_len     = 0;
    pn5180_rf_result_t result     = pn5180_rf_transceive(pn5180, operand, sizeof(operand), 0, &nak, 1, &rx_len, PN5180_TIMEOUT_MIFARE_READ_US, NULL);
    if (result == PN5180_RF_TIMEOUT) {
        return true;
    }
    ESP_LOGE(TAG, "MIFARE value operation on block %u rejected (result=%d, answer=0x%02X)", (unsigned)blockno, (int)result, nak);
    return false;
}

bool pn5180_mifare_increment(pn5180_t *pn5180, uint8_t blockno, uint32_t delta)
{
    return pn5180_mifare_value_op(pn5180, MIFARE_CMD_INCREMENT, blockno, delta);
}

bool pn5180_mifare_decrement(pn5180_t *pn5180, uint8_t blockno, uint32_t delta)
{
    return pn5180_mifare_value_op(pn5180, MIFARE_CMD_DECREMENT, blockno, delta);
}

bool pn5180_mifare_restore(pn5180_t *pn5180, uint8_t blockno)
{
    return pn5180_mifare_value_op(pn5180, MIFARE_CMD_RESTORE, blockno, 0);
}

bool pn5180_mifare_transfer(pn5180_t *pn5180, uint8_t blockno)
{
    uint8_t cmd_buf[2] = {MIFARE_CMD_TRANSFER, blockno};
    return pn5180_mifare_send_expect_ack(pn5180, cmd_buf, sizeof(cmd_buf), PN5180_TIMEOUT_MIFARE_WRITE_US, "MIFARE transfer to block", blockno) == 0;
}
