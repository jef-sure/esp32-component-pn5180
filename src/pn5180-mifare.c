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
