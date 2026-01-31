#include "pn5180-mifare.h"
#include "esp_log.h"
#include "pn5180-internal.h"

static const char *TAG = "pn5180-mifare";

bool pn5180_mifare_block_read(pn5180_t *pn5180, int blockno, uint8_t *buffer, size_t buffer_len)
{
    uint8_t cmd_buf[2];
    cmd_buf[0] = 0x30; // MIFARE Read command
    cmd_buf[1] = (uint8_t)blockno;
    PN5180_LOGD(TAG, "READ data: 0x%02X 0x%02X", cmd_buf[0], cmd_buf[1]);

    pn5180_clearAllIRQs(pn5180);

    if (!pn5180_sendData(pn5180, cmd_buf, 2, 0x00)) {
        ESP_LOGE(TAG, "Failed to send MIFARE Read command for block %d", blockno);
        return false;
    }

    uint32_t irqStatus;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "MIFARE Read", &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for MIFARE block %d read response", blockno);
        return false;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "Error during MIFARE block %d read", blockno);
        return false;
    }

    uint32_t rxStatus;
    if (!pn5180_readRegister(pn5180, RX_STATUS, &rxStatus)) {
        ESP_LOGE(TAG, "Failed to read RX_STATUS for block %d", blockno);
        return false;
    }

    if (rxStatus & (RX_PROTOCOL_ERROR | RX_DATA_INTEGRITY_ERROR)) {
        ESP_LOGD(TAG, "RX error during MIFARE block %d read (RX_STATUS=0x%08lX)", blockno, rxStatus);
        pn5180_clearAllIRQs(pn5180);
        return false;
    }

    uint16_t rxLen = rxStatus & RX_BYTES_RECEIVED_MASK;
    if (rxLen != 16 && rxLen != 4) {
        ESP_LOGE(TAG, "MIFARE block %d read returned incorrect length: %d (expected 16 for Classic or 4 for Ultralight)", blockno, rxLen);
        pn5180_clearAllIRQs(pn5180);
        return false;
    } else {
        PN5180_LOGD(TAG, "MIFARE block %d read returned %d bytes", blockno, rxLen);
    }

    uint8_t  temp_buffer[16];
    uint8_t *read_buffer = (rxLen <= buffer_len) ? buffer : temp_buffer;

    if (!pn5180_readData(pn5180, rxLen, read_buffer)) {
        ESP_LOGE(TAG, "Failed to read MIFARE block %d data", blockno);
        pn5180_clearAllIRQs(pn5180);
        return false;
    }

    if (rxLen > buffer_len) {
        PN5180_LOGD(TAG, "MIFARE block %d read returned %d bytes, but buffer is only %zu bytes, return required length", blockno, rxLen, buffer_len);
        memcpy(buffer, temp_buffer, buffer_len);
    }

    pn5180_clearAllIRQs(pn5180);
    return true;
}

int pn5180_mifare_block_write(pn5180_t *pn5180, int blockno, const uint8_t *buffer, size_t buffer_len)
{
    if (buffer_len < 16) {
        ESP_LOGE(TAG, "MIFARE block %d write buffer too small: %zu", blockno, buffer_len);
        return -1;
    }
    uint8_t cmd_buf[2];
    cmd_buf[0] = 0xA0; // MIFARE Write command
    cmd_buf[1] = (uint8_t)blockno;
    PN5180_LOGD(TAG, "Sending MIFARE Write command: 0x%02X 0x%02X", cmd_buf[0], cmd_buf[1]);
    if (!pn5180_sendData(pn5180, cmd_buf, 2, 0x00)) {
        ESP_LOGE(TAG, "Failed to send MIFARE Write command for block %d", blockno);
        return -1;
    }

    uint32_t irqStatus;
    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "MIFARE Write ACK", &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for MIFARE block %d write ACK", blockno);
        return -1;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "Error during MIFARE block %d write ACK", blockno);
        pn5180_clearAllIRQs(pn5180);
        return -1;
    }

    uint16_t rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen != 1) {
        ESP_LOGE(TAG, "MIFARE block %d write ACK returned incorrect length: %d", blockno, rxLen);
        pn5180_clearAllIRQs(pn5180);
        return -2;
    }

    uint8_t ack;
    if (!pn5180_readData(pn5180, 1, &ack)) {
        ESP_LOGE(TAG, "Failed to read MIFARE block %d write ACK", blockno);
        pn5180_clearAllIRQs(pn5180);
        return -2;
    }

    pn5180_clearAllIRQs(pn5180);

    if ((ack & 0x0F) != 0x0A) {
        ESP_LOGE(TAG, "MIFARE block %d write NACK received: 0x%02X", blockno, ack);
        return -3;
    }

    PN5180_LOGD(TAG, "Sending 16 bytes of write data for block %d", blockno);
    if (!pn5180_sendData(pn5180, buffer, 16, 0x00)) {
        ESP_LOGE(TAG, "Failed to send MIFARE block %d data for writing", blockno);
        return -4;
    }

    if (!pn5180_wait_for_irq(pn5180, RX_IRQ_STAT | GENERAL_ERROR_IRQ_STAT, "MIFARE Write Final ACK", &irqStatus)) {
        ESP_LOGE(TAG, "Timeout waiting for MIFARE block %d write final ACK", blockno);
        return -5;
    }

    if (irqStatus & GENERAL_ERROR_IRQ_STAT) {
        ESP_LOGE(TAG, "Error during MIFARE block %d write final ACK", blockno);
        pn5180_clearAllIRQs(pn5180);
        return -5;
    }

    rxLen = pn5180_rxBytesReceived(pn5180);
    if (rxLen != 1) {
        ESP_LOGE(TAG, "MIFARE block %d write final ACK returned incorrect length: %d", blockno, rxLen);
        pn5180_clearAllIRQs(pn5180);
        return -6;
    }

    if (!pn5180_readData(pn5180, 1, &ack)) {
        ESP_LOGE(TAG, "Failed to read MIFARE block %d write final ACK", blockno);
        pn5180_clearAllIRQs(pn5180);
        return -7;
    }

    pn5180_clearAllIRQs(pn5180);

    if ((ack & 0x0F) != 0x0A) {
        ESP_LOGE(TAG, "MIFARE block %d write final NACK received: 0x%02X", blockno, ack);
        return -8;
    }
    return 0;
}
