/**
 * @file pn5180-internal.h
 * @brief Internal helper functions for PN5180 component
 *
 * This header contains functions and macros used internally by the PN5180
 * component implementation. These are not part of the public API and may
 * change without notice.
 *
 * @note Application code should use pn5180.h, pn5180-14443.h, pn5180-15693.h,
 *       or pn5180-ndef.h instead.
 */

#pragma once

#include "esp_log.h"
#include "pn5180.h"
#include <stddef.h>
#include <stdint.h>

/** @brief Enable debug logging for PN5180 component (comment out to disable) */
#define PN5180_DEBUG

#ifdef PN5180_DEBUG
/** @brief Debug log macro (enabled when PN5180_DEBUG is defined) */
#define PN5180_LOGD(tag, format, ...) ESP_LOGD(tag, format, ##__VA_ARGS__)
#else
/** @brief Debug log macro (disabled - compiles to no-op) */
#define PN5180_LOGD(tag, format, ...) \
    do {                              \
    } while (0)
#endif

/**
 * @brief Wait for RX IRQ and read received data into a buffer
 * @param pn5180 Pointer to PN5180 device structure
 * @param irq_mask IRQ flags to wait for (RX_IRQ_STAT, timeout, etc.)
 * @param operation Description of operation (for logging)
 * @param buffer Destination buffer for RX data (can be NULL to skip copy)
 * @param buffer_len Size of destination buffer in bytes
 * @param out_len Optional pointer to receive RX byte count
 * @param out_rx_status Optional pointer to receive RX_STATUS register value
 * @return true on successful RX and read, false on error/timeout
 */
bool pn5180_wait_read_rx(     //
    pn5180_t   *pn5180,       //
    uint32_t    irq_mask,     //
    const char *operation,    //
    uint8_t    *buffer,       //
    size_t      buffer_len,   //
    uint16_t   *out_len,      //
    uint32_t   *out_rx_status //
);
