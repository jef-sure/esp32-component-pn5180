/**
 * @file pn5180-internal.h
 * @brief Internal helper functions for PN5180 component
 *
 * This header contains functions and macros used internally by the PN5180
 * component implementation. These are not part of the public API and may
 * change without notice.
 *
 * @note Application code should use pn5180.h, pn5180-14443.h, pn5180-15693.h,
 *       pn5180-mifare.h or pn5180-ndef.h instead.
 */

#pragma once

#include "esp_log.h"
#include "pn5180.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Enable debug logging for PN5180 component (uncomment to enable) */
// #define PN5180_DEBUG

#ifdef PN5180_DEBUG
/** @brief Debug log macro (enabled when PN5180_DEBUG is defined) */
#define PN5180_LOGD(tag, format, ...) ESP_LOGD(tag, format, ##__VA_ARGS__)
#else
/** @brief Debug log macro (disabled - compiles to no-op) */
#define PN5180_LOGD(tag, format, ...) \
    do {                              \
    } while (0)
#endif

/** @brief Warning log macro (always enabled) */
#define PN5180_LOGW(tag, format, ...) ESP_LOGW(tag, format, ##__VA_ARGS__)

/*
 * Response timeouts for pn5180_rf_transceive(), in microseconds. They bound the time until a card
 * starts to answer, so they decide how long a missing card costs. All are several times the delay
 * the standards and datasheets allow, because a timeout that is too short breaks a working card.
 */
#define PN5180_TIMEOUT_14443A_ACTIVATION_US 5000u  /**< REQA, WUPA, anticollision, SELECT (FDT is below 0.2 ms) */
#define PN5180_TIMEOUT_14443A_RATS_US       20000u /**< RATS: activation frame waiting time is about 5 ms */
#define PN5180_TIMEOUT_MIFARE_READ_US       10000u /**< READ, GET_VERSION and the ACK after a write command */
#define PN5180_TIMEOUT_MIFARE_WRITE_US      20000u /**< ACK after the data was programmed (Ultralight: up to 4 ms) */
#define PN5180_TIMEOUT_15693_US             10000u /**< Inventory, Select, Read, Get System Info, Reset to Ready */
#define PN5180_TIMEOUT_15693_WRITE_US       40000u /**< Write Single Block: the tag answers after programming (up to 20 ms) */

/**
 * Waits us microseconds with the CPU released: the calling task blocks on the poll timer of the
 * device and wakes up when it expires, at most some tens of microseconds late and never early.
 * Waits below about 0.2 ms, and a device without the timer, are left to pn5180_delay_us().
 */
void pn5180_sleep_us(pn5180_t *pn5180, uint32_t us);

/**
 * pn5180_14443_4_select_file() that also tells why it failed: *card_refused is true when the card
 * answered with an error status word, false when no well-formed answer came back (the session was
 * closed, or the answer has no status word). card_refused may be NULL.
 */
bool pn5180_14443_4_select_file_ex(pn5180_t *pn5180, const uint8_t *file_id, size_t file_id_len, bool *card_refused);

#ifdef __cplusplus
}
#endif
