#pragma once
/**
 * @file fake_pn5180.h
 * @brief Stand-in for src/pn5180.c in host tests
 *
 * The protocol code (ISO14443A, ISO14443-4, MIFARE, ISO15693, NDEF) only talks to the reader
 * through a handful of functions of pn5180.c. The fake implements those: RF exchanges go to a
 * simulated card installed by the test, register writes are remembered, delays return at once.
 */
#include "pn5180.h"

/** Simulated card: gets every frame the driver transmits and produces the reader's view of the answer. */
typedef pn5180_rf_result_t (*fake_card_fn)(void *ctx, const uint8_t *tx, size_t tx_len, uint8_t tx_last_bits, uint8_t *rx, size_t rx_size, size_t *rx_len,
                                           uint32_t timeout_us, uint32_t *rx_status);

/** Simulated MIFARE Classic authentication: returns 0 when the card accepts the key. */
typedef int16_t (*fake_auth_fn)(void *ctx, uint8_t blockno, const uint8_t *key, uint8_t key_type, const uint8_t uid[4]);

pn5180_t *fake_pn5180_create(void);
void      fake_pn5180_destroy(pn5180_t *pn5180);

/** Installs the card in the field; NULL removes it (every exchange then times out). */
void fake_set_card(fake_card_fn card, fake_auth_fn auth, void *ctx);

/** Number of RF frames transmitted since the last fake_pn5180_create(). */
int fake_frame_count(void);
