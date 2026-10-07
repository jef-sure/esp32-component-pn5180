#pragma once

#include "pn5180.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Read a MIFARE Classic block, or four Ultralight / NTAG pages (16 bytes)
 * @param pn5180 Pointer to PN5180 device structure
 * @param blockno Block or first page index to read, 0..255
 * @param buffer Destination buffer for block data
 * @param buffer_len Size of destination buffer in bytes; a buffer shorter than 16 bytes receives
 *                   the first buffer_len bytes
 * @return true if the card answered with 16 bytes, false otherwise
 */
bool pn5180_mifare_block_read(pn5180_t *pn5180, int blockno, uint8_t *buffer, size_t buffer_len);

/**
 * @brief Write a MIFARE Classic block (16 bytes) or an Ultralight/NTAG page (4 bytes)
 * @param pn5180 Pointer to PN5180 device structure
 * @param blockno Block or page index to write, 0..255
 * @param buffer Source buffer with block data
 * @param buffer_len Size of source buffer in bytes: exactly 4 writes one Ultralight/NTAG page
 *                   with WRITE (0xA2); 16 or more writes a 16-byte block with the MIFARE
 *                   Write command (0xA0)
 * @return 0 on success, negative on error
 */
int  pn5180_mifare_block_write(pn5180_t *pn5180, int blockno, const uint8_t *buffer, size_t buffer_len);

/**
 * @brief Read a MIFARE Classic value block and check its format
 *
 * The sector must be authenticated. Fails if the block is not a correctly formatted value
 * block (value, inverted value, value, address, inverted address, address, inverted address).
 *
 * @return true with the value in *value; false if the block could not be read or is not a value
 *         block, with *value left unchanged
 */
bool pn5180_mifare_value_read(pn5180_t *pn5180, uint8_t blockno, int32_t *value);

/**
 * @brief Format a block as a MIFARE Classic value block
 * @param value Initial value
 * @param addr Address byte stored in the block (usually the block number, used for backup management)
 */
bool pn5180_mifare_value_write(pn5180_t *pn5180, uint8_t blockno, int32_t value, uint8_t addr);

/**
 * @brief Add @p delta to a value block
 *
 * The result is held in the card's transfer buffer; call pn5180_mifare_transfer() to store it.
 */
bool pn5180_mifare_increment(pn5180_t *pn5180, uint8_t blockno, uint32_t delta);

/** @brief Subtract @p delta from a value block; store the result with pn5180_mifare_transfer() */
bool pn5180_mifare_decrement(pn5180_t *pn5180, uint8_t blockno, uint32_t delta);

/** @brief Load a value block into the card's transfer buffer */
bool pn5180_mifare_restore(pn5180_t *pn5180, uint8_t blockno);

/** @brief Write the card's transfer buffer to a value block */
bool pn5180_mifare_transfer(pn5180_t *pn5180, uint8_t blockno);

#ifdef __cplusplus
}
#endif
