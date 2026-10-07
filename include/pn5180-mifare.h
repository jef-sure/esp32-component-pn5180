#pragma once

#include "pn5180.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Read a MIFARE Classic block (16 bytes)
 * @param pn5180 Pointer to PN5180 device structure
 * @param blockno Block index to read
 * @param buffer Destination buffer for block data
 * @param buffer_len Size of destination buffer in bytes
 * @return true on success, false on failure
 */
bool pn5180_mifare_block_read(pn5180_t *pn5180, int blockno, uint8_t *buffer, size_t buffer_len);

/**
 * @brief Write a MIFARE Classic block (16 bytes) or an Ultralight/NTAG page (4 bytes)
 * @param pn5180 Pointer to PN5180 device structure
 * @param blockno Block or page index to write
 * @param buffer Source buffer with block data
 * @param buffer_len Size of source buffer in bytes: exactly 4 writes one Ultralight/NTAG page
 *                   with WRITE (0xA2); 16 or more writes a 16-byte block with the MIFARE
 *                   Write command (0xA0)
 * @return 0 on success, negative on error
 */
int  pn5180_mifare_block_write(pn5180_t *pn5180, int blockno, const uint8_t *buffer, size_t buffer_len);

#ifdef __cplusplus
}
#endif
