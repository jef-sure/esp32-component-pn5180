#pragma once
#include "pn5180.h"
#include <stdint.h>

/**
 * @brief Initialize ISO14443A/MIFARE protocol wrapper
 * @param pn5180 Pointer to PN5180 device structure
 * @return Protocol interface for ISO14443A operations
 */
pn5180_proto_t *pn5180_14443_init(pn5180_t *pn5180);

