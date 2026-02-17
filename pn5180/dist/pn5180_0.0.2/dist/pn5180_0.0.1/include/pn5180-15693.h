#pragma once
#include "pn5180.h"
#include <stdint.h>

/** @brief Supported RF configurations for ISO15693 */
typedef enum
{
    PN5180_15693_26KASK100 = 0x0D, /**< 26 kbps, ASK 100% */
    PN5180_15693_26KASK10  = 0x0E, /**< 26 kbps, ASK 10% */
} pn5180_15693_rf_config_t;

/**
 * @brief Initialize ISO15693 protocol wrapper
 * @param pn5180 Pointer to PN5180 device structure
 * @param rf_config RF configuration for ISO15693 modulation
 * @return Protocol interface for ISO15693 operations
 */
pn5180_proto_t *pn5180_15693_init(pn5180_t *pn5180, pn5180_15693_rf_config_t rf_config);