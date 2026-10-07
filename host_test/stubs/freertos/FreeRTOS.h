#pragma once
// Host stand-in for the FreeRTOS header.
#include <stdint.h>
typedef uint32_t TickType_t;
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))
