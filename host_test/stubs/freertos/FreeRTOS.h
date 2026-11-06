#pragma once
// Host stand-in for the FreeRTOS header, with the ESP-IDF default tick of 10 ms.
#include <stdint.h>
typedef uint32_t TickType_t;
typedef int      BaseType_t;
#define pdTRUE              1
#define pdFALSE             0
#define portMAX_DELAY       ((TickType_t)0xFFFFFFFFu)
#define configTICK_RATE_HZ  100
#define portTICK_PERIOD_MS  (1000 / configTICK_RATE_HZ)
#define pdMS_TO_TICKS(ms)   ((TickType_t)(((uint64_t)(ms) * configTICK_RATE_HZ) / 1000u))
#define portYIELD_FROM_ISR() \
    do {                     \
    } while (0)
