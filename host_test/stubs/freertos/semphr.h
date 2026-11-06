#pragma once
// Host stand-in for the FreeRTOS header: binary semaphores only.
#include "freertos/FreeRTOS.h"
typedef struct host_semaphore *SemaphoreHandle_t;
SemaphoreHandle_t xSemaphoreCreateBinary(void);
BaseType_t        xSemaphoreTake(SemaphoreHandle_t sem, TickType_t ticks);
BaseType_t        xSemaphoreGive(SemaphoreHandle_t sem);
BaseType_t        xSemaphoreGiveFromISR(SemaphoreHandle_t sem, BaseType_t *higher_priority_task_woken);
void              vSemaphoreDelete(SemaphoreHandle_t sem);
