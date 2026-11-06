#pragma once
// Host stand-in for the ESP-IDF header. Time is simulated by the test (see chip_sim.c).
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
typedef struct host_esp_timer *esp_timer_handle_t;
typedef void (*esp_timer_cb_t)(void *arg);
typedef struct
{
    esp_timer_cb_t callback;
    void          *arg;
    int            dispatch_method;
    const char    *name;
    bool           skip_unhandled_events;
} esp_timer_create_args_t;
int64_t   esp_timer_get_time(void);
esp_err_t esp_timer_create(const esp_timer_create_args_t *create_args, esp_timer_handle_t *out_handle);
esp_err_t esp_timer_start_once(esp_timer_handle_t timer, uint64_t timeout_us);
esp_err_t esp_timer_stop(esp_timer_handle_t timer);
esp_err_t esp_timer_delete(esp_timer_handle_t timer);
