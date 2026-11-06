#pragma once
// Host stand-in for the ESP-IDF header: every allocation comes from the C heap.
#include <stdlib.h>
#define MALLOC_CAP_DMA                   (1u << 3)
#define heap_caps_calloc(n, size, caps)  calloc((n), (size))
#define heap_caps_malloc(size, caps)     malloc((size))
