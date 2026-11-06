#pragma once
// Host stand-in for the ESP-IDF header: what the PN5180 sources use.
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include <stddef.h>
#include <stdint.h>
typedef struct host_spi_device *spi_device_handle_t;
typedef int spi_host_device_t;
#define SPI1_HOST       0
#define SPI2_HOST       1
#define SPI3_HOST       2
#define SPI_HOST_MAX    3
#define SPI_DMA_CH_AUTO 3
typedef struct
{
    int mosi_io_num;
    int miso_io_num;
    int sclk_io_num;
    int quadwp_io_num;
    int quadhd_io_num;
    int max_transfer_sz;
} spi_bus_config_t;
typedef struct
{
    int      clock_speed_hz;
    uint8_t  mode;
    int      spics_io_num;
    int      queue_size;
    uint32_t flags;
} spi_device_interface_config_t;
typedef struct
{
    uint32_t    flags;
    size_t      length;   /**< bits to transmit */
    size_t      rxlength; /**< bits to receive, 0 for length */
    const void *tx_buffer;
    void       *rx_buffer;
} spi_transaction_t;
esp_err_t spi_bus_initialize(spi_host_device_t host_id, const spi_bus_config_t *bus_config, int dma_chan);
esp_err_t spi_bus_free(spi_host_device_t host_id);
esp_err_t spi_bus_add_device(spi_host_device_t host_id, const spi_device_interface_config_t *dev_config, spi_device_handle_t *handle);
esp_err_t spi_bus_remove_device(spi_device_handle_t handle);
esp_err_t spi_bus_get_max_transaction_len(spi_host_device_t host_id, size_t *max_bytes);
esp_err_t spi_device_acquire_bus(spi_device_handle_t device, TickType_t wait);
void      spi_device_release_bus(spi_device_handle_t device);
esp_err_t spi_device_polling_transmit(spi_device_handle_t handle, spi_transaction_t *trans);
