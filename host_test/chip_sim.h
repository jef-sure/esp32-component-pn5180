#pragma once
/**
 * @file chip_sim.h
 * @brief Stand-ins for the ESP-IDF drivers that src/pn5180.c uses, and a PN5180 behind them
 *
 * SPI master, GPIO, esp_timer and binary semaphores are replaced by host code; behind the SPI bus
 * sits a model of the PN5180 host interface (datasheet rev. 4.0, chapter 11.4): every SPI frame
 * framed by NSS is one command, BUSY goes high with the frame and low once NSS is released and
 * the command is done, and a command with an answer is followed by a second frame that clocks
 * the answer out. RF exchanges end at once with the outcome the test queued. Time is simulated:
 * delays, sleeps and semaphore waits advance a counter instead of waiting.
 */
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "pn5180.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Pins the tests use; the model knows them as NSS, BUSY, RST and IRQ. */
#define CHIP_NSS  GPIO_NUM_5
#define CHIP_BUSY GPIO_NUM_21
#define CHIP_RST  GPIO_NUM_22
#define CHIP_IRQ  GPIO_NUM_4

/* Outcome of one RF exchange (SEND_DATA). */
typedef struct
{
    bool     card_answers;    /**< a frame comes back; without it Timer1 expires if it runs */
    uint8_t  data[600];       /**< the frame as the receiver stores it */
    size_t   len;             /**< bytes in data, reported in RX_STATUS */
    uint32_t rx_status_flags; /**< further RX_STATUS bits: collision, its position, integrity and protocol errors */
    bool     general_error;   /**< GENERAL_ERROR_IRQ is raised as well */
    bool     no_tx_irq;       /**< the transmission never ends: no TX_IRQ */
} chip_answer_t;

#define CHIP_MAX_ANSWERS 8

typedef struct
{
    /* Set by the tests */
    uint8_t       eeprom[256];          /**< EEPROM content; chip_sim_reset() writes a factory image */
    bool          busy_stuck;           /**< BUSY never goes low again */
    bool          spi_fails;            /**< spi_device_polling_transmit() returns an error */
    bool          gpio_config_fails;    /**< gpio_config() returns an error */
    bool          timer_create_fails;   /**< esp_timer_create() returns an error */
    bool          rfca_blocks;          /**< RF_ON finds an external field: RF_ACTIVE_ERROR, no field */
    uint8_t       auth_status;          /**< answer byte of MIFARE_AUTHENTICATE */
    size_t        rx_after_auth;        /**< bytes left in the receiver after a refused authentication */
    size_t        max_transfer_sz;      /**< what spi_bus_initialize() of the application asks for, 0 for 4092 */
    chip_answer_t answers[CHIP_MAX_ANSWERS];
    int           answer_count;
    int           answer_next;

    /* State of the PN5180 */
    uint32_t reg[64];
    bool     field_on;
    bool     in_reset;
    bool     busy;       /**< a frame is being clocked in */
    int64_t  busy_until; /**< BUSY stays high until then: the command is executed */
    uint8_t  tstate; /**< transceive state, RF_STATUS bits 26:24 */
    uint8_t  rf_config;
    uint8_t  rx_data[600];
    size_t   rx_len;
    bool     lpcd_active;

    /* Observed */
    int      boots;
    int      commands[256]; /**< commands executed, by opcode */
    int      frames;        /**< SPI frames */
    int      violations;    /**< frames outside NSS low or without the bus held, commands sent while BUSY was high */
    int      bus_held;      /**< spi_device_acquire_bus() minus spi_device_release_bus() */
    int      gpio_config_calls;
    int      eeprom_bytes_written;
    int      send_without_transceive;
    uint8_t  last_send[262];
    size_t   last_send_len;
    uint8_t  last_valid_bits;
    uint32_t timer1_config_at_send; /**< TIMER1_CONFIG when the last SEND_DATA started */
    uint32_t timer1_reload_at_send;
    int64_t  now_us; /**< simulated time */
} chip_sim_t;

extern chip_sim_t chip;

/** Power-on state: factory EEPROM, no field, SPI host 2 free, no answers queued, time 0. */
void chip_sim_reset(void);

/** Queues the outcome of the next RF exchange. */
void chip_answer(const uint8_t *data, size_t len, uint32_t rx_status_flags);
void chip_answer_ex(const chip_answer_t *answer);

/** True while an SPI host is initialised (a bus the driver owns must be gone after pn5180_deinit()). */
bool chip_host_initialised(spi_host_device_t host);

/** Initialises an SPI host as an application would, with max_transfer_sz from chip.max_transfer_sz. */
esp_err_t chip_app_bus_init(spi_host_device_t host);
