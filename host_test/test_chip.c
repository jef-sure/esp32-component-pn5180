/**
 * @file test_chip.c
 * @brief Host tests for src/pn5180.c, the reader layer
 *
 * The driver runs against stand-ins of the ESP-IDF SPI master, GPIO, esp_timer and semaphores,
 * with a model of the PN5180 host interface behind the SPI bus (chip_sim.c). The tests check the
 * SPI framing and BUSY handshake, boot and version checks, the field, the mapping of the
 * receiver's status to pn5180_rf_result_t, the Timer1 values of the receive timeout, MIFARE
 * authentication, recovery, EEPROM writes and the timing of the driver's waits.
 */
#include "chip_sim.h"
#include "pn5180-internal.h"
#include "pn5180.h"
#include "unity.h"
#include <stdlib.h>
#include <string.h>

static pn5180_spi_t *s_spi;
static pn5180_t     *s_dev;

void setUp(void)
{
    chip_sim_reset();
    s_spi = NULL;
    s_dev = NULL;
}

void tearDown(void)
{
    if (s_dev != NULL) {
        pn5180_deinit(s_dev, true);
    } else if (s_spi != NULL) {
        pn5180_spi_deinit(s_spi, true);
    }
}

static pn5180_t *make_device(void)
{
    s_spi = pn5180_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, 7000000);
    TEST_ASSERT_NOT_NULL(s_spi);
    s_dev = pn5180_init(s_spi, CHIP_NSS, CHIP_BUSY, CHIP_RST);
    TEST_ASSERT_NOT_NULL(s_dev);
    return s_dev;
}

// The device with the field on and the transceiver ready, as after setup_rf() of a protocol.
static pn5180_t *make_device_with_field(void)
{
    make_device();
    TEST_ASSERT_TRUE(pn5180_load_rf_config(s_dev, 0x00));
    TEST_ASSERT_TRUE(pn5180_set_rf_on(s_dev));
    return s_dev;
}

/* ---- Boot and the host interface ---- */

static void test_init_boots_and_reads_the_firmware_version(void)
{
    make_device();
    TEST_ASSERT_EQUAL_HEX16(0x0306, s_dev->firmware_version);
    TEST_ASSERT_EQUAL(1, chip.boots);
    TEST_ASSERT_TRUE(chip.frames > 0);
    // Every frame was framed by NSS with the bus held, and every command waited for BUSY.
    TEST_ASSERT_EQUAL(0, chip.violations);
    TEST_ASSERT_EQUAL(0, chip.bus_held);
    TEST_ASSERT_EQUAL(1, gpio_get_level(CHIP_NSS));
    TEST_ASSERT_EQUAL(1, gpio_get_level(CHIP_RST));
    TEST_ASSERT_NOT_NULL(s_dev->poll_timer);
}

static void test_init_refuses_firmware_below_3_4(void)
{
    chip.eeprom[PN5180_FIRMWARE_VERSION]     = 0x03;
    chip.eeprom[PN5180_FIRMWARE_VERSION + 1] = 0x03;
    s_spi = pn5180_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, 7000000);
    TEST_ASSERT_NULL(pn5180_init(s_spi, CHIP_NSS, CHIP_BUSY, CHIP_RST));

    // An EEPROM that reads FF FF is no PN5180 answering.
    chip.eeprom[PN5180_FIRMWARE_VERSION]     = 0xFF;
    chip.eeprom[PN5180_FIRMWARE_VERSION + 1] = 0xFF;
    TEST_ASSERT_NULL(pn5180_init(s_spi, CHIP_NSS, CHIP_BUSY, CHIP_RST));
}

// Pins are checked before anything is configured or sent.
static void test_init_refuses_pins_before_touching_the_hardware(void)
{
    TEST_ASSERT_NULL(pn5180_spi_init(SPI3_HOST, GPIO_NUM_NC, GPIO_NUM_19, GPIO_NUM_23, 7000000));
    TEST_ASSERT_NULL(pn5180_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_34, 7000000)); // MOSI input only
    TEST_ASSERT_FALSE(chip_host_initialised(SPI3_HOST));
    TEST_ASSERT_EQUAL(0, chip.gpio_config_calls);

    s_spi = pn5180_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, 7000000);
    TEST_ASSERT_NOT_NULL(s_spi);
    int configs = chip.gpio_config_calls;
    TEST_ASSERT_NULL(pn5180_init(s_spi, GPIO_NUM_34, CHIP_BUSY, CHIP_RST)); // NSS input only
    TEST_ASSERT_NULL(pn5180_init(s_spi, CHIP_NSS, GPIO_NUM_NC, CHIP_RST));
    TEST_ASSERT_NULL(pn5180_init(s_spi, CHIP_NSS, CHIP_BUSY, GPIO_NUM_20)); // no GPIO 20 on the ESP32
    TEST_ASSERT_NULL(pn5180_init(NULL, CHIP_NSS, CHIP_BUSY, CHIP_RST));
    TEST_ASSERT_EQUAL(configs, chip.gpio_config_calls);
    TEST_ASSERT_EQUAL(0, chip.frames);
}

static void test_init_fails_when_gpio_config_fails(void)
{
    s_spi = pn5180_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, 7000000);
    chip.gpio_config_fails = true;
    TEST_ASSERT_NULL(pn5180_init(s_spi, CHIP_NSS, CHIP_BUSY, CHIP_RST));
    TEST_ASSERT_EQUAL(0, chip.frames);
}

// IDLE IRQ after boot can be switched off in EEPROM; the driver then takes the EEPROM's word for it.
static void test_init_accepts_a_chip_without_idle_irq_after_boot(void)
{
    chip.eeprom[PN5180_IDLE_IRQ_AFTER_BOOT] = 0x00;
    make_device();
    TEST_ASSERT_EQUAL(1, chip.boots);
}

// A BUSY line that never falls ends the boot with an error after the boot timeout, not a hang.
static void test_init_gives_up_when_busy_stays_high(void)
{
    s_spi           = pn5180_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, 7000000);
    chip.busy_stuck = true;
    int64_t start   = chip.now_us;
    TEST_ASSERT_NULL(pn5180_init(s_spi, CHIP_NSS, CHIP_BUSY, CHIP_RST));
    int64_t elapsed = chip.now_us - start;
    TEST_ASSERT_TRUE(elapsed >= 5000000);
    TEST_ASSERT_TRUE(elapsed < 7000000);
}

// Without the poll timer the driver still works, with tick-length sleeps.
static void test_init_works_without_the_poll_timer(void)
{
    chip.timer_create_fails = true;
    make_device();
    TEST_ASSERT_NULL(s_dev->poll_timer);
    TEST_ASSERT_TRUE(pn5180_set_rf_on(s_dev));
}

static void test_registers_are_written_and_read(void)
{
    make_device();
    uint32_t value = 0;
    TEST_ASSERT_TRUE(pn5180_write_register(s_dev, PN5180_RX_WAIT_CONFIG, 0x12345678));
    TEST_ASSERT_TRUE(pn5180_read_register(s_dev, PN5180_RX_WAIT_CONFIG, &value));
    TEST_ASSERT_EQUAL_HEX32(0x12345678, value);
    TEST_ASSERT_TRUE(pn5180_write_register_or_mask(s_dev, PN5180_RX_WAIT_CONFIG, 0x80000001));
    TEST_ASSERT_TRUE(pn5180_write_register_and_mask(s_dev, PN5180_RX_WAIT_CONFIG, 0xFFFF0FFF));
    TEST_ASSERT_TRUE(pn5180_read_register(s_dev, PN5180_RX_WAIT_CONFIG, &value));
    TEST_ASSERT_EQUAL_HEX32(0x92340679, value);

    // IRQ_CLEAR clears the flags it names.
    chip.reg[PN5180_IRQ_STATUS] = PN5180_RX_IRQ_STAT | PN5180_TX_IRQ_STAT;
    TEST_ASSERT_TRUE(pn5180_clear_irq_status(s_dev, PN5180_TX_IRQ_STAT));
    TEST_ASSERT_EQUAL_HEX32(PN5180_RX_IRQ_STAT, pn5180_get_irq_status(s_dev));
    TEST_ASSERT_EQUAL(0, chip.violations);
}

// Addresses are checked before the command goes out; writes below 0x16 (versions) are refused.
static void test_eeprom_ranges_are_checked_before_anything_is_sent(void)
{
    make_device();
    uint8_t buffer[4] = {1, 2, 3, 4};
    int     frames    = chip.frames;
    TEST_ASSERT_FALSE(pn5180_read_eeprom(s_dev, 0xFE, buffer, 2));
    TEST_ASSERT_FALSE(pn5180_read_eeprom(s_dev, 0x10, buffer, 0));
    TEST_ASSERT_FALSE(pn5180_read_eeprom(s_dev, 0x10, NULL, 2));
    TEST_ASSERT_FALSE(pn5180_write_eeprom(s_dev, PN5180_FIRMWARE_VERSION, buffer, 2));
    TEST_ASSERT_FALSE(pn5180_write_eeprom(s_dev, 0xFE, buffer, 2));
    TEST_ASSERT_EQUAL(frames, chip.frames);

    TEST_ASSERT_TRUE(pn5180_write_eeprom(s_dev, 0x40, buffer, 4));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(buffer, &chip.eeprom[0x40], 4);
    uint8_t back[4] = {0};
    TEST_ASSERT_TRUE(pn5180_read_eeprom(s_dev, 0x40, back, 4));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(buffer, back, 4);
}

// The LPCD settings are EEPROM bytes, which have a limited number of write cycles: only bytes
// that differ are written.
static void test_lpcd_prepare_writes_only_bytes_that_differ(void)
{
    make_device();
    TEST_ASSERT_TRUE(pn5180_lpcd_prepare(s_dev));
    TEST_ASSERT_EQUAL(5, chip.eeprom_bytes_written);
    TEST_ASSERT_TRUE(pn5180_lpcd_prepare(s_dev));
    TEST_ASSERT_EQUAL(5, chip.eeprom_bytes_written);
}

/* ---- The field ---- */

static void test_rf_on_waits_the_guard_time(void)
{
    make_device();
    TEST_ASSERT_TRUE(pn5180_load_rf_config(s_dev, 0x00));
    int64_t start = chip.now_us;
    TEST_ASSERT_TRUE(pn5180_set_rf_on(s_dev));
    TEST_ASSERT_TRUE(chip.field_on);
    TEST_ASSERT_TRUE(s_dev->is_rf_on);
    TEST_ASSERT_EQUAL(1, chip.commands[0x16]);
    // 5.1 ms after the field is up, never less; RF_ON itself keeps BUSY high for 1 ms in the model,
    // and the poll timer wakes the task at most a little late.
    int64_t elapsed = chip.now_us - start;
    TEST_ASSERT_TRUE(elapsed >= 1000 + 5100);
    TEST_ASSERT_TRUE(elapsed < 1000 + 5100 + 500);
}

// The cached flag is checked against RF_STATUS: a field that is on is left alone, one that dropped
// is switched on again, and the ISO14443-4 session it carried is gone.
static void test_rf_on_checks_the_cached_flag(void)
{
    make_device_with_field();
    TEST_ASSERT_TRUE(pn5180_set_rf_on(s_dev));
    TEST_ASSERT_EQUAL(1, chip.commands[0x16]);

    s_dev->iso14443_layer4_active = true;
    chip.field_on                 = false;
    TEST_ASSERT_TRUE(pn5180_set_rf_on(s_dev));
    TEST_ASSERT_EQUAL(2, chip.commands[0x16]);
    TEST_ASSERT_TRUE(chip.field_on);
    TEST_ASSERT_FALSE(s_dev->iso14443_layer4_active);
}

// An external field keeps the PN5180 from switching its own on (RF collision avoidance).
static void test_rf_on_fails_against_an_external_field(void)
{
    make_device();
    chip.rfca_blocks = true;
    TEST_ASSERT_FALSE(pn5180_set_rf_on(s_dev));
    TEST_ASSERT_EQUAL(3, chip.commands[0x16]);
    TEST_ASSERT_FALSE(s_dev->is_rf_on);
}

static void test_rf_off_ends_the_iso_dep_session(void)
{
    make_device_with_field();
    s_dev->iso14443_layer4_active = true;
    TEST_ASSERT_TRUE(pn5180_set_rf_off(s_dev));
    TEST_ASSERT_FALSE(chip.field_on);
    TEST_ASSERT_FALSE(s_dev->is_rf_on);
    TEST_ASSERT_FALSE(s_dev->iso14443_layer4_active);
}

// pn5180_recover() resets the PN5180 and brings back the RF configuration and the field.
static void test_recover_restores_rf_config_and_field(void)
{
    make_device();
    TEST_ASSERT_TRUE(pn5180_load_rf_config(s_dev, 0x0D));
    TEST_ASSERT_TRUE(pn5180_set_rf_on(s_dev));
    TEST_ASSERT_TRUE(pn5180_recover(s_dev));
    TEST_ASSERT_EQUAL(2, chip.boots);
    TEST_ASSERT_EQUAL_HEX8(0x0D, chip.rf_config);
    TEST_ASSERT_TRUE(chip.field_on);
    TEST_ASSERT_TRUE(s_dev->is_rf_on);
}

/* ---- RF exchanges ---- */

static void test_rf_transceive_returns_the_answer(void)
{
    make_device_with_field();
    const uint8_t tx[3]     = {0x30, 0x04, 0x99};
    const uint8_t answer[5] = {1, 2, 3, 4, 5};
    chip_answer(answer, sizeof(answer), 0);

    uint8_t  rx[16];
    size_t   rx_len    = 0;
    uint32_t rx_status = 0;
    TEST_ASSERT_EQUAL(PN5180_RF_OK, pn5180_rf_transceive(s_dev, tx, sizeof(tx), 7, rx, sizeof(rx), &rx_len, 5000, &rx_status));
    TEST_ASSERT_EQUAL(5, rx_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(answer, rx, 5);
    TEST_ASSERT_EQUAL(5, rx_status & PN5180_RX_BYTES_RECEIVED_MASK);
    TEST_ASSERT_EQUAL(sizeof(tx), chip.last_send_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tx, chip.last_send, sizeof(tx));
    TEST_ASSERT_EQUAL(7, chip.last_valid_bits);
    // Timer1 is stopped again, the flags are cleared.
    TEST_ASSERT_EQUAL_HEX32(0, chip.reg[PN5180_TIMER1_CONFIG]);
    TEST_ASSERT_EQUAL_HEX32(0, chip.reg[PN5180_IRQ_STATUS]);
    TEST_ASSERT_EQUAL(0, chip.send_without_transceive);
    TEST_ASSERT_EQUAL(0, chip.violations);
}

// RX_STATUS decides the result: collision, integrity and protocol errors, a general error, and
// an answer larger than the buffer.
static void test_rf_transceive_maps_the_receiver_status(void)
{
    make_device_with_field();
    const uint8_t tx[1]      = {0x26};
    uint8_t       answer[10] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9};
    uint8_t       rx[4];
    size_t        rx_len    = 0;
    uint32_t      rx_status = 0;

    chip_answer(answer, 3, PN5180_RX_COLLISION_DETECTED | (5u << PN5180_RX_COLL_POS_START));
    TEST_ASSERT_EQUAL(PN5180_RF_COLLISION, pn5180_rf_transceive(s_dev, tx, 1, 7, rx, sizeof(rx), &rx_len, 5000, &rx_status));
    TEST_ASSERT_EQUAL(3, rx_len);
    TEST_ASSERT_EQUAL(5, (rx_status >> PN5180_RX_COLL_POS_START) & PN5180_RX_COLL_POS_MASK);

    // After a collision the first bytes are enough: a longer frame is cut to the buffer.
    chip_answer(answer, 10, PN5180_RX_COLLISION_DETECTED);
    TEST_ASSERT_EQUAL(PN5180_RF_COLLISION, pn5180_rf_transceive(s_dev, tx, 1, 7, rx, sizeof(rx), &rx_len, 5000, NULL));
    TEST_ASSERT_EQUAL(4, rx_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(answer, rx, 4);

    // A CRC error still delivers the bytes, which the caller may look at (a 4-bit ACK or NAK).
    chip_answer(answer, 1, PN5180_RX_DATA_INTEGRITY_ERROR);
    TEST_ASSERT_EQUAL(PN5180_RF_RX_ERROR, pn5180_rf_transceive(s_dev, tx, 1, 0, rx, sizeof(rx), &rx_len, 5000, NULL));
    TEST_ASSERT_EQUAL(1, rx_len);

    chip_answer(answer, 2, PN5180_RX_PROTOCOL_ERROR);
    TEST_ASSERT_EQUAL(PN5180_RF_RX_ERROR, pn5180_rf_transceive(s_dev, tx, 1, 0, rx, sizeof(rx), &rx_len, 5000, NULL));

    // After a general error the receive buffer is not trustworthy: nothing is read.
    chip_answer_t general = {.card_answers = true, .len = 2, .general_error = true};
    chip_answer_ex(&general);
    int reads = chip.commands[0x0A];
    TEST_ASSERT_EQUAL(PN5180_RF_RX_ERROR, pn5180_rf_transceive(s_dev, tx, 1, 0, rx, sizeof(rx), &rx_len, 5000, NULL));
    TEST_ASSERT_EQUAL(0, rx_len);
    TEST_ASSERT_EQUAL(reads, chip.commands[0x0A]);

    // A complete frame larger than the buffer is an overflow, not a cut answer.
    chip_answer(answer, 10, 0);
    TEST_ASSERT_EQUAL(PN5180_RF_OVERFLOW, pn5180_rf_transceive(s_dev, tx, 1, 0, rx, sizeof(rx), &rx_len, 5000, NULL));
    TEST_ASSERT_EQUAL(0, rx_len);
}

// No answer: Timer1 ends the wait at once, the receiver is stopped and Timer1 switched off.
static void test_rf_transceive_times_out_on_timer1(void)
{
    make_device_with_field();
    const uint8_t tx[1] = {0x26};
    uint8_t       rx[4];
    size_t        rx_len = 7;
    int64_t       start  = chip.now_us;
    TEST_ASSERT_EQUAL(PN5180_RF_TIMEOUT, pn5180_rf_transceive(s_dev, tx, 1, 7, rx, sizeof(rx), &rx_len, 5000, NULL));
    TEST_ASSERT_EQUAL(0, rx_len);
    TEST_ASSERT_TRUE(chip.timer1_config_at_send & PN5180_TIMER1_CONFIG_ENABLE);
    TEST_ASSERT_EQUAL_HEX32(0, chip.reg[PN5180_TIMER1_CONFIG]);
    TEST_ASSERT_EQUAL(PN5180_TS_IDLE, chip.tstate);
    TEST_ASSERT_TRUE(chip.now_us - start < 5000);
}

// Without Timer1 the host-side deadline ends the wait: never before the timeout.
static void test_rf_transceive_times_out_on_the_host_without_timer1(void)
{
    make_device_with_field();
    pn5180_set_hw_rx_timeout(s_dev, false);
    const uint8_t tx[1]    = {0x26};
    uint8_t       rx[4];
    size_t        rx_len   = 0;
    int           multiple = chip.commands[0x03];
    int64_t       start    = chip.now_us;
    TEST_ASSERT_EQUAL(PN5180_RF_TIMEOUT, pn5180_rf_transceive(s_dev, tx, 1, 7, rx, sizeof(rx), &rx_len, 5000, NULL));
    TEST_ASSERT_EQUAL(multiple, chip.commands[0x03]); // Timer1 not armed
    TEST_ASSERT_TRUE(chip.now_us - start >= 5000);
    TEST_ASSERT_EQUAL(PN5180_TS_IDLE, chip.tstate);
}

static void arm_and_check(uint32_t timeout_us, uint32_t reload, bool prescaler)
{
    const uint8_t tx[1] = {0x26};
    uint8_t       rx[4];
    size_t        rx_len = 0;
    TEST_ASSERT_EQUAL(PN5180_RF_TIMEOUT, pn5180_rf_transceive(s_dev, tx, 1, 7, rx, sizeof(rx), &rx_len, timeout_us, NULL));
    uint32_t expected = PN5180_TIMER1_CONFIG_START_ON_TX_ENDED | PN5180_TIMER1_CONFIG_STOP_ON_RX_STARTED | PN5180_TIMER1_CONFIG_ENABLE;
    if (prescaler) {
        expected |= PN5180_TIMER1_CONFIG_MODE_SEL | PN5180_TIMER1_CONFIG_PRESCALE_53KHZ;
    }
    TEST_ASSERT_EQUAL_HEX32(expected, chip.timer1_config_at_send);
    TEST_ASSERT_EQUAL_UINT32(reload, chip.timer1_reload_at_send);
}

// Timer1 counts 13.56 MHz up to 77 ms and 53 kHz above, with a 20-bit reload value.
static void test_timer1_reload_follows_the_timeout(void)
{
    make_device_with_field();
    arm_and_check(1, 13, false);              // 13.56 ticks, rounded down
    arm_and_check(5000, 67800, false);        // 5 ms
    arm_and_check(77000, 1044120, false);     // the last value without prescaler
    arm_and_check(77001, 4081, true);         // 53 ticks per ms
    arm_and_check(4949000, 262297, true);     // FWT of FWI 14
    arm_and_check(19000000, 1007000, true);   // the cap of an ISO-DEP wait
    arm_and_check(30000000, 0xFFFFF, true);   // above about 19.7 s: the 20-bit maximum
}

// A frame without an answer (HLTA) is done when the transmission ends; one that never ends is fatal.
static void test_transmit_only_frame(void)
{
    make_device_with_field();
    const uint8_t hlta[2]  = {0x50, 0x00};
    int           multiple = chip.commands[0x03];
    TEST_ASSERT_EQUAL(PN5180_RF_OK, pn5180_rf_transceive(s_dev, hlta, 2, 0, NULL, 0, NULL, 0, NULL));
    TEST_ASSERT_EQUAL(multiple, chip.commands[0x03]); // no receive timeout to arm
    TEST_ASSERT_EQUAL_HEX8_ARRAY(hlta, chip.last_send, 2);

    chip_answer_t stuck = {.no_tx_irq = true};
    chip_answer_ex(&stuck);
    TEST_ASSERT_EQUAL(PN5180_RF_FATAL, pn5180_rf_transceive(s_dev, hlta, 2, 0, NULL, 0, NULL, 0, NULL));
}

// A reader that does not take its commands is fatal, not a missing card.
static void test_rf_transceive_reports_spi_failures_as_fatal(void)
{
    make_device_with_field();
    const uint8_t tx[1] = {0x26};
    uint8_t       rx[4];
    size_t        rx_len = 0;
    chip.spi_fails       = true;
    TEST_ASSERT_EQUAL(PN5180_RF_FATAL, pn5180_rf_transceive(s_dev, tx, 1, 7, rx, sizeof(rx), &rx_len, 5000, NULL));
    chip.spi_fails  = false;
    chip.busy_stuck = true;
    TEST_ASSERT_EQUAL(PN5180_RF_FATAL, pn5180_rf_transceive(s_dev, tx, 1, 7, rx, sizeof(rx), &rx_len, 5000, NULL));
    chip.busy_stuck = false;
    chip.busy       = false;
    TEST_ASSERT_EQUAL(PN5180_RF_FATAL, pn5180_rf_transceive(s_dev, tx, 0, 7, rx, sizeof(rx), &rx_len, 5000, NULL));
    TEST_ASSERT_EQUAL(PN5180_RF_FATAL, pn5180_rf_transceive(NULL, tx, 1, 7, rx, sizeof(rx), &rx_len, 5000, NULL));
}

// With the IRQ pin the wait sleeps on the pin; the flags it waits for are routed to it.
static void test_rf_transceive_with_the_irq_pin(void)
{
    make_device_with_field();
    TEST_ASSERT_TRUE(pn5180_irq_attach(s_dev, CHIP_IRQ));
    TEST_ASSERT_TRUE(s_dev->irq_active_high);
    TEST_ASSERT_FALSE(pn5180_irq_attach(s_dev, CHIP_IRQ)); // once only

    const uint8_t tx[1]     = {0x26};
    const uint8_t answer[2] = {0x44, 0x00};
    uint8_t       rx[4];
    size_t        rx_len = 0;
    chip_answer(answer, 2, 0);
    TEST_ASSERT_EQUAL(PN5180_RF_OK, pn5180_rf_transceive(s_dev, tx, 1, 7, rx, sizeof(rx), &rx_len, 5000, NULL));
    TEST_ASSERT_EQUAL(2, rx_len);
    TEST_ASSERT_TRUE(chip.reg[PN5180_IRQ_ENABLE] & PN5180_RX_IRQ_STAT);
    TEST_ASSERT_EQUAL(PN5180_RF_TIMEOUT, pn5180_rf_transceive(s_dev, tx, 1, 7, rx, sizeof(rx), &rx_len, 5000, NULL));
}

static void test_irq_attach_refuses_what_is_no_gpio(void)
{
    make_device();
    TEST_ASSERT_FALSE(pn5180_irq_attach(s_dev, GPIO_NUM_NC));
    TEST_ASSERT_FALSE(pn5180_irq_attach(NULL, CHIP_IRQ));
    TEST_ASSERT_NULL(s_dev->irq_sem);
}

/* ---- MIFARE authentication ---- */

static void test_mifare_authentication_status(void)
{
    make_device_with_field();
    const uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t uid[4] = {0xDE, 0xAD, 0xBE, 0xEF};

    chip.auth_status = 0x00;
    TEST_ASSERT_EQUAL(PN5180_MIFARE_AUTH_OK, pn5180_mifare_authenticate(s_dev, 4, key, 0x60, uid));
    TEST_ASSERT_EQUAL(PN5180_MIFARE_AUTH_OK, s_dev->iso14443_last_auth_status);
    TEST_ASSERT_TRUE(chip.reg[PN5180_SYSTEM_CONFIG] & PN5180_SYSTEM_CONFIG_MFC_CRYPTO_ON);

    // A refused key: Crypto1 off, the transceiver idle, the receiver drained.
    chip.auth_status   = 0x01;
    chip.rx_after_auth = 3;
    int reads          = chip.commands[0x0A];
    TEST_ASSERT_EQUAL(PN5180_MIFARE_AUTH_REFUSED, pn5180_mifare_authenticate(s_dev, 4, key, 0x61, uid));
    TEST_ASSERT_EQUAL(PN5180_MIFARE_AUTH_REFUSED, s_dev->iso14443_last_auth_status);
    TEST_ASSERT_FALSE(chip.reg[PN5180_SYSTEM_CONFIG] & PN5180_SYSTEM_CONFIG_MFC_CRYPTO_ON);
    TEST_ASSERT_EQUAL(PN5180_TS_IDLE, chip.tstate);
    TEST_ASSERT_EQUAL(reads + 1, chip.commands[0x0A]);

    chip.auth_status = 0x02;
    TEST_ASSERT_EQUAL(PN5180_MIFARE_AUTH_NO_ANSWER, pn5180_mifare_authenticate(s_dev, 4, key, 0x60, uid));

    // Nothing is sent for an invalid key type or missing key; an SPI failure has no card status.
    int auths = chip.commands[0x0C];
    TEST_ASSERT_EQUAL(PN5180_MIFARE_AUTH_NONE, pn5180_mifare_authenticate(s_dev, 4, key, 0x62, uid));
    TEST_ASSERT_EQUAL(PN5180_MIFARE_AUTH_NONE, pn5180_mifare_authenticate(s_dev, 4, NULL, 0x60, uid));
    TEST_ASSERT_EQUAL(auths, chip.commands[0x0C]);
    chip.spi_fails = true;
    TEST_ASSERT_TRUE(pn5180_mifare_authenticate(s_dev, 4, key, 0x60, uid) < PN5180_MIFARE_AUTH_NONE);
    chip.spi_fails = false;
}

/* ---- SPI bus ---- */

// The application initialised the host; ESP-IDF tells the transaction size only once a device is on it.
static void test_spi_attach_to_a_host_the_application_initialised(void)
{
    TEST_ASSERT_EQUAL(ESP_OK, chip_app_bus_init(SPI2_HOST));
    s_spi = pn5180_spi_attach(SPI2_HOST, 10000000);
    TEST_ASSERT_NOT_NULL(s_spi);
    TEST_ASSERT_EQUAL(PN5180_SPI_MAX_CLOCK_HZ, s_spi->clock_speed_hz); // lowered to the PN5180 maximum
    TEST_ASSERT_FALSE(s_spi->owns_bus);
    s_dev = pn5180_init(s_spi, CHIP_NSS, CHIP_BUSY, CHIP_RST);
    TEST_ASSERT_NOT_NULL(s_dev);
    pn5180_deinit(s_dev, true);
    s_dev = NULL;
    s_spi = NULL;
    TEST_ASSERT_TRUE(chip_host_initialised(SPI2_HOST)); // not the driver's bus to free
}

static void test_spi_attach_refuses_a_host_that_cannot_carry_a_frame(void)
{
    chip.max_transfer_sz = 64;
    TEST_ASSERT_EQUAL(ESP_OK, chip_app_bus_init(SPI2_HOST));
    TEST_ASSERT_NULL(pn5180_spi_attach(SPI2_HOST, 7000000));
    TEST_ASSERT_EQUAL(ESP_OK, spi_bus_free(SPI2_HOST)); // the device was removed again

    TEST_ASSERT_NULL(pn5180_spi_attach(SPI2_HOST, 7000000)); // not initialised
    TEST_ASSERT_NULL(pn5180_spi_attach(SPI_HOST_MAX, 7000000));
}

// A bus the driver created is freed with the device when asked.
static void test_deinit_frees_the_bus_the_driver_created(void)
{
    make_device();
    TEST_ASSERT_TRUE(chip_host_initialised(SPI3_HOST));
    pn5180_deinit(s_dev, true);
    s_dev = NULL;
    s_spi = NULL;
    TEST_ASSERT_FALSE(chip_host_initialised(SPI3_HOST));
}

/* ---- Waiting ---- */

// The driver's waits never end early and, with the poll timer, end close to the time asked for.
static void test_waits_are_never_short(void)
{
    make_device();
    const uint32_t waits[] = {50, 199, 200, 300, 5100, 15000, 100000};
    for (size_t i = 0; i < sizeof(waits) / sizeof(waits[0]); i++) {
        int64_t start = chip.now_us;
        pn5180_sleep_us(s_dev, waits[i]);
        int64_t elapsed = chip.now_us - start;
        TEST_ASSERT_TRUE(elapsed >= waits[i]);
        TEST_ASSERT_TRUE(elapsed <= (int64_t)waits[i] + 50);

        start = chip.now_us;
        pn5180_delay_us(waits[i]);
        TEST_ASSERT_TRUE(chip.now_us - start >= waits[i]);
    }
    int64_t start = chip.now_us;
    pn5180_delay_ms(3);
    TEST_ASSERT_TRUE(chip.now_us - start >= 3000);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_init_boots_and_reads_the_firmware_version);
    RUN_TEST(test_init_refuses_firmware_below_3_4);
    RUN_TEST(test_init_refuses_pins_before_touching_the_hardware);
    RUN_TEST(test_init_fails_when_gpio_config_fails);
    RUN_TEST(test_init_accepts_a_chip_without_idle_irq_after_boot);
    RUN_TEST(test_init_gives_up_when_busy_stays_high);
    RUN_TEST(test_init_works_without_the_poll_timer);
    RUN_TEST(test_registers_are_written_and_read);
    RUN_TEST(test_eeprom_ranges_are_checked_before_anything_is_sent);
    RUN_TEST(test_lpcd_prepare_writes_only_bytes_that_differ);
    RUN_TEST(test_rf_on_waits_the_guard_time);
    RUN_TEST(test_rf_on_checks_the_cached_flag);
    RUN_TEST(test_rf_on_fails_against_an_external_field);
    RUN_TEST(test_rf_off_ends_the_iso_dep_session);
    RUN_TEST(test_recover_restores_rf_config_and_field);
    RUN_TEST(test_rf_transceive_returns_the_answer);
    RUN_TEST(test_rf_transceive_maps_the_receiver_status);
    RUN_TEST(test_rf_transceive_times_out_on_timer1);
    RUN_TEST(test_rf_transceive_times_out_on_the_host_without_timer1);
    RUN_TEST(test_timer1_reload_follows_the_timeout);
    RUN_TEST(test_transmit_only_frame);
    RUN_TEST(test_rf_transceive_reports_spi_failures_as_fatal);
    RUN_TEST(test_rf_transceive_with_the_irq_pin);
    RUN_TEST(test_irq_attach_refuses_what_is_no_gpio);
    RUN_TEST(test_mifare_authentication_status);
    RUN_TEST(test_spi_attach_to_a_host_the_application_initialised);
    RUN_TEST(test_spi_attach_refuses_a_host_that_cannot_carry_a_frame);
    RUN_TEST(test_deinit_frees_the_bus_the_driver_created);
    RUN_TEST(test_waits_are_never_short);
    return UNITY_END();
}
