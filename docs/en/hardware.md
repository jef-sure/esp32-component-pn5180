# Wiring, SPI bus and IRQ

*[По-русски](../ru/hardware.md)*

The module, its pins and supply, the SPI bus of its own or shared with other devices, the IRQ pin, low power card
detection and two readers side by side.

## The module

The PN5180 talks to the host over SPI and has two more lines of its own: **BUSY**, which it raises while it executes a
command, and **IRQ**, which signals events such as the end of an RF exchange. RST resets it.

| Signal | Direction | Required | Notes |
| ------ | --------- | -------- | ----- |
| SCK, MOSI | ESP32 → PN5180 | yes | SPI mode 0, up to 7 MHz |
| MISO | PN5180 → ESP32 | yes | |
| NSS | ESP32 → PN5180 | yes | chip select, driven by the driver as a GPIO, not by the SPI peripheral |
| BUSY | PN5180 → ESP32 | yes | the driver waits for its level around every transfer |
| RST | ESP32 → PN5180 | yes | active low; `pn5180_init()` and `pn5180_reset()` pulse it |
| IRQ | PN5180 → ESP32 | no | needed only for `pn5180_lpcd_wait()`; saves CPU time otherwise |
| GPIO, AUX, REQ | | no | not used |

The common breakout takes 5 V for the transmitter and 3.3 V for the logic and the pads; ESP32 GPIOs are 3.3 V logic.
Supply both. Keep the wires short at 7 MHz; with long wires lower the clock.

The antenna is detuned by metal: a module on a metal surface or close to a metal enclosure finds cards poorly or not
at all.

## Pins

Any GPIOs will do, with these limits:

- NSS, RST, SCK and MOSI are driven by the ESP32: no input-only GPIOs (GPIO 34 to 39 on the classic ESP32).
- GPIOs of the flash and PSRAM are taken: 6 to 11 on the classic ESP32, which is why `examples/app_logic`, whose pins 6
  to 8 suit the ESP32-S3, does not run on a classic ESP32.
- Strapping pins (GPIO 0, 2, 5, 12 and 15 on the classic ESP32) work, but a level the module puts on them at power-up
  can change how the chip boots. GPIO 12, which `examples/simple_main` uses for RST, selects the flash voltage of the
  classic ESP32: if the board does not boot with the module connected, move RST to another GPIO.

`pn5180_spi_init()` and `pn5180_init()` check their pins before they touch the hardware and return `NULL` for a pin that
is not a GPIO of the chip (`GPIO_NUM_NC` among them) or for a driven pin on an input-only GPIO; the log names the pin.

## An SPI bus of its own

```c
/* SPI host, SCK, MISO, MOSI, clock */
pn5180_spi_t *spi    = pn5180_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, 7000000);
/* NSS, BUSY, RST */
pn5180_t     *pn5180 = pn5180_init(spi, GPIO_NUM_5, GPIO_NUM_21, GPIO_NUM_12);
```

`pn5180_spi_init()` initializes the bus with a DMA channel and adds the PN5180 to it. A clock above 7 MHz
(`PN5180_SPI_MAX_CLOCK_HZ`) is lowered to 7 MHz. `pn5180_deinit(pn5180, true)` frees the device and this bus.

`pn5180_init()` resets the PN5180, waits for its boot (up to 5 s), reads its firmware version and returns `NULL` when
the PN5180 does not answer or reports a firmware older than 3.4. On failure the SPI structure is left as it was: call
`pn5180_init()` again, or release it with `pn5180_spi_deinit(spi, true)`.

## Sharing the SPI bus

If the bus also serves other devices, initialize it in the program and attach the PN5180 to it:

```c
spi_bus_initialize(SPI2_HOST, &bus_config, SPI_DMA_CH_AUTO); /* your bus, your other devices */
pn5180_spi_t *spi    = pn5180_spi_attach(SPI2_HOST, 7000000);
pn5180_t     *pn5180 = pn5180_init(spi, GPIO_NUM_5, GPIO_NUM_21, GPIO_NUM_12);
```

- `pn5180_spi_attach()` works right after `spi_bus_initialize()`, with no other device on the host yet.
- The bus must carry a whole PN5180 transfer in one transaction: leave `max_transfer_sz` at its default or set it to at
  least `PN5180_MAX_BUF_SIZE` (512), and use a DMA channel, since a bus without DMA is limited to 64 bytes.
  `pn5180_spi_attach()` returns `NULL` for a host that carries less, and leaves no PN5180 device on it.
- A PN5180 command is two SPI transfers, each framed by NSS. The driver holds the bus only while NSS is low; while the
  PN5180 executes a command (BUSY high, up to milliseconds for the field to come up) other devices can use the bus.
- A bus that was attached is never freed by `pn5180_deinit()`, whatever its second argument says.

Two PN5180 on one bus each get their own `pn5180_spi_attach()` and their own NSS, BUSY and RST pins.

## IRQ pin

```c
pn5180_irq_attach(pn5180, GPIO_NUM_4);
```

Optional, called once after `pn5180_init()`. With the IRQ pin the driver sleeps until the PN5180 signals the end of an
exchange; without it the driver polls the IRQ status register over SPI, back to back for the first 5 ms, then once per
millisecond with the CPU released in between. The pin polarity is read from the EEPROM of the PN5180
(`IRQ_PIN_CONFIG`). `pn5180_irq_attach()` returns `false` for a pin that is not a GPIO of the chip, and the driver keeps
polling.

The IRQ pin is required for `pn5180_lpcd_wait()`.

## Low power card detection

In LPCD mode the PN5180 sleeps and switches its field on for a moment at a given interval; when the antenna sees a
change, a card or a piece of metal, it wakes up and raises IRQ.

```c
pn5180_irq_attach(pn5180, GPIO_NUM_4);
pn5180_lpcd_prepare(pn5180);          /* once: writes the LPCD settings to EEPROM if they differ */

while (true) {
    pn5180_lpcd_enter(pn5180, 500);   /* check for a card every 500 ms */
    if (pn5180_lpcd_wait(pn5180, -1, NULL)) {
        proto->setup_rf(proto);       /* woke up: a card or metal object is near */
        /* poll, read, halt ... */
        pn5180_set_rf_off(pn5180);
    }
}
```

- `pn5180_lpcd_prepare()` writes the LPCD settings into the EEPROM of the PN5180: a high sensitivity and self
  calibration. It writes a byte only when it differs, because the EEPROM has a limited number of write cycles; call it
  once at start-up.
- `pn5180_lpcd_enter()` takes the interval in milliseconds, 1 to 2690 (`PN5180_MAX_WAKEUP_COUNTER_MS`). On firmware
  3.A and later it first lets the PN5180 measure the reference value of the antenna, so enter LPCD with no card near
  it.
- `pn5180_lpcd_wait()` waits without touching SPI, because any SPI access ends LPCD mode; that is why it needs the IRQ
  pin. It returns `true` when the PN5180 woke up because of a card or metal, and `false` on timeout (the PN5180 is still
  in LPCD mode), on another wake-up reason, or without an IRQ pin. On wake-up the PN5180 has lost its register settings:
  `pn5180_lpcd_wait()` reloads the RF configuration, and the field is off until `setup_rf()` or `pn5180_set_rf_on()`.
- The sensitivity is high, and a metal object or a hand near the antenna may wake it too. Poll after each wake-up and
  go back to LPCD when nothing is found.
- To leave LPCD mode without a wake-up, after a timeout for example, call `pn5180_recover()`: it resets the PN5180 and
  restores the RF configuration.

## RF collision avoidance and two readers

RF collision avoidance is on by default: the PN5180 does not switch its field on while it detects another field, and
`setup_rf()` fails with the log line `RF_ON blocked by external RF field (RFCA)`. After
`pn5180_set_rfca(pn5180, false)` the field goes on regardless.

Two readers whose antennas are close have to take turns with the field: each disturbs the cards in the other's field,
and with RF collision avoidance on, a reader does not switch its field on while the other's is on. Finish each cycle
with `pn5180_set_rf_off()`. Each reader has its own `pn5180_t` and may run in its own task, also on one SPI bus; create
and delete them from one task.

## EEPROM and registers

`pn5180_read_eeprom()` reads the EEPROM of the PN5180, for example its versions:

```c
uint8_t version[2];
if (pn5180_read_eeprom(pn5180, PN5180_FIRMWARE_VERSION, version, sizeof(version))) {
    printf("firmware %d.%d\n", version[1], version[0]);
}
```

`PN5180_PRODUCT_VERSION`, `PN5180_FIRMWARE_VERSION` and `PN5180_EEPROM_VERSION` are 2 bytes each, minor first. The
firmware version read at init is also kept in `pn5180->firmware_version`, major in the high byte.

`pn5180_write_eeprom()` writes from address 16h (`PN5180_EEPROM_MIN_ADDR`) to FEh; the bytes below hold the identity of
the chip. Registers are read and written with `pn5180_read_register()`, `pn5180_write_register()`,
`pn5180_write_register_or_mask()` and `pn5180_write_register_and_mask()`; the addresses and bits are in `pn5180.h` with
the `PN5180_` prefix. A register written by the program may be overwritten by the driver at the next RF configuration;
an EEPROM byte stays.
