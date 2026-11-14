# simple_main

The smallest scanning loop: every 2 seconds it polls for ISO14443A cards and then for ISO15693 tags and prints the UID
and the signal strength (AGC) of each card it finds. It shows the start-up of the driver, both protocol objects and a
poll with a field reset; it does not select or read cards.

## Hardware

A classic ESP32 and a PN5180 module on `SPI3_HOST`:

| PN5180 | ESP32 |
| ------ | ----- |
| RST    | GPIO 12 |
| NSS    | GPIO 5 |
| MOSI   | GPIO 23 |
| MISO   | GPIO 19 |
| SCK    | GPIO 18 |
| BUSY   | GPIO 21 |
| 5V, 3.3V, GND | 5V, 3V3, GND |

The pins are the `enum` at the top of `main/simple_main.c`; change them there for another board. GPIO 12 selects the
flash voltage of the classic ESP32 at power-up: if the board does not boot with the module connected, move RST to
another GPIO.

## Build

As a project of its own, with the component from the registry:

```sh
idf.py create-project-from-example "jef-sure/pn5180:simple_main"
cd simple_main
idf.py set-target esp32
idf.py build flash monitor
```

Inside the repository, `idf.py -C examples/simple_main build` builds it against the repository itself.

## What it prints

```text
Hello world!
I (...) main: PN5180 initialized successfully
I (...) main: Product version: x.y
I (...) main: Firmware version: x.y
I (...) main: EEPROM version: x.y
I (...) main: ISO14443 protocol initialized successfully
I (...) main: ISO15693 protocol initialized successfully
I (...) main: Scanning for ISO14443A cards...
I (...) main: Found 2 card(s)
ISO14443A card 1 UID: 04 A2 3B 1A 7C 61 80 | AGC: 412
ISO14443A card 2 UID: 3E 91 0C 5D | AGC: 437
I (...) main: Scanning for ISO15693 cards...
I (...) main: No cards found
```

The versions and the UIDs are those of your module and cards.

## How it works

1. `pn5180_spi_init()` and `pn5180_init()` bring the PN5180 up; the versions are read from its EEPROM with
   `pn5180_read_eeprom()`.
2. `pn5180_14443_init()` and `pn5180_15693_init()` create the two protocol objects.
3. Each scan switches the field off for `PN5180_RF_OFF_TIME_US`, calls `setup_rf()` of the protocol and
   `get_all_uids()`, prints the cards and frees the array.
4. `vTaskDelay()` pauses 2 seconds between the passes.

Next: [app_logic](../app_logic/README.md) selects the cards, identifies them and reads their NDEF or their blocks. The
documentation starts at [Getting started](../../docs/en/getting-started.md).
