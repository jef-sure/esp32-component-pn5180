# Getting started

*[По-русски](../ru/getting-started.md)*

From an empty ESP-IDF project to a program that prints the UID of every card in the field and the URI stored on it.

## What you need

- A PN5180 module. The common breakout has the antenna on the board and takes 5 V for the transmitter and 3.3 V for
  the logic.
- An ESP32 chip with a free SPI host and six GPIOs (seven with the IRQ pin). The examples are for the ESP32 and the
  ESP32-S3.
- ESP-IDF 5.0.4 or later, 6.x included. 5.0.4 is the first 5.0 release with `spi_bus_get_max_transaction_len()`, which
  the driver needs.
- Cards: ISO14443A (MIFARE Classic, Ultralight, NTAG, DESFire and other ISO14443-4 cards, phones) or ISO15693 (ICODE
  SLIX and other vicinity tags).

## 1. Add the component

From the ESP Component Registry, in the directory of your project:

```sh
idf.py add-dependency "jef-sure/pn5180^0.8.2"
```

This writes the dependency into `main/idf_component.yml`; the component manager fetches the component at the next
build. Instead of the registry you can copy this repository into `components/pn5180` of your project.

To start from a working program instead, create a project from an example:

```sh
idf.py create-project-from-example "jef-sure/pn5180:simple_main"
```

The examples are described in [simple_main](../../examples/simple_main/README.md),
[app_logic](../../examples/app_logic/README.md) and [ndef](../../examples/ndef/README.md).

## 2. Wire the module

| PN5180 | ESP32 (`simple_main`) | ESP32-S3 (`app_logic`) | What it is |
| ------ | --------------------- | ---------------------- | ---------- |
| 5V     | 5V                    | 5V                     | transmitter supply |
| 3.3V   | 3V3                   | 3V3                    | logic supply |
| GND    | GND                   | GND                    | |
| RST    | 12                    | 4                      | hardware reset, active low |
| NSS    | 5                     | 9                      | SPI chip select, active low, driven by the driver |
| MOSI   | 23                    | 7                      | SPI data to the PN5180 |
| MISO   | 19                    | 8                      | SPI data from the PN5180 |
| SCK    | 18                    | 6                      | SPI clock |
| BUSY   | 21                    | 5                      | the PN5180 is busy |
| IRQ    | not connected         | not connected          | optional, see [IRQ pin](hardware.md#irq-pin) |

Both examples use `SPI3_HOST`. Any GPIOs will do, with two limits: NSS, RST, SCK and MOSI are driven by the ESP32, so
they cannot be input-only GPIOs (GPIO 34 to 39 on the classic ESP32), and the GPIOs of the flash and PSRAM are taken (6
to 11 on the classic ESP32). The driver checks its pins and refuses one it cannot use, with a log line that names it.
More on power, pins and the SPI bus is in [Wiring, SPI bus and IRQ](hardware.md).

## 3. The first program

`main/main.c`:

```c
#include <stdio.h>
#include <stdlib.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pn5180.h"
#include "pn5180-14443.h"
#include "pn5180-ndef.h"

static const char *TAG = "nfc";

void app_main(void)
{
    /* SPI host, SCK, MISO, MOSI, clock */
    pn5180_spi_t *spi = pn5180_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, 7000000);
    /* NSS, BUSY, RST */
    pn5180_t *pn5180 = spi ? pn5180_init(spi, GPIO_NUM_5, GPIO_NUM_21, GPIO_NUM_12) : NULL;
    if (pn5180 == NULL) {
        ESP_LOGE(TAG, "PN5180 not found");
        return;
    }
    /* Most cards one poll enumerates, 0 for the default of 14 */
    pn5180_proto_t *nfc = pn5180_14443_init(pn5180, 0);

    while (true) {
        /* Restart the field so that cards halted by the previous scan answer again. */
        pn5180_set_rf_off(pn5180);
        pn5180_delay_us(PN5180_RF_OFF_TIME_US); /* 5.1 ms */
        nfc->setup_rf(nfc);

        pn5180_poll_status_t status;
        pn5180_uids_array_t *cards = pn5180_14443_get_all_uids_ex(nfc, &status);
        for (int i = 0; cards != NULL && i < cards->uids_count; i++) {
            pn5180_uid_t *card = &cards->uids[i];
            printf("UID:");
            for (int j = 0; j < card->uid_length; j++) {
                printf(" %02X", card->uid[j]);
            }
            printf("\n");

            if (!nfc->select_by_uid(nfc, card)) {
                continue;
            }
            int blocks = 0, block_size = 0;
            if (nfc->detect_card_type_and_capacity(pn5180, card, &blocks, &block_size)) {
                nfc->select_by_uid(nfc, card); /* detection asked for a new select */
            }

            pn5180_ndef_message_parsed_t *msg = NULL;
            if (pn5180_ndef_read_card_auto(nfc, card, &msg) == PN5180_NDEF_OK) {
                for (size_t r = 0; r < msg->record_count; r++) {
                    char uri[256];
                    if (pn5180_ndef_extract_uri(&msg->records[r], uri, sizeof(uri)) > 0) {
                        printf("  URI: %s\n", uri);
                    }
                }
                pn5180_ndef_free_parsed_message(msg);
            }
            nfc->halt(nfc);
        }
        free(cards);
        if (status == PN5180_POLL_TRANSPORT_ERROR) {
            pn5180_recover(pn5180);
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }
}
```

What it does, step by step:

1. `pn5180_spi_init()` initializes the SPI bus and adds the PN5180 as a device on it. `pn5180_init()` resets the
   PN5180, waits for its boot and checks its firmware. Either returns `NULL` when something is wrong; the log says
   what.
2. `pn5180_14443_init()` creates the protocol object for ISO14443A. Everything about cards goes through it.
3. Each pass of the loop switches the field off for 5.1 ms and on again with `setup_rf()`. Cards found by a poll are
   halted, and a halted card answers a new poll only after the field was off.
4. `pn5180_14443_get_all_uids_ex()` returns every card in the field, and the status says why nothing came back.
5. For each card: `select_by_uid()` wakes it up and selects it, `detect_card_type_and_capacity()` finds its type and
   memory size, `pn5180_ndef_read_card_auto()` reads its NDEF message, `halt()` ends the session.
6. The array of cards is freed with `free()`, the NDEF message with `pn5180_ndef_free_parsed_message()`.
7. `PN5180_POLL_TRANSPORT_ERROR` means the PN5180 itself did not respond: `pn5180_recover()` resets it.

With the registry, the component manager adds `pn5180` to the requirements of `main` by itself. With a copy in
`components/`, add `pn5180` to `REQUIRES` or `PRIV_REQUIRES` of `main/CMakeLists.txt` if it names any; a `main` that
names none sees every component.

## 4. Build and run

```sh
idf.py set-target esp32
idf.py build flash monitor
```

After the boot the log shows nothing until a card comes near the antenna, then a line `UID: 04 A2 ...` per card, and
`URI: ...` for a card that carries a URI. A card that stays in the field shows up on every pass.

When nothing appears, see [Troubleshooting](troubleshooting.md): most first problems are wiring, power or a BUSY line
that does not follow the SPI transfers.

## Next steps

- [How the driver works](how-it-works.md): the objects, the life of a card session, timing, memory and tasks.
- [Finding cards](polling.md): poll statuses, several cards in the field, phones with random UIDs.
- [ISO14443A cards](iso14443a.md), [ISO14443-4 and APDUs](iso14443-4.md), [ISO15693 tags](iso15693.md).
- [NDEF](ndef.md): reading, records, writing.
- [API reference](api.md).
