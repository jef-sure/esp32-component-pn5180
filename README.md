# PN5180 ESP-IDF Component

ESP-IDF driver for the NXP PN5180 NFC frontend over SPI: find ISO14443A and ISO15693 cards, read and write NDEF (NTAG / Ultralight, MIFARE Classic, Type 4, ISO15693), access MIFARE Classic blocks, and exchange APDUs with ISO14443-4 cards in reader mode.

- [Quick Start](#quick-start)
- [Choosing A Protocol](#choosing-a-protocol)
- [Common Tasks](#common-tasks)
- [IRQ Pin And Shared SPI Bus](#irq-pin-and-shared-spi-bus)
- [Troubleshooting](#troubleshooting)
- [Reliability And Recovery](#reliability-and-recovery)
- [Reference](#reference)

## Quick Start

### 1. Add the component

From the ESP Component Registry:

```sh
idf.py add-dependency "jef-sure/esp32-component-pn5180^0.4.2"
```

Or copy this repository to `components/` in your project. ESP-IDF 5.x or 6.0 is required.

### 2. Wire the module

The PN5180 needs SPI (SCK, MOSI, MISO, NSS), the BUSY line and RST. ESP32 GPIOs are 3.3 V logic; on the common breakout the module is supplied with both 5 V (transmitter) and 3.3 V. The IRQ line is optional.

| Signal | `examples/simple_main` (ESP32) | `examples/app_logic` (ESP32-S3) | Description |
| ------ | ------------------------------ | ------------------------------- | ----------- |
| RST    | 12 | 4 | Hardware reset (active low) |
| SCK    | 18 | 6 | SPI clock |
| MOSI   | 23 | 7 | SPI data to PN5180 |
| MISO   | 19 | 8 | SPI data from PN5180 |
| NSS    | 5  | 9 | SPI chip select (active low), driven by the driver |
| BUSY   | 21 | 5 | PN5180 busy indicator |

Both examples use `SPI3_HOST`. Adjust the GPIO numbers and the SPI host to your board.

### 3. Read cards

A complete `app_main()` that prints the UID of every ISO14443A card it sees and any URI stored on it:

```c
#include <stdio.h>
#include <stdlib.h>

#include "esp_log.h"
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
    pn5180_proto_t *nfc = pn5180_14443_init(pn5180);

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
        pn5180_delay_ms(250);
    }
}
```

## Choosing A Protocol

Each RF protocol is a `pn5180_proto_t` object with the same set of callbacks; one PN5180 can serve both, one at a time.

| | ISO14443A | ISO15693 |
|---|---|---|
| Create | `pn5180_14443_init(pn5180)` | `pn5180_15693_init(pn5180, PN5180_15693_26KASK100)` |
| Cards | MIFARE Classic, Ultralight, NTAG21x, DESFire and other ISO14443-4 cards | ICODE SLIX and other vicinity tags |
| Range | a few centimetres | longer |
| Authentication | MIFARE Classic keys (`authenticate`) | none |
| NDEF | Type 2, MIFARE Classic, Type 4 | Type 5 |
| Header | `pn5180-14443.h` | `pn5180-15693.h` |

Every protocol is then used the same way through its callbacks: `setup_rf`, `get_all_uids`, `select_by_uid`, `detect_card_type_and_capacity`, `block_read`, `block_write`, `authenticate`, `halt`. The object is allocated on the heap; release it with `free()`.

- **Switching protocols.** Call the other protocol's `setup_rf()`: it loads its own RF configuration. Switch the field off for at least 5.1 ms between scans (`pn5180_set_rf_off()`, then `pn5180_delay_us(PN5180_RF_OFF_TIME_US)`), so that cards return to their idle state.
- **ISO15693 modulation.** `PN5180_15693_26KASK100` suits most tags; the inventory tries ASK 10 % first and falls back to ASK 100 % on its own.

## Sample Apps

- `examples/simple_main` — minimal scanning loop for ISO14443A and ISO15693 on a classic ESP32.
- `examples/app_logic` — a fuller application on ESP32-S3: card classification, NDEF first and raw block dump as fallback, MIFARE Classic authentication with a key list.
- `examples/ndef` — NDEF parsing snippets (not a standalone project).

## Common Tasks

### Read NDEF

`pn5180_ndef_read_card_auto()` picks the mapping from the detected card type: Type 2 for Ultralight / NTAG, the MIFARE Application Directory for Classic, Type 4 for ISO14443-4 cards and Type 5 for ISO15693. The card must be selected and its type detected (see the Quick Start).

```c
#include "pn5180-ndef.h"

pn5180_ndef_message_parsed_t *msg = NULL;
pn5180_ndef_result_t result = pn5180_ndef_read_card_auto(proto, card, &msg);
if (result == PN5180_NDEF_OK) {
    for (size_t i = 0; i < msg->record_count; i++) {
        const pn5180_ndef_record_t *rec = &msg->records[i];
        char uri[256];
        const uint8_t *text;
        size_t text_len;
        char lang[64];
        if (pn5180_ndef_extract_uri(rec, uri, sizeof(uri)) > 0) {
            printf("URI: %s\n", uri);
        } else if (pn5180_ndef_extract_text(rec, &text, &text_len, lang, NULL)) {
            printf("Text (%s): %.*s\n", lang, (int)text_len, text);
        }
    }
    pn5180_ndef_free_parsed_message(msg);
} else {
    ESP_LOGW(TAG, "%s", pn5180_ndef_result_to_string(result));
}
```

`PN5180_NDEF_ERR_NO_NDEF` means that the card works but carries no message; `PN5180_NDEF_ERR_UNSUPPORTED` that the card type has no NDEF mapping here; `PN5180_NDEF_ERR_ACCESS_DENIED` that a Type 4 tag protects its NDEF file against reading.

### Write a URI to an NTAG

```c
pn5180_ndef_record_t  record;
pn5180_ndef_record_t  storage[1];
pn5180_ndef_message_t message;
uint8_t               payload[128];

pn5180_ndef_make_uri_record(&record, "https://www.example.com", true, payload, sizeof(payload));
pn5180_ndef_message_init(&message, storage, 1);
pn5180_ndef_message_add(&message, &record);

/* Selected Type 2 tag: data area starts at page 4, pages are 4 bytes; 36 pages on an NTAG213 */
pn5180_ndef_result_t result = pn5180_ndef_write_to_selected_card(proto, &message, 4, 4, 36);
```

The tag must already be NDEF formatted (capability container in page 3). Text, MIME and external records are built with `pn5180_ndef_make_text_record()`, `pn5180_ndef_make_mime_record()` and `pn5180_ndef_make_external_record()`.

### Poll, select, and inspect cards

```c
pn5180_poll_status_t status;
pn5180_uids_array_t *cards = pn5180_14443_get_all_uids_ex(proto, &status);
switch (status) {
case PN5180_POLL_FOUND:
    for (int i = 0; i < cards->uids_count; i++) {
        pn5180_uid_t *card = &cards->uids[i];
        if (!proto->select_by_uid(proto, card)) {
            continue;
        }
        int blocks = 0, block_size = 0;
        if (proto->detect_card_type_and_capacity(proto->pn5180, card, &blocks, &block_size)) {
            proto->select_by_uid(proto, card);
        }
        printf("SAK %02X ATQA %02X%02X type %d: %d blocks of %d bytes\n", card->sak, card->atqa[0], card->atqa[1],
               card->subtype, blocks, block_size);
        proto->halt(proto);
    }
    free(cards);
    break;
case PN5180_POLL_NO_TARGET:
    break; /* nothing in the field */
case PN5180_POLL_TRANSPORT_ERROR:
    pn5180_recover(proto->pn5180);
    break;
default:
    break; /* a card answered but could not be singled out; try again */
}
```

Up to 14 cards are enumerated. `get_all_uids()` is the same poll without the status. Cards are returned ordered as found; ISO15693 tags are sorted by signal strength (`agc`).

### Read MIFARE Classic blocks

```c
static const uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* Card selected. Authentication is per sector: block 4 is the first block of sector 1. */
if (proto->authenticate(proto, key, PN5180_MIFARE_CLASSIC_KEYA, card, 4)) {
    uint8_t data[16];
    if (proto->block_read(proto, 4, data, sizeof(data))) {
        ESP_LOG_BUFFER_HEX(TAG, data, sizeof(data));
    }
}
```

After a refused authentication the card stops answering: select it again (`halt`, then `select_by_uid`) before trying another key.

### Exchange APDUs with a Type 4 card

`select_by_uid()` activates ISO14443-4 (RATS) on cards that support it; APDUs then go through `pn5180_14443_4_transceive()`, which handles block chaining in both directions, waiting time extensions and retransmission.

```c
#include "pn5180-14443.h"

static const uint8_t ndef_app[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
static const uint8_t cc_file[]  = {0xE1, 0x03};

if (pn5180_14443_4_select_file(pn5180, ndef_app, sizeof(ndef_app)) &&
    pn5180_14443_4_select_file(pn5180, cc_file, sizeof(cc_file))) {
    uint8_t cc[15];
    size_t  got = sizeof(cc);
    if (pn5180_14443_4_read_binary(pn5180, 0, sizeof(cc), cc, &got)) {
        ESP_LOG_BUFFER_HEX(TAG, cc, got);
    }
}

/* Any other command: */
const uint8_t apdu[] = {0x90, 0x60, 0x00, 0x00, 0x00}; /* DESFire GetVersion */
uint8_t       rx[64];
size_t        rx_len = sizeof(rx);
if (pn5180_14443_4_transceive(pn5180, apdu, sizeof(apdu), rx, &rx_len)) {
    pn5180_apdu_response_t response;
    pn5180_apdu_parse_response(rx, rx_len, &response);
    printf("SW %04X, %u data bytes\n", pn5180_apdu_get_status(&response), (unsigned)response.data_len);
}
```

`halt()` releases an ISO14443-4 card with S(DESELECT).

### Read an ISO15693 tag

```c
#include "pn5180-15693.h"

pn5180_proto_t *tags = pn5180_15693_init(pn5180, PN5180_15693_26KASK100);
tags->setup_rf(tags);

pn5180_uids_array_t *found = tags->get_all_uids(tags);
if (found != NULL && tags->select_by_uid(tags, &found->uids[0])) {
    int blocks = 0, block_size = 0;
    tags->detect_card_type_and_capacity(pn5180, &found->uids[0], &blocks, &block_size);
    uint8_t data[32];
    if (tags->block_read(tags, 0, data, block_size)) {
        ESP_LOG_BUFFER_HEX(TAG, data, block_size);
    }
    tags->halt(tags);
}
free(found);
```

## IRQ Pin And Shared SPI Bus

### IRQ pin

```c
pn5180_irq_attach(pn5180, GPIO_NUM_4);
```

Optional, called once after `pn5180_init()`. With the IRQ pin the driver sleeps until the PN5180 signals the end of an exchange; without it the driver polls the status register over SPI — back to back for the first 5 ms, then once per millisecond with the CPU released in between. The pin polarity is read from the PN5180 EEPROM. The IRQ pin is required for `pn5180_lpcd_wait()`.

### Sharing the SPI bus with other devices

`pn5180_spi_init()` initializes the SPI bus itself. If the bus is shared, initialize it in your application and attach the PN5180 to it:

```c
spi_bus_initialize(SPI2_HOST, &bus_config, SPI_DMA_CH_AUTO); /* your bus, your other devices */
pn5180_spi_t *spi    = pn5180_spi_attach(SPI2_HOST, 7000000);
pn5180_t     *pn5180 = pn5180_init(spi, GPIO_NUM_5, GPIO_NUM_21, GPIO_NUM_12);
```

A PN5180 command is two SPI transfers, each framed by NSS. The driver holds the bus only while NSS is low; while the PN5180 executes a command (BUSY high, up to milliseconds for RF on) other devices can use the bus. A bus that was attached is never freed by `pn5180_deinit()`.

## Troubleshooting

- **`pn5180_init()` returns NULL** — the PN5180 did not boot or did not report a supported firmware. Check power (5 V and 3.3 V on the usual breakout), ground, and the NSS, BUSY and RST pins. Try a lower SPI clock.
- **`PN5180 ... timeout waiting for busy level`** — the BUSY line does not follow the SPI transfers: wrong BUSY pin, or NSS not reaching the module.
- **No cards found, `PN5180_POLL_NO_TARGET`** — check that the field comes up (`setup_rf()` returns true) and that the antenna is not on a metal surface. A card that was halted by the previous scan answers again only after the field was off for at least 5.1 ms (`PN5180_RF_OFF_TIME_US`); 5 ms is too short.
- **`RF_ON blocked by external RF field (RFCA)`** — another reader's field is present. `pn5180_set_rfca(pn5180, false)` switches the field on regardless.
- **`select_by_uid()` fails on a card that was just read** — the card is still selected and ignores the wake-up. Call `halt()` first, then `select_by_uid()`.
- **Reads fail after one refused command** — Ultralight and NTAG cards leave the selected state after any NAK (for example a read beyond the last page), MIFARE Classic after a refused authentication. Select the card again.
- **`PN5180_NDEF_ERR_NO_NDEF` on a MIFARE Classic card** — the card has no NFC Forum MAD, uses non-default keys, or its NDEF sectors are not contiguous. Read raw blocks with your own keys instead.
- **ISO15693 `halt()` returns false** — the tag does not implement Reset to Ready, which is an optional command. The tag stays selected until the field is switched off.
- **Everything times out after an update to 0.3.0 or later** — the receive timeout runs on a PN5180 timer; `pn5180_set_hw_rx_timeout(pn5180, false)` switches to a host-side timeout to tell a timer problem from an RF problem.

## Reliability And Recovery

### Timeouts

The wait for a card's answer is timed by PN5180 Timer1, started at the end of the transmission and stopped when a reception begins. A missing card is therefore reported within milliseconds, independent of host load. Each command has its own timeout: 5 ms for activation (REQA, anticollision, SELECT), 10 ms for reads, 20 ms for write acknowledges, 10 / 40 ms for ISO15693 read / write. ISO14443-4 exchanges use the frame waiting time the card announces in its ATS, extended when the card asks for it.

`pn5180_t.timeout_ms` (default 500 ms) only bounds SPI and BUSY handling.

### pn5180_recover()

```c
if (status == PN5180_POLL_TRANSPORT_ERROR) {
    pn5180_recover(pn5180);
}
```

Resets the PN5180 and restores the RF configuration and the field state it had. Cards have to be selected again.

### RF guard time

After the field is switched on, the driver waits 5.1 ms before the first command, so that cards have powered up. Change it with `pn5180_set_rf_guard_time_us()`; ISO15693 tags need 1 ms.

### Low power card detection

```c
pn5180_lpcd_prepare(pn5180);          /* once: writes the LPCD settings to EEPROM if they differ */
pn5180_lpcd_enter(pn5180, 500);       /* check for a card every 500 ms */
if (pn5180_lpcd_wait(pn5180, -1, NULL)) {
    proto->setup_rf(proto);           /* woke up: a card or metal object is near */
}
```

In LPCD mode the PN5180 sleeps and briefly switches its field on at the given interval. Any SPI access ends the mode, which is why waiting needs the IRQ pin. On wake-up the PN5180 has lost its register settings; `pn5180_lpcd_wait()` reloads the RF configuration.

## Reference

### Features and scope

- ISO14443A: anticollision with cascaded UIDs, up to 14 cards per scan, typed poll status, selection by UID
- ISO15693: inventory with collision resolution, select, block read and write, system information
- MIFARE Classic authentication and block access; Ultralight / NTAG page access; value-block operations
- Card identification: MIFARE Classic Mini / 1K / 4K, Ultralight, Ultralight C, Ultralight EV1, NTAG210 / 212 / 213 / 215 / 216, ISO14443-4
- ISO14443-4 (ISO-DEP) APDU exchange with chaining in both directions, waiting time extension, retransmission and S(DESELECT)
- Stateless ISO 7816-4 short APDU parser and response builder
- NDEF reading from Type 2, MIFARE Classic (MAD1 / MAD2), Type 4 and Type 5 cards; chunked-record reassembly
- NDEF record builders (Text, URI, MIME, External), message encoding, TLV writing to the selected tag
- Receive timeout on the PN5180 hardware timer; optional IRQ pin; own or shared SPI bus
- `pn5180_recover()`, low power card detection, RF collision avoidance option
- `pn5180_rf_transceive()` for custom RF frames; register and EEPROM access

Not implemented: ISO14443B, FeliCa, peer-to-peer, card emulation, formatting blank tags, writing NDEF to MIFARE Classic and Type 4 cards, Ultralight C / DESFire authentication.

Requirements: ESP-IDF 5.x or 6.0. Two 512-byte DMA-capable buffers are allocated per device. Release notes are in [CHANGES.md](CHANGES.md).

### Card session lifecycle

1. `setup_rf()` loads the protocol's RF configuration and switches the field on.
2. `get_all_uids()` enumerates the cards. Each ISO14443A card found is halted, each ISO15693 tag silenced, so that the next ones can answer; none is left selected.
3. `select_by_uid()` wakes one card up and selects it. For an ISO14443-4 card this includes the activation (RATS).
4. `detect_card_type_and_capacity()` fills `subtype`, `block_size` and `blocks_count` of the `pn5180_uid_t`. It returns true when the card has to be selected again afterwards, which is the case for the Ultralight family.
5. Block access, authentication, NDEF and APDU functions work on the selected card.
6. `halt()` ends the session: HLTA for ISO14443-3 cards, S(DESELECT) for ISO14443-4 cards, Reset to Ready for ISO15693 tags. A halted ISO14443A card is found again by `select_by_uid()`, but by `get_all_uids()` only after the field was switched off.

A selected ISO14443A card does not answer a new `select_by_uid()`: call `halt()` first.

### Cards with both MIFARE Classic and ISO14443-4

Some cards (SmartMX, JCOP, and similar) emulate MIFARE Classic on top of an ISO14443-4 chip and report SAK `0x28` (1K) or `0x38` (4K). One activation can serve only one of the two sides: once RATS was sent, the card speaks ISO14443-4 and refuses MIFARE commands until it is selected anew.

Such a card is detected with a Classic subtype and is treated as Classic by default: `select_by_uid()` does not send RATS, so authentication, block access and `pn5180_ndef_read_card_auto()` work as on a native Classic card.

To use the ISO14443-4 side instead, change the subtype in your copy of the `pn5180_uid_t` before selecting:

```c
pn5180_uid_t card = cards->uids[0];
if ((card.sak & 0x20) != 0) {              /* ISO14443-4 capable */
    card.subtype = PN5180_MIFARE_DESFIRE;  /* treat as ISO14443-4 / Type 4 */
}
if (proto->select_by_uid(proto, &card)) {
    /* pn5180_14443_4_transceive(), pn5180_14443_4_select_file(), ... */
}
```

With that subtype `pn5180_ndef_read_card_auto()` also takes the Type 4 path. To switch sides on a selected card, call `halt()` and `select_by_uid()` with the other subtype.

### APDU utilities

`pn5180_14443_4_transceive()` is the APDU exchange API. The APDU utilities are independent of it and of any hardware:

- `pn5180_apdu_parse_command()` supports short APDU cases 1, 2S, 3S, and 4S; extended-length APDUs are rejected.
- `pn5180_apdu_parse_response()` separates response data from SW1/SW2; `pn5180_apdu_build_response()` writes `DATA SW1 SW2` into a caller-provided buffer.
- They do not allocate memory; parsed data pointers refer directly to the caller-owned input buffer.

`pn5180_14443_4_select_file()` selects an application by AID (more than two bytes) or a file by identifier; for a file it uses P2=0x0C and retries once with P2=0x00 if the card refuses, for Type 4 mapping version 1.0 cards. In `pn5180_14443_4_read_binary()`, encoded `Le = 0` requests 256 bytes.

For an ISO14443-4 card the `block_read` callback is READ BINARY on the file the application has selected, with the block number as file offset.

### Low-level MIFARE access

Include `pn5180-mifare.h` for raw block and value operations on the selected card. The `block_read` / `block_write` / `authenticate` callbacks are the preferred entry points.

- `pn5180_mifare_block_read()` reads one 16-byte MIFARE Classic block, or 16 bytes spanning four Ultralight / NTAG pages (the read wraps to page 0 at the end of the memory).
- `pn5180_mifare_block_write()` with a 4-byte buffer writes one Ultralight / NTAG page (WRITE, A2h); with 16 bytes it writes one MIFARE Classic block.
- `pn5180_mifare_value_write()` formats a value block, `pn5180_mifare_value_read()` reads and checks one. `pn5180_mifare_increment()`, `pn5180_mifare_decrement()` and `pn5180_mifare_restore()` put their result into the card's transfer buffer; `pn5180_mifare_transfer()` stores it.

### Advanced driver control

- `pn5180_rf_transceive()` transmits a frame and receives the answer with an explicit timeout, and tells timeout, collision, RX error, overflow and transport failure apart. The protocol code is built on it; CRC handling follows `pn5180_enable_crc()` / `pn5180_disable_crc()`.
- `pn5180_read_register()`, `pn5180_write_register()`, `pn5180_write_register_or_mask()`, `pn5180_write_register_and_mask()` and `pn5180_read_eeprom()` / `pn5180_write_eeprom()` give direct access to the PN5180; register, IRQ flag and EEPROM address constants are in `pn5180.h` with the `PN5180_` prefix.
- `pn5180_load_rf_config()`, `pn5180_set_rf_on()`, `pn5180_set_rf_off()` control the RF configuration and the field; `pn5180_send_command()` sends a raw host command.
- `pn5180_set_hw_rx_timeout()`, `pn5180_set_rf_guard_time_us()`, `pn5180_set_rfca()` adjust timing and field behaviour.

### Ownership and lifetime

- `pn5180_spi_init()` and `pn5180_spi_attach()` return a heap-allocated `pn5180_spi_t *`. `pn5180_spi_attach()` never frees the underlying bus.
- `pn5180_init()` returns a heap-allocated `pn5180_t *`. If it fails, the SPI structure is untouched: retry, or release it with `pn5180_spi_deinit()`.
- `pn5180_deinit(pn5180, true)` frees the device, its SPI device and the bus (if `pn5180_spi_init()` created it); `pn5180_deinit(pn5180, false)` keeps the bus.
- `pn5180_14443_init()` and `pn5180_15693_init()` return a heap-allocated `pn5180_proto_t *`; release it with `free()` before `pn5180_deinit()`.
- `get_all_uids()` and the `..._get_all_uids_ex()` functions return a heap-allocated `pn5180_uids_array_t *`; release it with `free()`.
- `pn5180_ndef_read_card_auto()`, `pn5180_ndef_read_from_selected_card()` and `pn5180_ndef_parse_message()` return a heap-allocated `pn5180_ndef_message_parsed_t *` that owns a copy of the message; release it with `pn5180_ndef_free_parsed_message()`.

`pn5180_t` is a public struct because the driver is split across several source files, but application code should treat it as an owned handle and not modify its fields directly. One device must not be used from two tasks at the same time.

### Host tests

`host_test/` builds the protocol code for the host together with simulated cards (NTAG, Ultralight C, MIFARE Classic, an ISO14443-4 card with a Type 4 application, an ISO15693 tag) and runs it under AddressSanitizer:

```sh
make -C host_test test IDF_PATH=<path to esp-idf>
```

The tests cover polling, selection, card identification, NDEF reading and writing for all four mappings, ISO14443-4 chaining and recovery from lost frames, and MIFARE value operations. They do not cover the SPI layer and RF timing, which need the hardware.

### API map

- Device lifecycle: `pn5180_spi_init()`, `pn5180_spi_attach()`, `pn5180_spi_deinit()`, `pn5180_init()`, `pn5180_irq_attach()`, `pn5180_deinit()`, `pn5180_reset()`, `pn5180_recover()`
- RF field: `pn5180_load_rf_config()`, `pn5180_set_rf_on()`, `pn5180_set_rf_off()`, `pn5180_set_rf_guard_time_us()`, `pn5180_set_rfca()`
- Protocol objects: `pn5180_14443_init()`, `pn5180_15693_init()` and the callbacks `setup_rf`, `get_all_uids`, `select_by_uid`, `detect_card_type_and_capacity`, `authenticate`, `block_read`, `block_write`, `halt`
- Polling with status: `pn5180_14443_get_all_uids_ex()`, `pn5180_15693_get_all_uids_ex()`
- ISO14443-4 and Type 4: `pn5180_14443_4_transceive()`, `pn5180_14443_4_select_file()`, `pn5180_14443_4_read_binary()`
- APDU utilities: `pn5180_apdu_parse_command()`, `pn5180_apdu_parse_response()`, `pn5180_apdu_build_response()`, `pn5180_apdu_get_status()`
- MIFARE raw access: `pn5180_mifare_authenticate()`, `pn5180_mifare_block_read()`, `pn5180_mifare_block_write()`, value operations
- NDEF reading: `pn5180_ndef_read_card_auto()`, `pn5180_ndef_read_from_selected_card()`, `pn5180_ndef_parse_message()`, `pn5180_ndef_free_parsed_message()`
- NDEF records: `pn5180_ndef_extract_text()`, `pn5180_ndef_extract_uri()`, `pn5180_ndef_get_record_type()`, `pn5180_ndef_record_is_text()` / `_uri()` / `_smartposter()`, `pn5180_ndef_decode_smartposter()`
- NDEF writing: `pn5180_ndef_make_text_record()`, `pn5180_ndef_make_uri_record()`, `pn5180_ndef_make_mime_record()`, `pn5180_ndef_make_external_record()`, `pn5180_ndef_message_init()`, `pn5180_ndef_message_add()`, `pn5180_ndef_encode_message()`, `pn5180_ndef_write_to_selected_card()`
- Low power card detection: `pn5180_lpcd_prepare()`, `pn5180_lpcd_enter()`, `pn5180_lpcd_wait()`
- Raw access: `pn5180_rf_transceive()`, `pn5180_send_data()`, `pn5180_read_data()`, `pn5180_send_command()`, register and EEPROM functions, `pn5180_get_irq_status()`, `pn5180_clear_irq_status()`
- Timing: `pn5180_set_hw_rx_timeout()`, `pn5180_delay_ms()`, `pn5180_delay_us()`, `PN5180_RF_OFF_TIME_US`

## License

MIT License. See [LICENSE](LICENSE) for details.
