# app_logic

A fuller program on the ESP32-S3: it polls ISO14443A and ISO15693 every 2 seconds, and for each card found it selects
the card, identifies its type and memory, reads its NDEF message, and when there is none dumps its blocks, trying a
list of MIFARE Classic keys on each sector.

## Hardware

An ESP32-S3 and a PN5180 module on `SPI3_HOST`:

| PN5180 | ESP32-S3 |
| ------ | -------- |
| RST    | GPIO 4 |
| NSS    | GPIO 9 |
| MOSI   | GPIO 7 |
| MISO   | GPIO 8 |
| SCK    | GPIO 6 |
| BUSY   | GPIO 5 |
| 5V, 3.3V, GND | 5V, 3V3, GND |

The pins are the `enum` at the top of `main/app_logic.c`. On a classic ESP32, GPIO 6 to 8 belong to the flash: choose
other pins there, or run the example on an ESP32-S3.

## Build

```sh
idf.py create-project-from-example "jef-sure/pn5180:app_logic"
cd app_logic
idf.py set-target esp32s3
idf.py build flash monitor
```

Run `idf.py set-target esp32s3` before the first build. Inside the repository, `idf.py -C examples/app_logic build`
builds it against the repository itself.

## What it does with a card

1. **Poll.** `scan_protocol()` resets the field, sets up the protocol and prints the UID and AGC of every card.
2. **Select and identify.** `process_card()` selects the card and calls `detect_card_type_and_capacity()`, selecting
   it again when the detection asks for it, and prints the type and the number and size of its blocks.
3. **NDEF.** `pn5180_ndef_read_card_auto()` reads the message with the mapping of the card type and prints each
   record; Text records with their language and encoding.
4. **Blocks.** Without NDEF the card is selected again and `read_card_blocks()` reads every block. On MIFARE Classic and
   MIFARE Plus cards each sector is authenticated first: `authenticate_sector()` tries each key of the list as key A and
   as key B, one authentication per key; after a refused key the card is selected again, and a card that did not answer
   ends the search (`iso14443_last_auth_status`). A failed read is repeated once after a new select.
5. **Halt.** Each card is halted before the next one, so that an ISO14443-4 card does not stay in its session.

ISO14443-4 cards are not dumped: their memory is files behind APDUs, see
[ISO14443-4 and APDUs](../../docs/en/iso14443-4.md).

## The key list

`mifare_keys` holds the factory key, the MAD and NFC keys and a few keys that are often found on cards. Add your own
keys there. Each key costs two authentications per sector (key A and key B), and each refused one a new select, so a
long list makes a dump of a 4K card slow.

## Where to look next

- [ISO14443A cards](../../docs/en/iso14443a.md): card types, authentication, blocks and pages.
- [NDEF](../../docs/en/ndef.md): what `pn5180_ndef_read_card_auto()` returns and why.
- [simple_main](../simple_main/README.md): the scanning loop alone.
