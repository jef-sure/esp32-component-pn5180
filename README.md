# PN5180 ESP-IDF Component

*[По-русски: README.ru.md](README.ru.md)*

ESP-IDF driver for the NXP PN5180 NFC frontend over SPI: find ISO14443A and ISO15693 cards, read NDEF (NTAG /
Ultralight, MIFARE Classic, Type 4, ISO15693) and write it to NTAG / Ultralight and ISO15693 tags, access MIFARE
Classic blocks, and exchange APDUs with ISO14443-4 cards in reader mode.

**Multi-card:** one poll returns all the cards in the field, not just the first one, and each of them can then be
selected and read by its UID. Even a `max_cards` below the number of cards leaves none out for good: with the field
left on the next polls go on with the cards not found yet, and after a field reset ISO14443A settles collisions at
random, so over several polls every card turns up. See
[Several cards in the field](docs/en/polling.md#several-cards-in-the-field).

```c
pn5180_spi_t   *spi    = pn5180_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, 7000000); /* SCK, MISO, MOSI */
pn5180_t       *pn5180 = pn5180_init(spi, GPIO_NUM_5, GPIO_NUM_21, GPIO_NUM_12);                      /* NSS, BUSY, RST */
pn5180_proto_t *nfc    = pn5180_14443_init(pn5180, 0);

nfc->setup_rf(nfc);
pn5180_uids_array_t *cards = nfc->get_all_uids(nfc);
for (int i = 0; cards != NULL && i < cards->uids_count; i++) {
    pn5180_uid_t *card = &cards->uids[i];      /* UID, SAK, ATQA, signal strength */
    if (nfc->select_by_uid(nfc, card)) {
        /* identify it, read its NDEF message or its blocks, then nfc->halt(nfc) */
    }
}
free(cards);
```

## Quick start

```sh
idf.py add-dependency "jef-sure/pn5180^0.8.2"
```

ESP-IDF 5.0.4 or later is required, 6.x included. Wire SCK, MOSI, MISO, NSS, BUSY and RST of the module to free GPIOs,
supply it with 5 V and 3.3 V, and start from [Getting started](docs/en/getting-started.md): a complete program that
prints the UID of every card and the URI stored on it. Or take an example as a new project:

```sh
idf.py create-project-from-example "jef-sure/pn5180:simple_main"
```

## Documentation

| Page | What is in it |
| ---- | ------------- |
| [Getting started](docs/en/getting-started.md) | adding the component, wiring, the first program, building |
| [How the driver works](docs/en/how-it-works.md) | the objects, the life of a card session, the field, timing, memory, tasks |
| [Finding cards](docs/en/polling.md) | polls and their status, several cards in the field, scanning loops, random UIDs |
| [ISO14443A cards](docs/en/iso14443a.md) | card types, selecting, MIFARE Classic authentication, blocks and value blocks, Ultralight and NTAG pages |
| [ISO14443-4 and APDUs](docs/en/iso14443-4.md) | activation, APDU exchange, SELECT and READ BINARY, the APDU utilities, phones |
| [ISO15693 tags](docs/en/iso15693.md) | RF configuration, inventory, select, blocks |
| [NDEF](docs/en/ndef.md) | reading all four mappings, records, building messages, writing tags |
| [Wiring, SPI bus and IRQ](docs/en/hardware.md) | pins, a shared SPI bus, the IRQ pin, low power card detection, two readers |
| [Troubleshooting](docs/en/troubleshooting.md) | symptoms, causes and what to try |
| [API reference](docs/en/api.md) | every type, function and constant |
| [Development](docs/en/development.md) | the repository, the host tests, the documentation |

The examples: [simple_main](examples/simple_main/README.md), the smallest scanning loop on an ESP32;
[app_logic](examples/app_logic/README.md), card identification, NDEF and block dumps with MIFARE keys on an ESP32-S3;
[ndef](examples/ndef/README.md), NDEF snippets. Release notes are in [CHANGES.md](CHANGES.md).

## Features

- [Multi-card](docs/en/polling.md#several-cards-in-the-field): one poll enumerates all cards in the field, up to
  `max_cards` with ISO14443A (14 by default) and as many as 192 inventory frames allow with ISO15693 (about 50 tags with
  unrelated UIDs)
- ISO14443A: anticollision with cascaded UIDs, typed poll status, selection by UID
- ISO15693: inventory with collision resolution, select, block read and write (block numbers above 255 with the
  extended commands), system information
- MIFARE Classic authentication and block access; Ultralight / NTAG page access; value-block operations
- Card identification: MIFARE Classic Mini / 1K / 4K, MIFARE Plus 2K / 4K (security level 2), Ultralight, Ultralight C,
  Ultralight EV1, NTAG210 / 212 / 213 / 215 / 216, ISO14443-4
- ISO14443-4 (ISO-DEP) APDU exchange with chaining in both directions, waiting time extension, retransmission and
  S(DESELECT)
- Stateless ISO 7816-4 short APDU parser and response builder
- NDEF reading from Type 2, MIFARE Classic (MAD1 / MAD2), Type 4 and Type 5 cards; chunked-record reassembly
- NDEF record builders (Text, URI, MIME, External), message encoding, TLV writing to Ultralight / NTAG and ISO15693 tags
- Receive timeout on the PN5180 hardware timer; optional IRQ pin; own or shared SPI bus
- `pn5180_recover()`, low power card detection, RF collision avoidance option
- `pn5180_rf_transceive()` for custom RF frames; register and EEPROM access

Not implemented: ISO14443B, FeliCa, peer-to-peer, card emulation, formatting blank tags, writing NDEF to MIFARE Classic
and Type 4 cards, Ultralight C / DESFire authentication.

## License

MIT License. See [LICENSE](LICENSE) for details.
