# PN5180 ESP32 Component (ESP-IDF)

## Overview

ESP-IDF component for the NXP PN5180 NFC/RFID reader. This implementation provides a robust multi-protocol NFC reader with comprehensive support for ISO14443A, ISO15693, MIFARE Classic/Ultralight, NTAG21x, and NDEF message parsing, and is compatible with ESP-IDF 5.x and 6.0.

### Features
- ✅ **ISO14443A** - Anticollision, multi-cascade UID enumeration, card selection
- ✅ **ISO15693** - Vicinity tag support with configurable modulation (ASK 100%/10%)
- ✅ **MIFARE Classic 1K/4K** - Authentication (Key A/B), block read/write
- ✅ **MIFARE Ultralight / NTAG21x** - Page read and write (no authentication)
- ✅ **NDEF** - Message reading and writing with TLV decoding, Text RTD, URI RTD support (`pn5180_ndef_*` API)
- ✅ **Multi-card** - Enumerate up to 14 cards in field
- ✅ **Error detection** - RX/CRC/collision error handling with clean recovery
- ✅ **SPI** - Tested at 7 MHz with BUSY line synchronization; own bus or a bus shared with other devices
- ✅ **Timing** - Receive timeout on the PN5180 hardware timer; optional IRQ pin instead of polling
- ✅ **ESP-IDF 6.0** - Updated examples and core sources for current ESP-IDF builds

## Hardware

The repository now ships multiple standalone examples. Their default wiring differs by target board.

### `examples/simple_main`

Default wiring for a classic ESP32 board:

| Signal | ESP32 GPIO | Description |
| ------ | ---------- | ----------- |
| RST    | 12         | Hardware reset (active low) |
| SCK    | 18         | SPI clock |
| MOSI   | 23         | SPI data to PN5180 |
| MISO   | 19         | SPI data from PN5180 |
| NSS    | 5          | SPI chip select (active low) |
| BUSY   | 21         | PN5180 busy indicator |

Uses `SPI3_HOST` in the example source.

### `examples/app_logic`

Default wiring for the ESP32-S3 setup used by the richer example app:

| Signal | ESP32-S3 GPIO | Description |
| ------ | ------------- | ----------- |
| RST    | 4             | Hardware reset (active low) |
| SCK    | 6             | SPI clock |
| MOSI   | 7             | SPI data to PN5180 |
| MISO   | 8             | SPI data from PN5180 |
| NSS    | 9             | SPI chip select (active low) |
| BUSY   | 5             | PN5180 busy indicator |

Uses `SPI3_HOST` in the example source.

Adjust the GPIO assignments and SPI host to match your board.

## Requirements

- ESP-IDF 5.x or 6.0.
- 3.3 V PN5180 breakout wired for SPI and BUSY/RST lines.
- Enough DMA-capable heap for the driver buffers (two 512-byte buffers are allocated).

## Getting Started

1. Add the component with the ESP-IDF Component Manager:

```bash
idf.py add-dependency "jef-sure/esp32-component-pn5180^0.3.0"
```

2. Or place this repository under your project's `components/` directory.
3. Include the headers you need:
   - `pn5180.h` - Core driver and shared types
   - `pn5180-14443.h` - ISO14443A protocol (MIFARE, NTAG, etc.)
   - `pn5180-15693.h` - ISO15693 protocol (vicinity tags)
   - `pn5180-ndef.h` - NDEF message reading, writing and parsing
   - `pn5180-mifare.h` - MIFARE Classic block and Ultralight/NTAG page read/write helpers
4. Build and flash with `idf.py build flash monitor`.

## Examples

- `examples/simple_main` - Minimal scanning example for ISO14443A and ISO15693.
- `examples/app_logic` - More complete application example with card classification, auth helpers, and ESP32-S3 default pin mapping.
- `examples/ndef` - Focused NDEF parsing helpers and test code.

## API Reference

### Core Types

```c
// Card type enumeration (subset)
typedef enum {
    PN5180_MIFARE_UNKNOWN,
    PN5180_MIFARE_CLASSIC_1K,
    PN5180_MIFARE_CLASSIC_MINI,
    PN5180_MIFARE_CLASSIC_4K,
    PN5180_MIFARE_ULTRALIGHT,
    PN5180_MIFARE_NTAG213,
    PN5180_MIFARE_DESFIRE,
    PN5180_15693,
    // ... see pn5180.h for complete list
} pn5180_card_type_t;

// Protocol interface - all protocols implement this
typedef struct {
    pn5180_t                 *pn5180;
    pn5180_func_setup_rf_t         *setup_rf;
    pn5180_func_get_all_uids_t     *get_all_uids;
    pn5180_func_select_by_uid_t    *select_by_uid;
    pn5180_func_authenticate_t     *authenticate;
    pn5180_func_block_read_t       *block_read;
    pn5180_func_block_write_t      *block_write;
    pn5180_func_detect_card_type_t *detect_card_type_and_capacity;
    pn5180_func_halt_t             *halt;
    // ...
} pn5180_proto_t;
```

## Usage Examples

### Basic ISO14443A Card Enumeration

```c
#include "pn5180.h"
#include "pn5180-14443.h"

enum {
    PN5180_RST  = GPIO_NUM_12,
    PN5180_SCK  = GPIO_NUM_18,
    PN5180_MOSI = GPIO_NUM_23,
    PN5180_MISO = GPIO_NUM_19,
    PN5180_NSS  = GPIO_NUM_5,
    PN5180_BUSY = GPIO_NUM_21,
    PN5180_FREQ = 7000000,
};

// Adjust pins and SPI host to match your board. See the example apps above
// for the current ESP32 and ESP32-S3 defaults.

void app_main(void)
{
    pn5180_spi_t *spi = pn5180_spi_init(SPI3_HOST, PN5180_SCK, PN5180_MISO, PN5180_MOSI, PN5180_FREQ);
    pn5180_t *pn5180  = pn5180_init(spi, PN5180_NSS, PN5180_BUSY, PN5180_RST);

    pn5180_proto_t *iso14443 = pn5180_14443_init(pn5180);
    iso14443->setup_rf(iso14443);

    pn5180_uids_array_t *uids = iso14443->get_all_uids(iso14443);
    if (uids) {
        for (int i = 0; i < uids->uids_count; i++) {
            pn5180_uid_t *uid = &uids->uids[i];
            printf("Card %d: Type=%d, UID len=%d\n", i, uid->subtype, uid->uid_length);
        }
        free(uids);
    }

    free(iso14443);
    pn5180_deinit(pn5180, true);
}
```

### MIFARE Classic Authentication and Read

```c
#include "pn5180.h"
#include "pn5180-14443.h"
#include "pn5180-mifare.h"

void read_mifare_classic(pn5180_proto_t *proto, pn5180_uid_t *uid)
{
    // Select the card first
    if (!proto->select_by_uid(proto, uid)) {
        ESP_LOGE(TAG, "Failed to select card");
        return;
    }

    // Authenticate sector 1 (blocks 4-7) with Key A
    uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // Default key
    int block = 4;  // First block of sector 1

    if (!proto->authenticate(proto, key, PN5180_MIFARE_CLASSIC_KEYA, uid, block)) {
        ESP_LOGE(TAG, "Authentication failed");
        return;
    }

    // Read authenticated block
    uint8_t data[16];
    if (proto->block_read(proto, block, data, sizeof(data))) {
        ESP_LOGI(TAG, "Block %d data:", block);
        ESP_LOG_BUFFER_HEX(TAG, data, 16);
    }
}
```

### ISO15693 Vicinity Tag Reading

```c
#include "pn5180.h"
#include "pn5180-15693.h"

void read_iso15693_tags(pn5180_t *pn5180)
{
    // Initialize with ASK 100% modulation
    pn5180_proto_t *iso15693 = pn5180_15693_init(pn5180, PN5180_15693_26KASK100);
    iso15693->setup_rf(iso15693);

    // Enumerate tags
    pn5180_uids_array_t *uids = iso15693->get_all_uids(iso15693);
    if (uids && uids->uids_count > 0) {
        // Select first tag
        if (iso15693->select_by_uid(iso15693, &uids->uids[0])) {
            // Read block 0
            uint8_t data[4];
            if (iso15693->block_read(iso15693, 0, data, sizeof(data))) {
                ESP_LOG_BUFFER_HEX(TAG, data, 4);
            }
        }
        free(uids);
    }

    free(iso15693);
}
```

### NDEF Message Reading

All NDEF functions and types are prefixed with `pn5180_ndef_`, constants with `PN5180_NDEF_` (since 0.2.0; earlier versions used `ndef_` / `NDEF_`). Since 0.3.0 the remaining types and macros are prefixed as well (`pn5180_uid_t`, `PN5180_IRQ_STATUS`, ...) and all function names are snake_case (`pn5180_read_register()`, `pn5180_set_rf_on()`, ...); see CHANGES.md for the full list of renames.

```c
#include "pn5180-ndef.h"

void read_ndef_message(pn5180_proto_t *proto)
{
    // For MIFARE Classic: start_block=4, block_size=16
    // For ISO15693 Type 5: start_block=1, block_size=4

    int start_block = 4;   // Adjust based on card type
    int block_size  = 16;  // 16 for MIFARE, 4 for ISO15693

    pn5180_ndef_message_parsed_t *msg = NULL;
    // auth_cb + sector_cb are optional (NULL if not needed)
    pn5180_ndef_result_t result = pn5180_ndef_read_from_selected_card(proto, start_block, block_size, 0,
                                                        NULL, NULL, NULL, &msg);

    if (result != PN5180_NDEF_OK || !msg) {
        ESP_LOGE(TAG, "NDEF read failed: %s", pn5180_ndef_result_to_string(result));
        return;
    }

    ESP_LOGI(TAG, "Found %zu NDEF records", msg->record_count);

    for (size_t i = 0; i < msg->record_count; i++) {
        pn5180_ndef_record_t *rec = &msg->records[i];
        ESP_LOGI(TAG, "Record %zu: TNF=0x%02X, Type len=%u, Payload len=%u",
                 i, rec->tnf, rec->type_len, rec->payload_len);

        // Check for URI record
        if (rec->tnf == PN5180_NDEF_TNF_WELL_KNOWN && rec->type_len == 1 && rec->type[0] == 'U') {
            // Decode URI - first byte is prefix code
            ESP_LOGI(TAG, "  URI record found");
        }
        // Check for Text record
        else if (rec->tnf == PN5180_NDEF_TNF_WELL_KNOWN && rec->type_len == 1 && rec->type[0] == 'T') {
            ESP_LOGI(TAG, "  Text record found");
        }
    }

    pn5180_ndef_free_parsed_message(msg);
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                    │
│   (Your code - card detection, business logic, etc.)    │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                     NDEF Layer                          │
│   pn5180-ndef.h - Message parsing, TLV, record types    │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                   Protocol Layer                        │
│   pn5180-14443.h (MIFARE)  │  pn5180-15693.h (Vicinity) │
│   pn5180-mifare.h (Auth)   │                            │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                     Core Driver                         │
│   pn5180.h - SPI, RF control, low-level commands        │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                      Hardware                           │
│            ESP32 SPI <-> PN5180 NFC Reader              │
└─────────────────────────────────────────────────────────┘
```

## Notes

- **Blocking calls & timeouts**: All APIs are synchronous. The wait for a card response is timed by PN5180 Timer1 (started at the end of the transmission, stopped when a reception begins), so a missing card is reported within a few milliseconds. `pn5180_set_hw_rx_timeout(pn5180, false)` falls back to a host-side timeout.

- **IRQ pin (optional)**: call `pn5180_irq_attach(pn5180, gpio)` after `pn5180_init()` to wait on the PN5180 IRQ pin instead of polling `IRQ_STATUS` over SPI. Without it the driver polls, busy for the first 5 ms and yielding to other tasks after that. The IRQ pin is required for `pn5180_lpcd_wait()`.

- **Custom RF exchanges**: `pn5180_rf_transceive()` sends a frame and receives the response with an explicit timeout; the protocol code in this component is built on it.

- **Shared SPI bus**: if the bus is used by other devices, initialize it in the application and use `pn5180_spi_attach(host, clock_hz)` instead of `pn5180_spi_init()`. `pn5180_deinit()` then leaves the bus alone.

- **Recovery**: `pn5180_recover()` resets the reader and restores the RF configuration and the field state.

- **Error handling**: The component detects RX errors and performs limited automatic recovery where implemented, including ISO14443-4 receive retries for timeout/protocol errors. Applications should still handle persistent failures and card removal.

- **MIFARE Classic authentication**:
    - Authentication is per-sector; re-authenticate when crossing sector boundaries
    - After auth failure, re-select the card before retrying
    - Some tags/readers may require a HALT before re-select; apply only on failure if needed

- **CRC policy (ISO14443A)**: Anticollision runs with CRC disabled; SELECT uses CRC enabled. After SELECT, CRC remains enabled.

- **RF field control**: Toggle RF off/on between scans (`pn5180_set_rf_off()` / `pn5180_set_rf_on()`) and allow 5.1 ms for tags to return to IDLE. After switching the field on the driver waits a guard time (5.1 ms by default, `pn5180_set_rf_guard_time_us()`) before the first command. `pn5180_set_rfca(pn5180, false)` disables RF collision avoidance.

- **Initialization checks**: `pn5180_init()` validates the detected firmware version and fails early if the reader does not meet the minimum supported revision. On failure the `pn5180_spi_t` passed in is left untouched, so `pn5180_init()` can be retried with it.

- **Block writes**: `block_write()` with a 4-byte buffer writes one Ultralight/NTAG page (WRITE, 0xA2); a 16-byte buffer writes one MIFARE Classic block.

- **Card type detection**: a card with an unrecognised SAK is reported as `PN5180_MIFARE_UNKNOWN` with zero blocks; any SAK with the ISO 14443-4 bit (0x20) set is handled as an ISO-DEP card.

- **Halt**: for ISO14443A `halt()` sends HLTA; for ISO15693 it sends Reset to Ready in Select mode, which returns the selected tag to the Ready state. Reset to Ready is an optional ISO15693 command, so `halt()` returns false on tags that do not implement it.

- **NDEF URI prefixes**: abbreviation codes follow NFC Forum URI RTD 1.0. Versions before 0.2.0 used non-standard prefixes for codes 0x0B and above, so tags written by them with such a prefix decode differently now.

- **UID enumeration**: `get_all_uids()` returns a heap-allocated array (max 14 cards). Always free after use; returns NULL if no cards detected.

- **Runtime configuration**: Pins and SPI frequency are set in your app; there are no Kconfig options.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No cards detected | Check wiring, ensure 3.3V supply, verify RF field is on |
| Auth timeout after first block | Re-authenticate on sector change; re-select on auth failure |
| WUPA timeout | Try HALT then re-select (only if selection fails) |
| Corrupted reads | Check SPI wiring, reduce frequency, add decoupling capacitors |
| WDT reset during multi-sector read | Add `vTaskDelay(pdMS_TO_TICKS(10))` between operations |

## License

MIT License