# PN5180 ESP32 Component (ESP-IDF)

## Overview

ESP-IDF component for the NXP PN5180 NFC/RFID reader. This implementation provides a robust multi-protocol NFC reader with comprehensive support for ISO14443A, ISO15693, MIFARE Classic/Ultralight, and NDEF message parsing.

### Features
- ✅ **ISO14443A** - Anticollision, multi-cascade UID enumeration, card selection
- ✅ **ISO15693** - Vicinity tag support with configurable modulation (ASK 100%/10%)
- ✅ **MIFARE Classic 1K/4K** - Authentication (Key A/B), block read/write
- ✅ **MIFARE Ultralight** - Read-only support
- ✅ **NDEF** - Complete message parsing with TLV decoding, Text RTD, URI RTD support
- ✅ **Multi-card** - Enumerate up to 14 cards in field
- ✅ **Error detection** - RX/CRC/collision error handling with clean recovery
- ✅ **SPI** - Tested at 7 MHz with BUSY line synchronization

## Hardware

Default wiring used in the sample app:

| Signal | ESP32 GPIO | Description |
| ------ | ---------- | ----------- |
| RST    | 12         | Hardware reset (active low) |
| SCK    | 18         | SPI clock |
| MOSI   | 23         | SPI data to PN5180 |
| MISO   | 19         | SPI data from PN5180 |
| NSS    | 5          | SPI chip select (active low) |
| BUSY   | 21         | PN5180 busy indicator |

Adjust the GPIO assignments or the SPI host (`VSPI_HOST` by default) to match your board.

## Requirements

- ESP-IDF v5.x (tested) with an ESP32 target.
- 3.3 V PN5180 breakout wired for SPI and BUSY/RST lines.
- Enough DMA-capable heap for the driver buffers (two 512-byte buffers are allocated).

## Getting Started

1. Place this repository under your project's `components/` directory (or add it as a git submodule).
2. Include the headers you need:
   - `pn5180.h` - Core driver and shared types
   - `pn5180-14443.h` - ISO14443A protocol (MIFARE, NTAG, etc.)
   - `pn5180-15693.h` - ISO15693 protocol (vicinity tags)
   - `pn5180-ndef.h` - NDEF message reading and parsing
   - `pn5180-mifare.h` - MIFARE Classic authentication helpers
3. Build and flash with `idf.py build flash monitor`.

**Note**: The `main/` directory contains an example application. The `examples/` directory has standalone examples you can reference.

## API Reference

### Core Types

```c
// Card type enumeration (detected via SAK analysis)
typedef enum {
    NFC_TYPE_UNKNOWN,           // Unknown or unsupported
    NFC_TYPE_MIFARE_CLASSIC_1K, // MIFARE Classic 1K (SAK 0x08)
    NFC_TYPE_MIFARE_CLASSIC_4K, // MIFARE Classic 4K (SAK 0x18)
    NFC_TYPE_MIFARE_ULTRALIGHT, // MIFARE Ultralight/NTAG (SAK 0x00)
    NFC_TYPE_NTAG,              // NTAG21x series
    NFC_TYPE_ISO14443_4,        // ISO14443-4 compliant (DESFire, etc.)
    // ... see pn5180.h for complete list
} nfc_type_t;

// Protocol interface - all protocols implement this
typedef struct {
    func_setup_rf_t        setup_rf;        // Configure RF field
    funct_get_all_uids_t   get_all_uids;    // Enumerate all cards
    func_select_by_uid_t   select_by_uid;   // Select specific card
    func_authenticate_t    authenticate;    // Auth (MIFARE Classic)
    func_block_read_t      block_read;      // Read block
    func_block_write_t     block_write;     // Write block
    func_halt_t            halt;            // HALT selected card
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

void app_main(void)
{
    pn5180_spi_t *spi = pn5180_spi_init(VSPI_HOST, PN5180_SCK, PN5180_MISO, PN5180_MOSI, PN5180_FREQ);
    pn5180_t *pn5180  = pn5180_init(spi, PN5180_NSS, PN5180_BUSY, PN5180_RST);

    pn5180_proto_t *iso14443 = pn5180_14443_init(pn5180);
    iso14443->setup_rf(iso14443);

    nfc_uids_array_t *uids = iso14443->get_all_uids(iso14443);
    if (uids) {
        for (int i = 0; i < uids->uids_count; i++) {
            nfc_uid_t *uid = &uids->uids[i];
            printf("Card %d: Type=%d, UID len=%d\n", i, uid->type, uid->uid_len);
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

void read_mifare_classic(pn5180_proto_t *proto, nfc_uid_t *uid)
{
    // Select the card first
    if (!proto->select_by_uid(proto, uid)) {
        ESP_LOGE(TAG, "Failed to select card");
        return;
    }

    // Authenticate sector 1 (blocks 4-7) with Key A
    uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // Default key
    int block = 4;  // First block of sector 1

    if (!proto->authenticate(proto, block, 0, key)) {  // 0 = Key A
        ESP_LOGE(TAG, "Authentication failed");
        return;
    }

    // Read authenticated block
    uint8_t data[16];
    if (proto->block_read(proto, block, data, sizeof(data)) > 0) {
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
    nfc_uids_array_t *uids = iso15693->get_all_uids(iso15693);
    if (uids && uids->uids_count > 0) {
        // Select first tag
        if (iso15693->select_by_uid(iso15693, &uids->uids[0])) {
            // Read block 0
            uint8_t data[4];
            if (iso15693->block_read(iso15693, 0, data, sizeof(data)) > 0) {
                ESP_LOG_BUFFER_HEX(TAG, data, 4);
            }
        }
        free(uids);
    }

    free(iso15693);
}
```

### NDEF Message Reading

```c
#include "pn5180-ndef.h"

void read_ndef_message(pn5180_proto_t *proto)
{
    // For MIFARE Classic: start_block=4, block_size=16
    // For ISO15693 Type 5: start_block=1, block_size=4

    int start_block = 4;   // Adjust based on card type
    int block_size  = 16;  // 16 for MIFARE, 4 for ISO15693

    ndef_message_parsed_t *msg = NULL;
    // auth_cb + sector_cb are optional (NULL if not needed)
    ndef_result_t result = ndef_read_from_selected_card(proto, start_block, block_size, 0,
                                                        NULL, NULL, NULL, &msg);

    if (result != NDEF_OK || !msg) {
        ESP_LOGE(TAG, "NDEF read failed: %s", ndef_result_to_string(result));
        return;
    }

    ESP_LOGI(TAG, "Found %zu NDEF records", msg->record_count);

    for (size_t i = 0; i < msg->record_count; i++) {
        ndef_record_t *rec = &msg->records[i];
        ESP_LOGI(TAG, "Record %zu: TNF=0x%02X, Type len=%u, Payload len=%u",
                 i, rec->tnf, rec->type_len, rec->payload_len);

        // Check for URI record
        if (rec->tnf == NDEF_TNF_WELL_KNOWN && rec->type_len == 1 && rec->type[0] == 'U') {
            // Decode URI - first byte is prefix code
            ESP_LOGI(TAG, "  URI record found");
        }
        // Check for Text record
        else if (rec->tnf == NDEF_TNF_WELL_KNOWN && rec->type_len == 1 && rec->type[0] == 'T') {
            ESP_LOGI(TAG, "  Text record found");
        }
    }

    ndef_free_parsed_message(msg);
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

- **Blocking calls & timeouts**: All APIs are synchronous and wait for hardware completion using `BUSY`, IRQ, and transceiver-state polling. Operations respect internal timeouts and return promptly on error.

- **Error handling**: The component detects RX errors (protocol/CRC/collision) and returns failure without automatic retries. Implement retries in your application.

- **MIFARE Classic authentication**:
    - Authentication is per-sector; re-authenticate when crossing sector boundaries
    - After auth failure, re-select the card before retrying
    - Some tags/readers may require a HALT before re-select; apply only on failure if needed

- **CRC policy (ISO14443A)**: Anticollision runs with CRC disabled; SELECT uses CRC enabled. After SELECT, CRC remains enabled.

- **RF field control**: Toggle RF off/on between scans (`pn5180_rf_off()` / `pn5180_rf_on()`) and allow ~5 ms for tags to return to IDLE.

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