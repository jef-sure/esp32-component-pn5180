# Changelog

## v 0.2.0 - 2026-10-07

### NDEF API moved to the `pn5180_ndef_` namespace; bug fixes from a code review

The review compared the driver with the PN532 component, the NXP reader library and the datasheets.
These changes were verified by building the examples only; they have not been tested on hardware yet.

Breaking change:

- Every public NDEF symbol now carries the component prefix, so the component can be linked into the same application as `esp32-component-pn532`, which exports the same unprefixed names. Functions and types `ndef_*` are now `pn5180_ndef_*` (for example `pn5180_ndef_read_from_selected_card()`, `pn5180_ndef_record_t`, `pn5180_ndef_tlv_find_ndef()`); constants and macros `NDEF_*` are now `PN5180_NDEF_*` (for example `PN5180_NDEF_OK`, `PN5180_NDEF_TNF_WELL_KNOWN`, `PN5180_NDEF_RTD_URI`). There are no compatibility aliases: add the prefix in application code.

Memory safety:

- ATQA, ATS and ISO15693 inventory responses longer than the receive buffer are rejected instead of being read past the end of the buffer.
- `pn5180_init()` no longer removes the SPI device and frees the caller's `pn5180_spi_t` when it fails; the SPI structure stays valid and can be passed to `pn5180_init()` again.
- NDEF record decoding no longer overflows on 32-bit targets when a record declares a very large payload length.

Behaviour:

- NDEF URI prefix codes from 0x0B onwards now follow NFC Forum URI RTD 1.0 (`smb://`, `nfs://`, `ftp://`, `urn:` ...). The previous table was wrong for these codes in both directions, so URIs written with such a prefix by 0.1.1 decode differently now.
- `pn5180_mifare_block_write()` with a 4-byte buffer writes one Ultralight/NTAG page with WRITE (0xA2). Previously a 4-byte buffer was rejected, which made `pn5180_ndef_write_to_selected_card()` fail on Type 2 tags.
- An unknown SAK is reported as `PN5180_MIFARE_UNKNOWN` with zero capacity instead of MIFARE Classic 1K. Any SAK with the ISO 14443-4 bit set (for example 0x60) is handled as an ISO-DEP card.
- ISO15693 `halt` sends Reset to Ready in Select mode. It used to send Stay Quiet with the Select flag, which is not a valid request.
- ISO15693 Stay Quiet during inventory waits for the end of transmission instead of a fixed delay.
- `pn5180_getTransceiveState()` returns `PN5180_TS_RESERVED` when the status register cannot be read; it used to return `PN5180_TS_Idle`.
- `SYSTEM_CONFIG_TX_MODE_MASK` is 0x07 (three command bits).

Cleanup:

- All public headers can be included from C++ (`extern "C"`).
- Removed duplicated register definitions from `pn5180.h`.
- Corrected LPCD comments and log messages to match the datasheet (field-on time is the value times 8 µs; EEPROM 0x3A is the delay after field off) and removed a redundant EEPROM read in `pn5180_prepareLPCD()`.
- Fixed log messages for NTAG216 detection, SAK 0x28/0x38 and the `MFC_AUTH_TIMEOUT` read.
- The `simple_main` example and the README use `SPI3_HOST` instead of `VSPI_HOST`, which no longer exists in ESP-IDF 6.

## v 0.1.1 - 2026-04-15 

### ESP-IDF 6.0 compatibility, example refresh and tag detection fixes

Changes in this release are credited to [Garag](https://github.com/Garag).

- Reorganized the examples into standalone ESP-IDF apps under `examples/app_logic`, `examples/simple_main`, and `examples/ndef` with their own build files and component manifests.
- Added ESP-IDF 6.0 compatibility fixes across the examples and core sources, including the include and project layout updates needed by newer IDF builds.
- Added `app_main()` to the application logic example and updated the default pin mapping and SPI host selection for ESP32-S3 boards.
- Fixed NTAG21x capacity detection so NTAG213, NTAG215, and NTAG216 storage sizes map to the correct variant.
- Corrected example component manifest naming and ignored generated example artifacts.
- Added missing FreeRTOS includes in the driver sources used by the refreshed examples.

## v 0.1.0 - 2026-03-25

### Driver and protocol hardening

- Hardened core driver checks and RF handling.
- Fixed ISO14443-4 ATS/WTX, chaining and receive retries.
- Added ISO15693 response validation.
- Included small fixes and logging cleanup.

## v 0.0.9 - 2026-03-22

### Fix RF ON command

- Correct bit check: rfStatus & RF_STATUS_TX_RF_STATUS_MASK instead of rfStatus & 0x01
- Removed polling loop: FIELD_ON (0x16) is synchronous — when the SPI command completes (BUSY low), the result is final. No need to busy-wait on IRQs/register. Just one pn5180_readRegister after the command.
- RFCA error detection: If RF field doesn't come up, checks RF_ACTIVE_ERROR_IRQ_STAT to distinguish "external RF field blocked us" from a generic failure.

## v 0.0.7 - 2026-03-17

### Fix ISO14443-3A anticollision resolver

Rewrote `pn5180_14443_anticollision_level()` and removed
`pn5180_14443_resolve_collision()` to improve the bit-level
anticollision loop, verified against the NXP NfcRdLib v07.14.00 reference
implementation.
