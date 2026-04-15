# Changelog

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
