# Changelog

## v 0.4.1 - 2026-10-07

### Fixes from a review of 0.4.0

- ISO14443-4: a card that keeps requesting waiting time extensions is given up on after 10 requests in a row; it could hold the caller indefinitely before.
- ISO14443-4: received blocks with wrong fixed bits or with CID / NAD are treated as invalid blocks; a reserved frame size in the ATS (FSCI 13 to 15) no longer makes the activation fail.
- An SPI failure while waiting for the card's answer is reported as `PN5180_RF_FATAL`; it used to look like an ordinary timeout.
- Shared SPI bus: the bus is held only while NSS is low, not while the PN5180 executes the command, so other devices are not blocked during long commands such as RF on.
- LPCD: the reference value is set through `AGC_REF_CONFIG` only on firmware 3.A and later, where the datasheet requires it; on earlier firmware the step is skipped. `pn5180_t` has a new `firmware_version` field.
- Type 4 NDEF: an NDEF length that does not fit the file is `PN5180_NDEF_ERR_PARSE_FAILED` (was `NO_NDEF`); a read-protected NDEF file is the new `PN5180_NDEF_ERR_ACCESS_DENIED` without a second read attempt; an unknown mapping version is `PN5180_NDEF_ERR_UNSUPPORTED`.

## v 0.4.0 - 2026-10-07

### ISO14443-4 rework and public APDU API, automatic NDEF reading for all tag types, host tests

Breaking changes:

- `select_by_uid()` no longer selects the NDEF application on ISO14443-4 cards; it only activates ISO14443-4 (RATS). `detect_card_type_and_capacity()` reports such cards as byte-addressed with unknown size (`block_size` 1, `blocks_count` 0) instead of assuming 4096 bytes. Code that read a Type 4 tag through `block_read()` right after selecting has to select the files itself, or use `pn5180_ndef_read_card_auto()`.
- Cards that emulate MIFARE Classic on an ISO14443-4 chip (SAK 0x28 / 0x38) are not activated as ISO14443-4 any more, so MIFARE authentication works on them. Set the subtype to `PN5180_MIFARE_DESFIRE` before `select_by_uid()` to use their ISO14443-4 side.
- `pn5180_uid_t` has a new `atqa` field and `pn5180_card_type_t` two new values (`PN5180_MIFARE_NTAG210`, `PN5180_MIFARE_NTAG212`); `pn5180_t` lost the `iso14443_ndef_checked` / `iso14443_ndef_detected` fields.
- NDEF parsing is stricter: a reserved TNF (0x07), an unknown-type record with a type, an empty record with content, a missing Message End flag and malformed chunk sequences are rejected.

New:

- **`pn5180_ndef_read_card_auto()`** reads the NDEF message of the selected card by its type: Type 2 (Ultralight, NTAG) bounded by the capability container, MIFARE Classic through the MIFARE Application Directory (MAD1 / MAD2) with the public keys, Type 4 (NDEF application, capability container file, NDEF file) and Type 5 (ISO15693). A failed read is retried once after selecting the card again.
- **`pn5180_ndef_parse_message()`** parses an encoded message and reassembles chunked records. `PN5180_NDEF_ERR_UNSUPPORTED` for card types without NDEF mapping.
- **Public ISO14443-4 API**: `pn5180_14443_4_transceive()`, `pn5180_14443_4_select_file()` (P2=0x0C with fallback to 0x00), `pn5180_14443_4_read_binary()`, and the hardware-independent APDU helpers `pn5180_apdu_parse_command()`, `pn5180_apdu_parse_response()`, `pn5180_apdu_build_response()`, `pn5180_apdu_get_status()`.
- **Poll status**: `pn5180_14443_get_all_uids_ex()` and `pn5180_15693_get_all_uids_ex()` tell "no card" apart from a transport failure, a protocol error and an allocation failure.
- **MIFARE Classic value blocks**: `pn5180_mifare_value_read()`, `pn5180_mifare_value_write()`, `pn5180_mifare_increment()`, `pn5180_mifare_decrement()`, `pn5180_mifare_restore()`, `pn5180_mifare_transfer()`.
- **Card identification**: MIFARE Ultralight C is told apart from Ultralight (it answers AUTHENTICATE with a challenge); NTAG210 and NTAG212 are told apart from Ultralight EV1 by the product type of GET_VERSION.
- **Host tests** in `host_test/`: the protocol code runs on the host against simulated cards (NTAG, Ultralight C, MIFARE Classic, ISO14443-4 with a Type 4 application, ISO15693) under AddressSanitizer. `make -C host_test test IDF_PATH=<esp-idf>`.

ISO14443-4 fixes:

- After a timeout or a damaged frame the reader sends R(NAK) (R(ACK) while the card is chaining) instead of repeating the I-block, and repeats the I-block only when the card's R(ACK) shows that it was not received.
- Commands longer than the card's frame size are chained.
- RATS announces 256-byte frames (FSDI 8) instead of 64.
- `halt()` releases an ISO14443-4 card with S(DESELECT).
- A waiting time extension applies to one block only and is capped at the longest frame waiting time (4949 ms).
- After HLTA the driver waits 1.1 ms before the next command, as the NXP reader library does.

Other changes:

- `pn5180_delay_ms()` is precise below a FreeRTOS tick: whole ticks are slept, the remainder is a busy wait. It used to round every delay up to whole ticks.
- Without an IRQ pin the driver polls once per millisecond after the first 5 ms, sleeping on a high-resolution timer in between (it slept a whole tick before).
- `detect_card_type_and_capacity()` leaves an Ultralight family card halted on every path, so the caller's `select_by_uid()` always works afterwards.
- The `app_logic` example reads NDEF with `pn5180_ndef_read_card_auto()` and selects the card again after a refused read.
- README restructured: quick start, common tasks, troubleshooting, reference.

## v 0.3.0 - 2026-10-07

### Hardware receive timeout, common RF exchange, IRQ pin, shared SPI bus; all public names prefixed

Breaking changes:

- Every public name now carries the component prefix. Types: `nfc_uid_t` is `pn5180_uid_t`, `nfc_uids_array_t` is `pn5180_uids_array_t`, `nfc_type_t` is `pn5180_card_type_t`, the callback types `func_*_t` / `funct_*_t` are `pn5180_func_*_t`. Register, IRQ flag, RX status and EEPROM address macros got the `PN5180_` prefix (`IRQ_STATUS` is `PN5180_IRQ_STATUS`, `RX_IRQ_STAT` is `PN5180_RX_IRQ_STAT`, `FIRMWARE_VERSION` is `PN5180_FIRMWARE_VERSION`, `MIFARE_CLASSIC_KEYA` is `PN5180_MIFARE_CLASSIC_KEYA`, and so on). There are no compatibility aliases.
- camelCase is gone from the API. Functions: `pn5180_writeRegister()` is `pn5180_write_register()`, `pn5180_writeRegisterWithOrMask()` / `...WithAndMask()` are `pn5180_write_register_or_mask()` / `pn5180_write_register_and_mask()`, `pn5180_readRegister()` is `pn5180_read_register()`, `pn5180_readEEprom()` / `pn5180_writeEEprom()` are `pn5180_read_eeprom()` / `pn5180_write_eeprom()`, `pn5180_sendData()` / `pn5180_readData()` are `pn5180_send_data()` / `pn5180_read_data()`, `pn5180_sendCommand()` is `pn5180_send_command()`, `pn5180_clearAllIRQs()` is `pn5180_clear_all_irqs()`, `pn5180_clearIRQStatus()` / `pn5180_getIRQStatus()` are `pn5180_clear_irq_status()` / `pn5180_get_irq_status()`, `pn5180_getTransceiveState()` is `pn5180_get_transceive_state()`, `pn5180_loadRFConfig()` is `pn5180_load_rf_config()`, `pn5180_setRF_on()` / `pn5180_setRF_off()` are `pn5180_set_rf_on()` / `pn5180_set_rf_off()`, `pn5180_mifareAuthenticate()` is `pn5180_mifare_authenticate()`, `pn5180_rxBytesReceived()` is `pn5180_rx_bytes_received()`, `pn5180_prepareLPCD()` is `pn5180_lpcd_prepare()`, `pn5180_switchToLPCD()` is `pn5180_lpcd_enter()`. Transceiver state values are upper case: `PN5180_TS_WaitTransmit` is `PN5180_TS_WAIT_TRANSMIT`, and so on.
- `rf_config` moved from `pn5180_t` to `pn5180_proto_t`: each protocol object keeps its own RF configuration and `setup_rf()` loads it. Code that assigned `proto->pn5180->rf_config` before calling `setup_rf()` has to drop that line.
- `pn5180_wait_read_rx()` (internal header) is removed; use `pn5180_rf_transceive()`.

New:

- **Receive timeout on PN5180 Timer1.** The timer starts when the transmission ends and stops when a reception begins, as in the NXP reader library. A missing card is now reported after a few milliseconds instead of after the 500 ms host timeout, and timing no longer depends on how fast the host polls. `pn5180_set_hw_rx_timeout(pn5180, false)` switches back to a host-side timeout.
- **`pn5180_rf_transceive()`**: one public function to send a frame and receive the response, with an explicit timeout and a result that tells timeout, collision, RX error, overflow and SPI failure apart. ISO14443A, ISO14443-4, MIFARE and ISO15693 code all go through it.
- **Optional IRQ pin**: `pn5180_irq_attach(pn5180, gpio)`. With the pin, waits block on the interrupt; without it the driver polls as before, now yielding to other tasks after the first 5 ms. The pin polarity is read from EEPROM.
- **Shared SPI bus**: `pn5180_spi_attach(host, clock_hz)` adds the PN5180 to a bus the application initialized, and never frees that bus. Each command holds the bus for its two SPI transfers, so other devices cannot get in between. `pn5180_spi_deinit()` releases an SPI structure that is not owned by a `pn5180_t`.
- **`pn5180_recover()`**: reset the reader and restore the RF configuration and field state.
- **Guard time after field on**, 5.1 ms by default, `pn5180_set_rf_guard_time_us()`.
- **RF collision avoidance option**: `pn5180_set_rfca(pn5180, false)` switches the field on even if another field is present.
- **LPCD**: `pn5180_lpcd_wait()` waits for the wake-up on the IRQ pin and reloads the RF configuration afterwards (the PN5180 loses its registers in LPCD mode). `pn5180_lpcd_enter()` now sets the reference value in `AGC_REF_CONFIG`, which self calibration needs and which was never written before. `pn5180_lpcd_prepare()` writes an EEPROM byte only if it differs.

Behaviour changes to be aware of:

- `get_all_uids()` and failed selects return much faster when no card is present. Polling loops that relied on the old 500 ms wait as their pacing need their own delay.
- Timeouts are fixed per command (5 ms for activation, 10 ms for reads, 20 ms for write acknowledges, 10/40 ms for ISO15693 read/write); ISO14443-4 uses the frame waiting time from the ATS. `pn5180_t.timeout_ms` now only bounds SPI and BUSY handling.
- A SELECT answer (SAK) and an ATS with a CRC error are rejected; a missing answer is no longer logged as an error for card polling.
- `pn5180_reset()` accepts a boot without IDLE IRQ if EEPROM says that the IDLE IRQ after boot is disabled.
- GPIOs are set up with `gpio_config()`.

## v 0.2.0 - 2026-10-07

### NDEF API moved to the `pn5180_ndef_` namespace; bug fixes from a code review

The review compared the driver with the PN532 component, the NXP reader library and the datasheets.

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
