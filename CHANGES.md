# Changelog

## v 0.8.2 - 2026-11-06

Fixes from a review of 0.8.1.

Fixes:

- **ISO14443-4: a card left in its session no longer answers for the next one.** `select_by_uid()` dropped the session state without telling the card. A card in its ISO14443-4 session ignores WUPA, the anticollision and RATS, but answers every I-block whatever its block number (ISO/IEC 14443-4), so after a second card was selected without `halt()` in between, both answered its APDUs: the NDEF read of the second card could return the message of the first under the second UID, or fail where the answers collided. A poll with the field left on sent the halt of the first card it found to the old card as S(DESELECT), left the new card selected and ended early. `select_by_uid()` and the ISO14443A poll now close such a session with S(DESELECT) before they send anything else. `examples/app_logic` read the cards of a poll one after the other without `halt()`; it now halts each one.
- **Build: a component that requires pn5180 compiles with ESP-IDF 6.** `pn5180.h` includes `driver/gpio.h` and `driver/spi_master.h`, but `esp_driver_gpio` and `esp_driver_spi` were private requirements, and since ESP-IDF 6.0 `driver` no longer passes them on: a component with `REQUIRES pn5180` failed with `driver/gpio.h: No such file or directory`. The examples name those components themselves, which hid it. They are public requirements now (ESP-IDF 5.3 and later); `driver` stays one too.
- **Type 2: a tag without GET_VERSION gets the data area its capability container declares.** Such a tag is detected as Ultralight, and the NDEF functions took that for a size of 16 pages: an NTAG203 (144 bytes) read a message above 48 bytes as `PN5180_NDEF_ERR_PARSE_FAILED` and refused to write one with `PN5180_NDEF_ERR_CARD_FULL`. The Ultralight subtype is a guess, so the capability container alone bounds the data area now, as in the PN532 component. A GET_VERSION answer that arrives damaged (anything but no answer or a NAK) is asked for once more, instead of taking an NTAG for an Ultralight.
- **ISO15693: a tag behind a stronger one is found.** The receiver takes an answer under half as strong as another one for no signal (PN5180 datasheet), so the stronger tag's answer arrived clean, the inventory took it for the only tag under that mask and never asked the field again: with the field reset before each poll the weaker tag never appeared. A pass that found tags is now followed by one more inventory of the whole field, which costs one frame when no tag is left.
- **ISO14443A: one lost HLTA no longer ends the poll.** A card that answered again after its HLTA ended the scan, and the cards not found yet were missed. It is halted once more and the poll goes on; a second repeat ends it, so a card that ignores HLTA still cannot keep the poll going.
- **ISO14443A: a failed anticollision leaves no card half-selected.** The cards stayed in the middle of the anticollision and ignored the REQA of the next poll, which reported `PN5180_POLL_NO_TARGET` with the field left on. They are sent back to IDLE with HLTA, as when a poll stops at `max_cards`.
- **Cards with MIFARE Classic emulation (SAK `28h`, `38h`): the ISO14443-4 side the caller chose survives type detection.** `detect_card_type_and_capacity()` set the subtype back to Classic after the card had been activated as `PN5180_MIFARE_DESFIRE`, so `pn5180_ndef_read_card_auto()`, called as in the Quick Start, sent MIFARE commands into the ISO14443-4 session and failed.
- **`setup_rf()` checks that the field is really on.** Since 0.6.0 `pn5180_set_rf_on()` does not take the cached flag on trust, but `setup_rf()` of both protocols returned early on that flag when the right RF configuration was loaded: a field that had dropped showed up as `PN5180_POLL_NO_TARGET`. Now the field is switched on again, and the poll reports `PN5180_POLL_TRANSPORT_ERROR` when it cannot be. It costs one register read per call.
- **ISO14443-4: FWI 15 is read as 4.** The reserved value was taken as 14, the longest frame waiting time, so each lost frame cost about 5 s. ISO/IEC 14443-4 and the NXP reader library read it as the default 4, as the driver already did with SFGI 15.
- **ISO15693: a failed allocation is `PN5180_POLL_NO_MEMORY`.** The UID was dropped silently and the tag silenced, so it was lost for the poll. The inventory now stops there, leaves the tag unsilenced and reports `PN5180_POLL_NO_MEMORY` if it found nothing.
- **ISO15693: the inventory needs 0.8 KB of stack instead of 1.7 KB.** An entry of its search stack took 24 bytes and now takes 10.
- **NDEF: `pn5180_ndef_encode_message(msg, NULL, n)` returns the size for any `n`**, as the header says; it returned 0 for an `n` above 0.
- **NDEF: a chunked Empty record is refused.** Its chunks gave a record of type Empty a payload, which it must not have.
- **MIFARE Classic: an NDEF TLV longer than the sectors the directory lists is `PN5180_NDEF_ERR_PARSE_FAILED`**, as on Type 2 and Type 5 tags; it was `PN5180_NDEF_ERR_NO_NDEF`.
- Examples: the ISO14443A protocol object is freed when the ISO15693 one cannot be created.

Documentation:

- README "Task stack": the driver's frames measured with `-fstack-usage`, about 1.5 KB on the deepest paths; the figure of about 800 bytes was counted from buffer sizes and left out the ISO15693 inventory.
- `pn5180-15693.h`, `pn5180.h`, README: which statuses the ISO15693 poll reports; there is no `PN5180_POLL_PROTOCOL_ERROR`, because the PN5180 reports noise the way it reports damaged answers.
- README: sessions that `select_by_uid()` and `get_all_uids()` close, tags without GET_VERSION, the repeated inventory, and that an ISO15693 tag brought back to Ready by `select_by_uid()` and `halt()` is counted again by the next poll.
- `pn5180-ndef-tlv.h`: `pn5180_ndef_tlv_find_ndef()` returns true once type and length of the NDEF TLV are found; the value may run past the end of the buffer.
- README "Read NDEF": how much memory a read takes; the driver sets no limit of its own, and a 32 KB Type 4 message of the smallest records takes about 320 KB at the peak.

Host tests of the reader layer: `src/pn5180.c` had none, because the protocol tests replace it. A second program runs it against stand-ins of the ESP-IDF SPI master, GPIO, esp_timer and semaphores, with a model of the PN5180 host interface behind them: SPI framing and BUSY, boot, firmware and pin checks, the field and RF collision avoidance, the results of `pn5180_rf_transceive()` for each receiver status, the Timer1 reload values, MIFARE authentication, recovery, EEPROM writes, the IRQ pin and the length of the driver's waits (29 tests).

Host tests of the protocol code: a second ISO14443-4 card selected without halting the first, a poll with an ISO14443-4 session left open, a lost HLTA, a failed anticollision, the ISO14443-4 side of a SAK `28h` card through type detection, FWI 15, an NTAG203, a damaged GET_VERSION answer, a field that dropped, a Classic NDEF TLV longer than its sectors, an ISO15693 tag behind a stronger one, the size query of the encoder and a chunked Empty record. The simulated ISO14443-4 card ignores everything but valid blocks while in its session, as the standard asks, and the fake field can drop.

## v 0.8.1 - 2026-11-04

Brought over from the PN532 component (0.8.2 and the fixes after it).

Fixes:

- **MIFARE Classic: an NDEF sector with a factory trailer is read again.** Since 0.5.0 the general purpose byte of the first NDEF sector was checked whichever key opened it. A sector that only the default key `FF FF FF FF FF FF` opens was never NFC formatted (formatting writes the NFC key and GPB `40h`) and keeps its factory trailer, `FF 07 80 69`: GPB `69h` has read access `10b`, so the card was reported as `PN5180_NDEF_ERR_ACCESS_DENIED`. The byte is now checked only on a sector the NFC key `D3 F7 D3 F7 D3 F7` opens, as in NxpNfcRdLib phalTop, which opens NFC sectors with that key only and takes `69h` for a blank sector. A default-key sector costs one READ fewer.
- **MIFARE Classic: a refused key is told from a lost card.** The PN5180 reports a refused key as authentication status 1 ("permission denied") and a card that did not answer as status 2 (datasheet, table 26), but both counted as a refused key. A card that left the field at the MAD key gave a definite `PN5180_NDEF_ERR_NO_NDEF` without a second attempt, and the second key was tried on a card that was gone. Now only status 1 is a refused key. A card that does not answer the authentication of a directory or NDEF sector is `PN5180_NDEF_ERR_READ_FAILED`, the read is repeated once after a new select, and no second key is tried on it.
- **MIFARE Classic: NDEF sectors that turn down both public keys are `PN5180_NDEF_ERR_ACCESS_DENIED`.** They were `PN5180_NDEF_ERR_READ_FAILED`, so the whole read ran a second time to the same end. NxpNfcRdLib phalTop takes such a tag as misconfigured, without a retry either.
- **Type 4: a SELECT answer without a status word is a read error.** An answer shorter than two bytes left the ISO14443-4 session open and was taken for a card that refused the application or file: `PN5180_NDEF_ERR_NO_NDEF` after one exchange. Only a refusal with a status word means no NDEF now; anything else is `PN5180_NDEF_ERR_READ_FAILED` and is repeated once.
- **Pins are checked.** `pn5180_spi_init()` put MISO into the 64-bit `gpio_config()` mask unchecked, which for `GPIO_NUM_NC` is a shift by -1, and `pn5180_irq_attach()` did the same with its pin. `pn5180_init()` refused only negative numbers. Now `pn5180_init()` and `pn5180_spi_init()` return NULL, and `pn5180_irq_attach()` false, for a pin that is not a GPIO of the chip or for a driven pin (NSS, RST, SCK, MOSI) on an input-only GPIO, before the PN5180 or the SPI host is touched. Results of `gpio_config()` are checked. `pn5180_irq_attach()` and `pn5180_mifare_authenticate()` return at once for a NULL device, the latter also for a NULL key or UID.

New:

- **`pn5180_t.iso14443_last_auth_status`**: the result of the last MIFARE Classic authentication, as `pn5180_mifare_authenticate()` returns it, with the constants `PN5180_MIFARE_AUTH_OK`, `PN5180_MIFARE_AUTH_REFUSED`, `PN5180_MIFARE_AUTH_NO_ANSWER` and `PN5180_MIFARE_AUTH_NONE` (nothing was sent). It tells a refused key from a lost card after the `authenticate` callback returned false.

Changes:

- **The driver's own waits release the CPU.** The guard time after the field goes on (5.1 ms), the time the field stays off when a protocol is set up again (5.1 ms), the start-up frame guard time of ISO14443-4 cards, the inventory jitter of ISO15693 and the waits of reset and field on now sleep on the high-resolution timer the device already has for polling. They ended with a busy wait of up to one RTOS tick, and the waits below a tick, the guard times among them, were busy waits altogether; they now end at most some tens of microseconds late, never early. `pn5180_delay_ms()` and `pn5180_delay_us()` are unchanged.
- Examples: each key and key type of the MIFARE Classic dump costs one authentication, and the card is selected again only after a refusal. `examples/app_logic` authenticated twice per key with a select in between, the second time with the key just refused, and sent the next key to a card out of the active state. The pause between polls is `vTaskDelay()`, as in the README.

Documentation:

- README and `pn5180-ndef.h`: which keys open which MIFARE Classic sectors, which first NDEF sector has its general purpose byte checked, which failures are read again and which are not; troubleshooting entries for `PN5180_NDEF_ERR_ACCESS_DENIED` on a Classic card and for pins `pn5180_init()` refuses. `pn5180.h` and the README: what `iso14443_last_auth_status` says after a failed authentication, and how the driver waits.

Host tests: a Classic sector behind a factory trailer, read with one READ fewer; GPB `69h` behind the NFC key still read protected; a card that misses the authentication of the directory or of an NDEF sector once (read again) and twice (read error); an NDEF sector and a directory sector that turn down both keys; the authentication status after a refusal, a missing answer and a card type without authentication; Type 4 SELECT answers without a status word, and a card that refuses the NDEF application.

## v 0.8.0 - 2026-11-02

Brought over from the PN532 component (0.8.0, 0.8.1).

Breaking change:

- **`pn5180_ndef_extract_text()` takes the size of `lang_buf`**: the new argument `lang_buf_len` follows `lang_buf`. The card sets the length of the language code, up to 63 bytes, and the function copied it into a buffer of unknown size; the header asked for 64 bytes, and a smaller buffer overflowed. The code is now truncated to fit and always NUL-terminated, as in `pn5180_ndef_extract_uri()`; the text pointer and length do not depend on it. A call in the old form no longer compiles: add `sizeof(lang)` after the buffer, or `0` after `NULL`.

Fixes:

- **`pn5180_spi_attach()` works on a host the application has just initialized.** ESP-IDF answers `spi_bus_get_max_transaction_len()` only after the first `spi_bus_add_device()` on a host, so `spi_bus_initialize()` followed by `pn5180_spi_attach()`, the setup the README shows, returned NULL since `pn5180_spi_attach()` appeared in 0.3.0, unless another device was on the host already. The transaction size is now checked once the PN5180 is on the host; a host that cannot carry a transfer is refused as before and keeps no device.
- **MIFARE Classic: a failed READ of the directory is a read error** (`pn5180_ndef_read_card_auto()`), as in NxpNfcRdLib phalTop. After the MAD key was accepted it means that the card left the field or fell back to IDLE, so the read is now repeated after a new select instead of reporting `PN5180_NDEF_ERR_NO_NDEF`. The fallback that assumed MAD version 1 when the trailer of the MAD sector could not be read is gone: it went on reading from a card in IDLE and could not succeed. A MAD sector no key opens is still no NDEF.

Packaging:

- **The manifest asks for ESP-IDF 5.0.4 or later.** It said 5.0.0 and the README "5.x", but 5.0.0 to 5.0.3 lack `spi_bus_get_max_transaction_len()`, which the driver calls since 0.3.0, so the component did not build there.
- The `files` section of the manifest is an explicit list: the component archive holds the sources, the headers, the examples, the README, the change log and the license. `host_test/`, `.clang-format` and `.gitignore` stay in the repository.

Documentation:

- `pn5180_ndef_extract_text()` and `pn5180_ndef_extract_uri()` leave the buffer as it was when the record is not of their type.
- Type 4: `pn5180_ndef_read_card_auto()` selects the NDEF application of mapping 2.0 and later (AID `D2 76 00 00 85 01 01`), as NxpNfcRdLib does; a mapping 1.0 tag, which has another AID, reads as `PN5180_NDEF_ERR_NO_NDEF`. The README suggested otherwise.
- Two readers may run in separate tasks; readers with close antennas take turns with the field.
- `pn5180_spi_attach()` may be called right after `spi_bus_initialize()`.
- From a check of the whole documentation: `pn5180_t.timeout_ms` bounds the waits for the PN5180 itself, not only SPI and BUSY; `examples/app_logic` needs `idf.py set-target esp32s3`, its GPIOs 6 to 8 belong to the flash of a classic ESP32; the headers named the key constants without their `PN5180_` prefix; `pn5180_deinit()` frees only a bus that `pn5180_spi_init()` initialized; the LPCD wake-up interval is 1 to 2690 ms; the descriptions of `PN5180_NDEF_ERR_NO_NDEF` and `PN5180_NDEF_ERR_UNSUPPORTED` cover all their causes.
- `examples/ndef` uses `pn5180_ndef_extract_uri()` and `pn5180_ndef_extract_text()` instead of its own decoding, which knew 5 of the 36 URI prefixes.

Host tests: a 63-byte language code against a short buffer, a 64-byte buffer, a size of 0 and no buffer; buffers of another record type left untouched; a lost READ of the MAD sector trailer and of each MAD1 block, once (read again) and twice (read error).

## v 0.7.2 - 2026-11-01

Packaging only, no code changes. 0.7.0 and 0.7.1 were removed from the ESP Component Registry, so this is the first version there with the changes listed under them, among them the new `max_cards` argument of `pn5180_14443_init()`.

- The component archive holds the files of the repository and nothing else. It also took local notes, a local installer configuration and generated files from the build directories of the examples.
- The README says that a `max_cards` below the number of cards leaves no card out for good.

## v 0.7.1 - 2026-11-01

Documentation only, no code changes.

- Multi-card polling is up front now: in the first lines of the README, first in its feature list, in the component description and tags, and with a section of its own, "Several cards in the field".
- The feature list of the README still said "up to 14 cards per scan", which 0.7.0 left behind. It names `max_cards` and the limit of the ISO15693 inventory now.

## v 0.7.0 - 2026-11-01

- **`pn5180_14443_init()` takes a new argument `max_cards`**, the most cards one poll enumerates. 0 keeps the limit of 14 cards, which was fixed so far although no standard or chip limit stands behind it; a negative value returns NULL. The limit only ends the poll for a card that ignores HLTA and shows a new UID every time.
- **The ISO14443A anticollision takes the collision bit at random.** It always took 1, so the same card won every time: with a limit below the number of cards and the field reset before every poll, the same cards were found and the others never showed up. Now every card turns up over several polls, though not equally often. The order of the cards in the result changes from poll to poll.
- A poll that leaves cards out logs a warning: ISO14443A when one more card answered at the limit, ISO15693 when the inventory ran out of its 192 frames. Both stopped silently.
- The README said that at most 14 cards are enumerated. That never was true for ISO15693, which has no limit on cards, only on inventory frames.

## v 0.6.0 - 2026-10-30

### Brought over from the PN532 component (0.7.4, 0.7.5)

Behaviour changes to be aware of:

- **New result `PN5180_NDEF_ERR_READ_ONLY` (-11), as in the PN532 component.** `pn5180_ndef_write_card_auto()` returns it for a tag without write access (Type 2 access byte 0Fh, Type 5 access 3h); it was `PN5180_NDEF_ERR_ACCESS_DENIED`, which now stands for read protection only. Code that checks the result of a write has to follow.
- **Type 2 NDEF read goes around lock and reserved bytes.** Bytes that Lock Control and Memory Control TLVs place inside the data area are not part of the TLV stream: the TLV walk and the message continue behind them, as in NxpNfcRdLib phalTop. Such a message returned `PN5180_NDEF_ERR_UNSUPPORTED`. The bytes are skipped one by one, as in the PN532 component; NxpNfcRdLib skips whole blocks, which makes a difference only for an area that does not fill its blocks. A length that fits the data area only with those bytes counted is `PN5180_NDEF_ERR_PARSE_FAILED`. Factory NTAG21x and Ultralight C tags are not affected: their lock bytes lie behind the data area.
- **Type 2 NDEF write is refused only if it would touch lock or reserved bytes.** The check covered everything from the NDEF TLV to the end of the data area, so a short message in front of such bytes returned `PN5180_NDEF_ERR_UNSUPPORTED` for no reason. It now covers the blocks to write, whole: bytes that only share the last block with the Terminator TLV count as touched.
- Up to six control TLVs are followed, as many as NxpNfcRdLib keeps (three of each kind); it was four.
- `authenticate()` of a MIFARE Classic card returns false for a block number outside 0..255, which used to be cut to 8 bits (256 authenticated block 0), and for a UID shorter than 4 bytes.
- `pn5180_ndef_make_mime_record()` and `pn5180_ndef_make_external_record()` return false for `data == NULL` with a non-zero length; the record was built and refused later by the encoder.

Fixes:

- An ISO14443-4 session counts as closed whenever the field is gone. `pn5180_reset()`, entering LPCD and `pn5180_set_rf_on()` finding the field off left it marked as open until the next select: `block_write` was refused, and an APDU waited for a card that could not answer. Only `pn5180_recover()` and `pn5180_set_rf_off()` closed it.
- `pn5180_reset()` documents what a reset drops and that `pn5180_recover()` brings the RF configuration and the field back.

Host tests: reading around lock and reserved bytes (inside the message, between the T and the L byte, inside a TLV in front of the NDEF TLV, two areas that touch, six and seven control TLVs); writing up to the block in front of reserved bytes; `authenticate()` and record builder arguments.

### Fixes from a review of 0.5.2

Behaviour changes to be aware of:

- ISO14443-4 activation sends RATS once. ISO 14443-4 allows one RATS per activation: a card that received the first one ignores any repetition, so the three attempts only added about 50 ms before failing. Recovery stays with the callers, which select the card again (WUPA).
- `pn5180_set_rf_on()` no longer trusts the cached field state: it reads TX_RF_STATUS also when it believes the field is on. A field that dropped for a reason the driver did not cause (RFCA, an external reset) now makes `setup_rf` fail instead of letting every poll return NO_TARGET.
- `pn5180_load_rf_config()` with 0xFF ("no change") is no longer recorded as the configuration to restore: a later `pn5180_recover()` or LPCD wake-up would have reloaded 0xFF, which reloads nothing.
- ISO15693 `setup_rf` does not switch the field off and on when the requested configuration is already loaded, like the ISO14443-A one always did. A poll with the preferred ASK 10 % configuration loaded saves about 10 ms of dead time and does not reset the tags in the field.
- `pn5180_init()` rejects `GPIO_NUM_NC` (-1) for NSS, BUSY and RST. The shift `1ULL << pin` with pin -1 is undefined behaviour.

NFC Forum Type 4:

- The NDEF Tag Application Select carries Le = 00h (a case 4 APDU, the FCI may follow). It was sent without Le; most cards tolerate that, but a strict tag or an HCE app answers 6700. A select by file identifier stays without Le, as before. (The PN532 component already sent it this way.)

MIFARE:

- MIFARE keys are no longer printed with `PN5180_DEBUG` enabled.

EEPROM:

- `PN5180_EEPROM_MAX_ADDR` is 254 (0xFE). The datasheet says for READ_EEPROM and WRITE_EEPROM: "EEPROM Address must be in the range from 0 to 254, inclusive." The constant was 253 (0xFD), which refused the last byte; the 0.5.2 changelog wrongly claimed the datasheet said 253.

Hardening:

- `pn5180_reset()` makes the announced three boot attempts, not two.
- `stream_append()` with a zero count no longer calls `memcpy` with a NULL destination on an empty stream (undefined behaviour; the host tests run UBSan with `-fno-sanitize-recover=undefined`).

Logging:

- Card found, direct-path select and ISO15693 tag found/AGC messages are debug level now, so a poll no longer writes the log. The internal reselects inside NDEF reads had been writing an INFO line each.

Deprecation:

- `pn5180_ndef_read_from_selected_card()` is deprecated in the header; use `pn5180_ndef_read_card_auto()`, which knows the block layout of every supported card type.

Host tests:

- The fake transceiver follows the CRC bits of `CRC_TX_CONFIG` / `CRC_RX_CONFIG`: the answer to a CRC request carries a CRC, which is checked and stripped, and the 4-bit ACK/NAK stays without one. A driver mistake in the CRC ordering shows up as an RX error now.
- A two-card ISO14443A simulator (`sim_a_field`) collides the anticollision bit by bit, with the collision position relative to the first FIFO byte as the PN5180 reports it. The bit-level branch of `pn5180_14443_anticollision_level` (RX_BIT_ALIGN, collision position, split-byte merge) runs in the tests now.
- The fake counts the RF-on switches, and a test checks that an ISO15693 poll with the preferred configuration loaded does not cycle the field.

## v 0.5.2 - 2026-10-12

### Fixes from a review of 0.5.1

Behaviour changes to be aware of:

- ISO15693 inventory no longer makes a second pass at the low data rate. The PN5180 has no receive configuration for it, so the pass could not find a tag and only doubled the time of an empty scan. The field `iso15693_use_high_rate` of `pn5180_t` is removed.
- ISO15693 inventory takes a UID only from a response received without errors. A response with a CRC or protocol error was accepted if it was long enough, so a damaged frame could be reported as a tag. Such a response is now asked for again, up to three times.

ISO15693:

- Collision resolution goes on to the full 64 bits of the UID; it stopped at a mask of 16 bits, so tags with the same first 16 transmitted UID bits were not told apart. The scan limit is 192 inventory requests instead of 64.
- `block_read()` and `block_write()` refuse a negative block number and one above 65535. They were cut to one or two bytes and addressed another block.

NDEF:

- `pn5180_ndef_message_add()` returns false for a message initialized without a record array; it wrote through the NULL pointer.

Examples:

- `examples/app_logic` frees the NDEF message it has read; every successful read leaked it.
- `examples/app_logic` and `examples/simple_main` release the SPI structure when `pn5180_init()` fails, and name `esp_driver_spi` and `esp_driver_gpio` as requirements only from ESP-IDF 5.3 on, like the component does.
- `examples/ndef/main/ndef_read_example.c` reads with `pn5180_ndef_read_card_auto()`. It called `pn5180_ndef_read_from_selected_card()` from page 4 with 16-byte blocks, which on a Type 2 tag reads overlapping pages and damages any message longer than the first read.

Documentation:

- `pn5180_read_eeprom()` / `pn5180_write_eeprom()`: the last EEPROM address is 254 (`PN5180_EEPROM_MAX_ADDR`), not 255. (Corrected again in 0.6.0: the datasheet says 254, and the constant is 0xFE now.)
- `pn5180_ndef_read_from_selected_card()`: `max_blocks` of 0 means the default limit of 256 blocks, not "no limit".

Component name in the ESP Component Registry (`jef-sure/pn5180`; `esp32-component-pn5180` is the name of the repository):

- README: the install command is `idf.py add-dependency "jef-sure/pn5180^0.5.2"`. It named `jef-sure/esp32-component-pn5180`, which the registry does not have.
- `examples/app_logic` and `examples/simple_main` depend on `jef-sure/pn5180`. With the old name a project made with `idf.py create-project-from-example` asked for a component that does not exist. Inside the repository the examples take the component from the repository itself and switch the component manager off, so they build whatever the directory of the clone is called.

## v 0.5.1 - 2026-10-07

### Fixes from a review of 0.5.0

Behaviour change to be aware of:

- `pn5180_ndef_decode_message()` and `pn5180_ndef_decode_smartposter()` return 0 for a message with more records than the array holds. They used to return the first `capacity` records without a sign that the rest was missing.

NDEF:

- Type 2: the data area ends with the user memory of the detected tag (page 15 of an Ultralight, NTAG210 and the small Ultralight EV1, 35 of an NTAG212 and the large Ultralight EV1, 39 of an Ultralight C and NTAG213, 129 of an NTAG215, 225 of an NTAG216). It was bounded by the number of pages, so on a tag whose capability container promises more than the tag has, a long message reached the lock, configuration and password pages.
- Type 2: a Lock Control or Memory Control TLV with the size `00` names 256 bits or bytes; it was taken as an empty area. If these bytes lie inside the data area the tag is `PN5180_NDEF_ERR_UNSUPPORTED`, as for any other size.
- `pn5180_ndef_decode_message()` checks the message structure like `pn5180_ndef_parse_message()`: Message Begin on the first record only, Message End on the last one, nothing after it, valid chunk sequences. It used to accept a message without Message Begin or Message End. Chunks are still returned as separate records.

ISO15693:

- The CRC is switched on for every request. Select, Reset to Ready (`halt`), Stay Quiet and Get System Information relied on an inventory or a block read having done it before.

## v 0.5.0 - 2026-10-07

### NDEF writing reworked and NDEF checks aligned with the NXP reader library; fixes from two comparisons with the PN532 component and from an external review

Behaviour changes to be aware of:

- NDEF reading is stricter. A tag that declares an unknown mapping version or non-standard access conditions is now `PN5180_NDEF_ERR_UNSUPPORTED` where the driver used to read it anyway; details under "NDEF" below.
- `pn5180_ndef_write_card_auto()` writes into the NDEF TLV the tag has. A tag without one (not NDEF formatted) is refused, where the old function wrote wherever it was told to.
- ISO15693 inventory makes one pass if the first RF configuration finds tags, and leaves that configuration (ASK 10 %) loaded.
- The `block_write` callback is refused for ISO14443-4 cards, and `block_read` fails on a short answer from ISO14443-4 and ISO15693 cards.

Breaking change:

- **`pn5180_ndef_write_card_auto(proto, &uid, &message)`** replaces `pn5180_ndef_write_to_selected_card(proto, &message, start_block, block_size, max_blocks)`. Like `pn5180_ndef_read_card_auto()` it takes the selected card and finds the data area in the capability container of the tag, for Ultralight / NTAG (Type 2) and ISO15693 (Type 5). The old function wrote consecutive blocks of any size the caller named: on a MIFARE Classic card a message of more than 46 bytes written from block 4 ran into the sector trailer and overwrote the keys and access bits. MIFARE Classic and ISO14443-4 cards are now `PN5180_NDEF_ERR_UNSUPPORTED`.

NDEF:

- Writing follows the procedure of the NXP reader library (`phalTop`):
  - The capability container is checked: a tag without one is `PN5180_NDEF_ERR_NO_NDEF`, a read-only tag `PN5180_NDEF_ERR_ACCESS_DENIED`, an unknown mapping version or proprietary access conditions `PN5180_NDEF_ERR_UNSUPPORTED`.
  - The message is written into the NDEF TLV the tag already has, and the TLVs in front of it are kept. The old function wrote from the block the caller named, which on an NTAG as it leaves the factory overwrote the Lock Control TLV. A tag without NDEF TLV is `PN5180_NDEF_ERR_NO_NDEF`.
  - The TLV length is set to 0 first and to the real length last, so a write that stops halfway leaves an empty message. The length used to be written first, in front of old data.
  - A message that does not fit between the NDEF TLV and the end of the data area is `PN5180_NDEF_ERR_CARD_FULL`; the Terminator TLV is written only if there is room for it. The size of the data area was not checked before.
  - A Type 2 tag whose control TLVs put lock or reserved bytes inside the data area is `PN5180_NDEF_ERR_UNSUPPORTED`.
- Reading follows the checks of the NXP reader library as well:
  - Type 2 and Type 5: a capability container with an unknown major version or with proprietary or reserved access conditions is `PN5180_NDEF_ERR_UNSUPPORTED`; a Type 2 data area below 48 bytes is `PN5180_NDEF_ERR_NO_NDEF`. Neither was checked before.
  - Type 2: more than three NULL TLVs in a row end the search (`PN5180_NDEF_ERR_NO_NDEF`), so a blank data area is no longer read to its end. Lock or reserved bytes that a control TLV places inside the message are `PN5180_NDEF_ERR_UNSUPPORTED`; they were returned as message bytes.
  - Type 5: the byte `00` is a TLV with a length field like any other; it was skipped as a one-byte NULL TLV, which exists on Type 2 only.
  - Type 2 and Type 5: an NDEF TLV longer than the rest of the data area is `PN5180_NDEF_ERR_PARSE_FAILED`, found without reading the tag to its end; it was `PN5180_NDEF_ERR_NO_NDEF`.
  - MIFARE Classic: only the identifier `03 E1` in the application directory marks an NDEF sector; `E1 03` was accepted too. The general purpose byte of the first NDEF sector is checked: a major mapping version above 1 is `PN5180_NDEF_ERR_UNSUPPORTED`, read access other than "granted" is `PN5180_NDEF_ERR_ACCESS_DENIED`.
  - Type 4: a capability container with CCLEN below 15, MLe below 15, an NDEF file size outside 5 to 7FFFh or a reserved NDEF file identifier is `PN5180_NDEF_ERR_PARSE_FAILED`.
- A message longer than the TLV length field allows (FFFEh bytes) is `PN5180_NDEF_ERR_CARD_FULL`; the length was truncated before.
- `pn5180_ndef_encode_message()` returns 0 for a record that declares a type, ID or payload length without the matching pointer. It used to skip those bytes and return a shorter, damaged message.
- `pn5180_ndef_decode_smartposter()` applies the rules of the message parser to the nested message: a payload without Message End, with a second Message Begin, or with data after the last record returns 0 instead of the records decoded so far. Chunked nested records return 0 as well.
- Type 4: a capability container with the Extended NDEF File Control TLV (`06`, files above 32 KB) is `PN5180_NDEF_ERR_UNSUPPORTED`; it was `PN5180_NDEF_ERR_PARSE_FAILED`. The mapping version is checked before the TLV.
- Type 4: a SELECT that got no answer and closed the ISO14443-4 session is `PN5180_NDEF_ERR_READ_FAILED`, so `pn5180_ndef_read_card_auto()` repeats the read from a new activation. It was `PN5180_NDEF_ERR_NO_NDEF`, as for a card that refuses the SELECT.
- `pn5180_ndef_read_from_selected_card()` stops at the Terminator TLV instead of reading on to the block limit.
- `pn5180_ndef_tlv_find_ndef()` rejects NULL arguments.

MIFARE:

- `pn5180_mifare_block_read()` accepts only the 16-byte READ answer. A 4-byte answer was tolerated and left the other 12 bytes of the buffer unset.
- `pn5180_mifare_block_read()` and `pn5180_mifare_block_write()` reject NULL pointers and block numbers outside 0..255; 256 used to be sent as block 0.

Fixes from an external review of 0.4.3:

- **ISO14443A scan: the limit of 14 cards did not work with a log level below INFO.** The card counter was incremented inside a log statement, which is not compiled in at lower levels. A card that did not take the HLTA was then found again and again until the memory ran out. The counter is a statement of its own now, and a UID that shows up a second time ends the scan.
- **ISO14443-4: a card that answers with chained blocks without data no longer keeps `pn5180_14443_4_transceive()` running forever**; such a block ends the exchange.
- ISO14443-4: S-blocks with a CID are treated as invalid blocks, as I- and R-blocks with CID already were; the CID byte of an S(WTX) was read as the waiting time multiplier.
- ISO14443-4: the start-up frame guard time of the ATS (SFGI) is waited after RATS. The waiting time after an extension request is never shorter than the card's own frame waiting time.
- ISO14443-4 cards through the protocol callbacks: `block_read()` fails if the card returns fewer bytes than asked for, instead of leaving the rest of the buffer unset; `block_write()` is refused while ISO14443-4 is active, where it used to send a raw MIFARE frame into the session.
- `pn5180_recover()` and `pn5180_set_rf_off()` mark ISO14443-4 as inactive: the card loses the session with the field.
- SAK `0x11` is MIFARE Plus 4K (`PN5180_MIFARE_PLUS_4K`, 256 blocks); it was reported as Plus 2K. The unreachable SAK `0x24` entry is gone.
- **ISO15693: blocks above 255 are read and written with Extended Read / Write Single Block (`30h` / `31h`).** The codes used before, `23h` / `24h`, are Read / Write Multiple Blocks, so a wrong block came back.
- ISO15693 inventory: tags found with the first RF configuration (ASK 10 %) end the search. It used to run a second pass with ASK 100 % in every case, left that configuration loaded and mixed the signal strength values of both passes.
- ISO15693: a reader failure during the inventory is reported as `PN5180_POLL_TRANSPORT_ERROR`, not as "no tag"; the entries of the second and further tags are zeroed before use (`block_size`, `blocks_count` and `atqa` held stale memory); `block_read()` fails if the tag's blocks are shorter than the buffer asks for; the collision search no longer loses a branch at the deepest level.
- `pn5180_send_data()` rejects a negative length; `pn5180_read_register()` assembles the value without signed overflow; `pn5180.c` includes the headers it uses directly.

Brought over from PN532 component 0.7.3, which was debugged on hardware:

- `pn5180_ndef_encode_message()` returns 0 for records the parser of this driver refuses: an Empty record with a type, ID or payload, an Unknown record with a type, and the TNF values Unchanged and Reserved.
- `pn5180_spi_attach()` returns NULL for a host that is not initialized or whose transactions are shorter than a PN5180 transfer (`max_transfer_sz` below `PN5180_MAX_BUF_SIZE`, or a bus without DMA); the first longer read failed there before.
- SPI clocks above 7 MHz are lowered to that limit with a warning (`PN5180_SPI_MAX_CLOCK_HZ`).
- `pn5180_send_command()` rejects NULL buffers.
- The component names `esp_driver_spi` and `esp_driver_gpio` as requirements only from ESP-IDF 5.3 on, where they exist; with 5.0 to 5.2 the configuration step failed. Compiled here with 5.5.4 and 6.0.1 only.
- `host_test/Makefile` accepts `UNITY_DIR` in place of `IDF_PATH`, and a GitHub workflow runs the host tests on push and pull request.
- README: new section on targets with a random UID (first byte `08`, a phone for example).

Other changes:

- The package in the component registry contains the build files of the examples and `CHANGES.md`.
- Documentation: the README introduction no longer promises NDEF writing for MIFARE Classic and Type 4; new README section on task stack use; return value contracts of `pn5180_ndef_encode_message()`, `pn5180_ndef_extract_uri()`, `pn5180_ndef_decode_smartposter()` and `pn5180_mifare_value_read()` spelled out; `PN5180_NDEF_ERR_BUFFER_TOO_SMALL` marked as reserved; block number ranges and buffer sizes of the `block_read` / `block_write` callbacks described; new troubleshooting entries for refused NDEF writes and unsupported tags; the comment on `PN5180_MIFARE_ULTRALIGHT_EV1` gave bytes as pages.
- Host tests cover the changes of this release (42 tests), with a simulated card that ignores HLTA and one that sends empty chained blocks.

## v 0.4.3 - 2026-10-07

### ISO14443-4 session is closed after a failed exchange

- When `pn5180_14443_4_transceive()` gives up (no answer after the retries, too many waiting time extensions, protocol error, response larger than the buffer), reader and card are out of step. The driver now sends S(DESELECT) and marks ISO14443-4 as inactive, so the next call fails clearly until the card is selected again. It used to leave the session marked active.
- `pn5180_wait_for_irq()` logs an SPI failure as such instead of as a timeout.
- MIFARE Classic NDEF: the CRC of the MIFARE Application Directory (MAD1 and MAD2) is checked; a directory with a wrong CRC is treated as absent (`PN5180_NDEF_ERR_NO_NDEF`).

## v 0.4.2 - 2026-10-07

### Field-off time of 5.1 ms

- New constant `PN5180_RF_OFF_TIME_US` (5100) and public `pn5180_delay_us()`: the time the RF field has to stay off between scans so that halted cards return to their idle state. 5 ms is not enough.
- The examples and the README use it; `simple_main` waited exactly 5 ms before.
- `setup_rf()` waits this time itself when it has to switch the field off to change the RF configuration (switching between ISO14443A and ISO15693, and between the two ISO15693 modulations during inventory). It used to switch the field back on at once, so cards and tags could keep their halted or quiet state.

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
