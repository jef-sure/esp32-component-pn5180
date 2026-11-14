# How the driver works

*[По-русски](../ru/how-it-works.md)*

The objects a program holds, the life of a card session, the field, timing, memory and tasks. The functions named
here are described one by one in the [API reference](api.md).

## Three objects

```text
pn5180_spi_t      the SPI host and the PN5180 as a device on it
    ^
pn5180_t          one PN5180: pins, buffers, field, timing, the state of the selected card
    ^
pn5180_proto_t    one RF protocol on that PN5180: ISO14443A or ISO15693
```

- **`pn5180_spi_t`** comes from `pn5180_spi_init()`, which initializes the bus itself, or from `pn5180_spi_attach()`,
  which adds the PN5180 to a bus the program has already initialized, shared with other devices.
- **`pn5180_t`** comes from `pn5180_init()`: it resets the PN5180, waits for its boot, checks its firmware (3.4 or
  later) and keeps two 512-byte DMA-capable buffers for the SPI transfers. It is a public struct because the driver is
  split across several source files; a program treats it as a handle. The fields a program reads are
  `iso14443_last_auth_status` (why a MIFARE Classic authentication failed, see
  [ISO14443A cards](iso14443a.md#authentication)) and `firmware_version`; `timeout_ms` is described under
  [Timing](#timing).
- **`pn5180_proto_t`** comes from `pn5180_14443_init()` or `pn5180_15693_init()`. Both can live on one PN5180 and are
  used one at a time: `setup_rf()` of one protocol loads its RF configuration and replaces the other's.

## Two protocols

| | ISO14443A | ISO15693 |
|---|---|---|
| Create | `pn5180_14443_init(pn5180, max_cards)` | `pn5180_15693_init(pn5180, PN5180_15693_26KASK100)` |
| Cards | MIFARE Classic, Plus, Ultralight, NTAG21x, DESFire and other ISO14443-4 cards, phones | ICODE SLIX and other vicinity tags |
| Range | a few centimetres | longer |
| Authentication | MIFARE Classic keys (`authenticate`) | none |
| NDEF | Type 2, MIFARE Classic, Type 4 | Type 5 |
| Header | `pn5180-14443.h` | `pn5180-15693.h` |

## The protocol object

Every card operation goes through the callbacks of the protocol object, the same set for both protocols:

| Callback | ISO14443A | ISO15693 |
| -------- | --------- | -------- |
| `setup_rf(proto)` | RF configuration 00h (106 kbit/s), field on | the configuration given to `pn5180_15693_init()`, field on |
| `get_all_uids(proto)` | REQA, anticollision of all cascade levels, HLTA for each card | inventory with collision resolution, Stay Quiet for each tag |
| `select_by_uid(proto, uid)` | WUPA and SELECT of each cascade level; RATS for an ISO14443-4 card | Select (addressed) |
| `detect_card_type_and_capacity(pn5180, uid, &blocks, &size)` | from SAK, then GET_VERSION for the Ultralight family | Get System Information |
| `authenticate(proto, key, key_type, uid, block)` | MIFARE Classic Crypto1; `true` at once for Ultralight, NTAG and ISO14443-4 cards | `NULL`: not available |
| `block_read(proto, block, buf, len)` | READ (30h), 16 bytes; READ BINARY on an ISO14443-4 card | Read Single Block, Extended above block 255 |
| `block_write(proto, block, buf, len)` | WRITE (A2h) of a 4-byte page, or MIFARE WRITE (A0h) of a 16-byte block | Write Single Block, Extended above block 255 |
| `halt(proto)` | HLTA; S(DESELECT) for an ISO14443-4 card | Reset to Ready (selected) |

Note the exceptions: `detect_card_type_and_capacity()` takes the `pn5180_t`, not the protocol object;
`block_write()` returns an `int`, 0 on success and negative on failure, while the others return `bool`; the
ISO15693 object has no `authenticate`, so check the pointer before calling it on an object that may be either.

The protocol object is allocated on the heap and released with `free()`.

## A card session

1. **`setup_rf()`** loads the protocol's RF configuration and switches the field on.
2. **`get_all_uids()`** enumerates the cards. Each ISO14443A card found is halted, each ISO15693 tag silenced, so that
   the next ones can answer; none is left selected. See [Finding cards](polling.md).
3. **`select_by_uid()`** wakes one card up and selects it. For an ISO14443-4 card this includes the activation (RATS).
4. **`detect_card_type_and_capacity()`** fills `subtype`, `block_size` and `blocks_count` of the `pn5180_uid_t`. It
   returns `true` when the card has to be selected again afterwards, which is the case for the Ultralight family.
5. **Block access, authentication, NDEF and APDUs** work on the selected card.
6. **`halt()`** ends the session: HLTA for ISO14443-3 cards, S(DESELECT) for ISO14443-4 cards, Reset to Ready for
   ISO15693 tags. A halted ISO14443A card is found again by `select_by_uid()`, but by `get_all_uids()` only after the
   field was switched off.

A selected ISO14443A card does not answer a new `select_by_uid()`: call `halt()` first. A card left in its ISO14443-4
session is the exception, and a dangerous one: it ignores the wake-up and the activation of the next card, but answers
every I-block, also those meant for that card. `select_by_uid()` and `get_all_uids()` therefore close such a session
themselves with S(DESELECT) before they send anything else.

Several card families leave the selected state after an error: Ultralight and NTAG after any NAK, for example a read
beyond the last page, MIFARE Classic after a refused authentication. After such an error, `halt()` and
`select_by_uid()` again before the next command.

## pn5180_uid_t

A poll returns an array of `pn5180_uid_t`, one per card. The program keeps the entry and passes it to the other
callbacks:

| Field | Filled by | Meaning |
| ----- | --------- | ------- |
| `uid`, `uid_length` | poll | the UID in the order the card sends it: 4, 7 or 10 bytes for ISO14443A; 8 for ISO15693, least significant byte first, so `uid[7]` is `E0` |
| `sak`, `atqa` | poll, `select_by_uid()` | ISO14443A only: SAK of the last cascade level, ATQA first byte first |
| `agc` | poll | the AGC value of the receiver when the card answered: lower is a stronger signal, a closer card |
| `subtype` | `detect_card_type_and_capacity()` | the card type, a `pn5180_card_type_t`; `PN5180_MIFARE_UNKNOWN` after the poll |
| `blocks_count`, `block_size` | `detect_card_type_and_capacity()` | the memory: blocks or pages, and their size in bytes |

The NDEF functions choose the mapping from `subtype`, so they need the detection first. Changing `subtype` before
`select_by_uid()` is the way to choose the ISO14443-4 side of a card that has both, see
[Cards with both MIFARE Classic and ISO14443-4](iso14443a.md#cards-with-both-mifare-classic-and-iso14443-4).

## The RF field

- **`setup_rf()`** keeps the field as it is when its own RF configuration is already loaded and the field is on; it
  checks that the field is really on and switches it on again if it dropped. Cards halted or silenced by the last poll
  stay so. With the other protocol's configuration loaded, it switches the field off for 5.1 ms, loads its own and
  switches the field on.
- **A field reset** brings every card back to its idle state: `pn5180_set_rf_off()`, then at least
  `PN5180_RF_OFF_TIME_US` (5.1 ms; 5 ms is not enough), then `setup_rf()`. A loop that wants to see the same cards on
  every pass does that before each poll, as the [first program](getting-started.md#3-the-first-program) does.
- **Guard time.** After the field is switched on the driver waits 5.1 ms before the first command, so that cards have
  powered up. `pn5180_set_rf_guard_time_us()` changes it; ISO15693 tags need 1 ms.
- **RF collision avoidance** is on by default: the PN5180 does not switch its field on while another field is present,
  and `setup_rf()` fails. After `pn5180_set_rfca(pn5180, false)` the field goes on regardless.
- Switching the field off, by `pn5180_set_rf_off()`, `pn5180_reset()` or `pn5180_recover()`, ends every session: an
  ISO14443-4 session is marked as closed, and cards have to be selected again.

## Timing

**Card timeouts.** The wait for a card's answer is timed by PN5180 Timer1, started at the end of the transmission and
stopped when a reception begins. A missing card is therefore reported within milliseconds, independent of host load.
Each command has its own timeout, several times what the standards allow, because a timeout that is too short breaks a
working card:

| Command | Timeout |
| ------- | ------- |
| ISO14443A REQA, WUPA, anticollision, SELECT | 5 ms |
| RATS | 20 ms |
| MIFARE READ, GET_VERSION, the ACK after a write command | 10 ms |
| ACK after the data was programmed | 20 ms |
| ISO15693 Inventory, Select, Read, Get System Information, Reset to Ready | 10 ms |
| ISO15693 Write Single Block | 40 ms |
| ISO14443-4 I-blocks | the frame waiting time the card announces in its ATS, extended when it asks for it |

`pn5180_set_hw_rx_timeout(pn5180, false)` replaces Timer1 by a host-side timeout, which is slower to report a missing
card; it helps to tell a timer problem from an RF problem.

**Waits for the PN5180.** `pn5180_t.timeout_ms`, 500 ms by default, bounds only the waits for the PN5180 itself:
BUSY, the transceiver state, the field going on or off, `pn5180_wait_for_irq()`. It is not a card timeout.

**The end of an exchange.** With the [IRQ pin](hardware.md#irq-pin) the driver sleeps until the PN5180 signals the
end of an exchange. Without it the driver reads the IRQ status register over SPI: back to back for the first 5 ms,
then once per millisecond with the CPU released in between.

**The driver's own waits** (the guard time, the time the field stays off when a protocol is set up again, the start-up
frame guard time of ISO14443-4 cards, the reset) sleep on a high-resolution timer (`esp_timer`) of the `pn5180_t`:
the CPU is free meanwhile, and a wait ends at most some tens of microseconds late, never early.

**`pn5180_delay_ms()` and `pn5180_delay_us()`** have no device: they sleep whole RTOS ticks and busy-wait the rest, up
to one tick. For a pause that need not be precise, such as the one between polls, use `vTaskDelay()`.

## Memory

| What | Where | Size | Released by |
| ---- | ----- | ---- | ----------- |
| `pn5180_spi_t` | heap | small | `pn5180_deinit()`, or `pn5180_spi_deinit()` if `pn5180_init()` failed |
| `pn5180_t` and its buffers | heap, buffers DMA-capable | two 512-byte buffers and the struct | `pn5180_deinit()` |
| `pn5180_proto_t` | heap | small | `free()` |
| a poll's `pn5180_uids_array_t` | heap | one `pn5180_uid_t` per card | `free()` |
| an NDEF message read from a card | heap | see [NDEF memory](ndef.md#memory) | `pn5180_ndef_free_parsed_message()` |

Some calls also allocate for their own duration and free it before they return: `pn5180_14443_4_transceive()` about
0.3 KB for the state of an exchange, the NDEF functions their read and write buffers. The record builders, the APDU
utilities and `pn5180_ndef_decode_message()` allocate nothing and work in buffers of the caller.

### Task stack

The SPI buffers live in `pn5180_t`, but the protocol code keeps frame buffers on the stack. Measured with GCC's
`-fstack-usage` and call graph on an ESP32 (ESP-IDF 5.5, `-Og`, the default of a new project), the frames of the
driver add up to about 1.5 KB on its deepest paths:

- a MIFARE Classic NDEF read, about 1.5 KB: the authentication keeps a 512-byte buffer to drain the receiver after a
  refusal;
- an ISO15693 poll, about 1.5 KB: the inventory keeps its search stack, 0.8 KB, in one frame;
- a Type 4 NDEF read, about 1.4 KB: the READ BINARY buffer and the block buffers of `pn5180_14443_4_transceive()`;
- selecting an ISO14443-4 card, about 0.9 KB with the ATS buffer; an ISO14443A poll, about 0.8 KB.

The ESP-IDF SPI driver, logging and the calling code come on top. Size the stack of the task that calls the driver with
that in mind; the figures are the driver's frames, not a high-water mark of a running task.

## Tasks and locking

The driver has no locking: one `pn5180_t` must not be used from two tasks at the same time. Two readers, each with its
own `pn5180_t`, may run in separate tasks, also on one SPI bus; create and delete them from one task.

Readers whose antennas are close still have to take turns with the field: each disturbs the cards in the other's
field, and with RF collision avoidance on (the default) a reader does not switch its field on while the other's is on.
Finish each cycle with `pn5180_set_rf_off()`.

## Ownership and lifetime

- `pn5180_spi_init()` and `pn5180_spi_attach()` return a heap-allocated `pn5180_spi_t *`. `pn5180_spi_attach()`
  never frees the underlying bus.
- `pn5180_init()` returns a heap-allocated `pn5180_t *`. If it fails, the SPI structure is untouched: retry, or release
  it with `pn5180_spi_deinit()`.
- `pn5180_deinit(pn5180, true)` frees the device, its SPI device and the bus, if `pn5180_spi_init()` created it;
  `pn5180_deinit(pn5180, false)` keeps the bus.
- `pn5180_14443_init()` and `pn5180_15693_init()` return a heap-allocated `pn5180_proto_t *`; release it with `free()`
  before `pn5180_deinit()`.
- `get_all_uids()` and the `..._get_all_uids_ex()` functions return a heap-allocated `pn5180_uids_array_t *`; release
  it with `free()`.
- `pn5180_ndef_read_card_auto()`, `pn5180_ndef_read_from_selected_card()` and `pn5180_ndef_parse_message()` return a
  heap-allocated `pn5180_ndef_message_parsed_t *` that owns a copy of the message; release it with
  `pn5180_ndef_free_parsed_message()`.

## Results and errors

- Most functions return `bool`. `block_write()` and `pn5180_mifare_block_write()` return 0 on success and a negative
  value on failure.
- A poll tells why it returned nothing through `pn5180_poll_status_t`, see
  [Poll status](polling.md#poll-status).
- The NDEF functions return `pn5180_ndef_result_t`; `pn5180_ndef_result_to_string()` gives a text for the log.
- The APDU utilities return `esp_err_t`.
- `pn5180_rf_transceive()` returns `pn5180_rf_result_t`, which tells timeout, collision, receive error, overflow and
  transport failure apart.

When the PN5180 itself stops responding (a poll reports `PN5180_POLL_TRANSPORT_ERROR`), `pn5180_recover()` resets it
and restores the RF configuration and the field state it had. Cards have to be selected again.

## Logging

The driver logs with the ESP-IDF tags `PN5180` (the reader layer), `pn5180-14443`, `pn5180-15693`, `pn5180-mifare` and
`pn5180-ndef`. Errors and warnings are always compiled in; the debug lines of the protocol code are compiled only when
`PN5180_DEBUG` is defined in `include/pn5180-internal.h`, and then shown at the debug log level. MIFARE keys are never
logged.
