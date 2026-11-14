# API reference

*[По-русски](../ru/api.md)*

Every public type, function and constant, header by header. How they fit together is described in
[How the driver works](how-it-works.md); the pages on [polling](polling.md), [ISO14443A](iso14443a.md),
[ISO14443-4](iso14443-4.md), [ISO15693](iso15693.md) and [NDEF](ndef.md) show them in use.

| Header | What it has |
| ------ | ----------- |
| `pn5180.h` | the SPI and device objects, the protocol interface, the field, RF exchanges, MIFARE authentication, LPCD, registers and EEPROM |
| `pn5180-14443.h` | the ISO14443A protocol, ISO14443-4 APDU exchange, the APDU utilities |
| `pn5180-15693.h` | the ISO15693 protocol |
| `pn5180-mifare.h` | raw MIFARE block, page and value operations |
| `pn5180-ndef.h` | NDEF records, messages, reading and writing tags |
| `pn5180-ndef-tlv.h` | finding the NDEF TLV in raw bytes |

`pn5180-internal.h` is used by the driver's sources and is not part of the API.

All public names start with `pn5180_` or `PN5180_`. Every header has `extern "C"` for C++.

## pn5180.h: types

### pn5180_spi_t

```c
typedef struct _pn5180_spi_t {
    gpio_num_t          sck, miso, mosi;
    int                 clock_speed_hz;
    spi_device_handle_t spi_handle;
    spi_host_device_t   host_id;
    bool                owns_bus;    /* the bus was initialized by pn5180_spi_init() */
} pn5180_spi_t;
```

The SPI host and the PN5180 as a device on it. Created by `pn5180_spi_init()` or `pn5180_spi_attach()`.

### pn5180_t

The device: pins, the two 512-byte SPI buffers, the RF state, timing settings and the state of the selected
ISO14443 card. A public struct because the driver is split across several files; treat it as a handle and do not
modify its fields. Fields a program may read:

| Field | Meaning |
| ----- | ------- |
| `firmware_version` | read from the EEPROM at init, major version in the high byte (`0x0304` is 3.4) |
| `iso14443_last_auth_status` | the result of the last MIFARE Classic authentication, see [`pn5180_mifare_authenticate()`](#pn5180_mifare_authenticate) |
| `timeout_ms` | the bound of the waits for the PN5180 itself (BUSY, transceiver state, field, IRQ), 500 ms; not a card timeout |
| `is_rf_on` | the driver's idea of the field: on or off |
| `irq` | the IRQ pin, `GPIO_NUM_NC` without `pn5180_irq_attach()` |

### pn5180_proto_t

```c
typedef struct _pn5180_proto_t {
    pn5180_t                       *pn5180;
    pn5180_func_setup_rf_t         *setup_rf;
    pn5180_func_get_all_uids_t     *get_all_uids;
    pn5180_func_select_by_uid_t    *select_by_uid;
    pn5180_func_block_read_t       *block_read;
    pn5180_func_block_write_t      *block_write;
    pn5180_func_authenticate_t     *authenticate;    /* NULL for ISO15693 */
    pn5180_func_detect_card_type_t *detect_card_type_and_capacity;
    pn5180_func_halt_t             *halt;
    uint8_t                         rf_config;       /* RF configuration loaded by setup_rf() */
    int                             max_cards;       /* most cards one poll enumerates (ISO14443A) */
} pn5180_proto_t;
```

The protocol interface, created by `pn5180_14443_init()` or `pn5180_15693_init()` and released with `free()`. The
callbacks:

#### setup_rf

```c
bool setup_rf(pn5180_proto_t *proto);
```

Loads the protocol's RF configuration and switches the field on. With that configuration already loaded and the field
on, it checks that the field is really on and keeps it, so cards halted or silenced by the last poll stay so. With
another configuration loaded, it switches the field off for `PN5180_RF_OFF_TIME_US` first. `false` when the
configuration could not be loaded or the field did not come up (RF collision avoidance among the reasons).

#### get_all_uids

```c
pn5180_uids_array_t *get_all_uids(pn5180_proto_t *proto);
```

Polls for all cards in the field. Returns a heap array, released with `free()`, or `NULL` when nothing was found or
the poll failed; `pn5180_14443_get_all_uids_ex()` and `pn5180_15693_get_all_uids_ex()` say which. No card is left
selected. See [Finding cards](polling.md).

#### select_by_uid

```c
bool select_by_uid(pn5180_proto_t *proto, pn5180_uid_t *uid);
```

Selects one card. ISO14443A: closes an ISO14443-4 session left open, sends WUPA and SELECT of each cascade level,
updates `sak` and `atqa`, and activates ISO14443-4 (RATS) for a card with SAK bit `20`, unless the card also emulates
MIFARE Classic and `subtype` is not `PN5180_MIFARE_DESFIRE`. ISO15693: addressed Select; the UID must have 8 bytes.

#### detect_card_type_and_capacity

```c
bool detect_card_type_and_capacity(pn5180_t *pn5180, pn5180_uid_t *uid, int *blocks_count, int *block_size);
```

Takes the `pn5180_t`, not the protocol object. Sets `uid->subtype`, `uid->blocks_count`, `uid->block_size` and the two
outputs. Returns `true` when the card has to be selected again afterwards (the Ultralight family), `false` otherwise.
The card types are listed on [ISO14443A cards](iso14443a.md#card-types) and
[ISO15693 tags](iso15693.md#select-detect-halt).

#### authenticate

```c
bool authenticate(pn5180_proto_t *proto, const uint8_t *key, uint8_t key_type, const pn5180_uid_t *uid, int blockno);
```

ISO14443A only (`NULL` for ISO15693). MIFARE Classic / Plus: Crypto1 authentication of the sector of `blockno` (0 to
255) with the 6-byte `key`, `key_type` `PN5180_MIFARE_CLASSIC_KEYA` or `PN5180_MIFARE_CLASSIC_KEYB`; a 7- or 10-byte UID
authenticates with its last 4 bytes. Ultralight, NTAG and ISO14443-4 cards: `true`, nothing sent. After `false` the
card is out of the selected state; `pn5180->iso14443_last_auth_status` tells a refused key
(`PN5180_MIFARE_AUTH_REFUSED`) from a card that did not answer (`PN5180_MIFARE_AUTH_NO_ANSWER`) and from nothing sent
(`PN5180_MIFARE_AUTH_NONE`).

#### block_read

```c
bool block_read(pn5180_proto_t *proto, int blockno, uint8_t *buffer, size_t buffer_len);
```

- MIFARE Classic, Ultralight, NTAG: READ of block or first page `blockno` (0 to 255); the card answers 16 bytes, the
  first `buffer_len` are copied.
- ISO14443-4 cards: READ BINARY of `buffer_len` (1 to 255) bytes at offset `blockno` (0 to 7FFFh) of the selected
  file; `false` when fewer bytes come back.
- ISO15693: Read Single Block, the extended command above block 255 (up to 65535); the tag must deliver at least
  `buffer_len` bytes.

#### block_write

```c
int block_write(pn5180_proto_t *proto, int blockno, const uint8_t *buffer, size_t buffer_len);
```

Returns 0 on success, a negative value on failure. `buffer_len` 16 writes a MIFARE Classic block, 4 an Ultralight /
NTAG page, the block size (1 to 32) an ISO15693 block. Not available for an ISO14443-4 card in its session (-1).

#### halt

```c
bool halt(pn5180_proto_t *proto);
```

Ends the session: HLTA for ISO14443-3 cards, S(DESELECT) for an ISO14443-4 card, Reset to Ready to the selected
ISO15693 tag (optional in ISO15693: `false` on a tag without it).

### pn5180_uid_t

```c
typedef struct {
    int8_t             uid_length;   /* 4, 7 or 10 for ISO14443A, 8 for ISO15693 */
    uint8_t            sak;          /* ISO14443A */
    uint16_t           agc;          /* receiver AGC when the card answered: lower is closer */
    int                block_size;   /* bytes per block */
    int                blocks_count; /* blocks on the card */
    pn5180_card_type_t subtype;
    uint8_t            uid[10];
    uint8_t            atqa[2];      /* ISO14443A, first byte first */
} pn5180_uid_t;
```

One card, as a poll found it. `subtype`, `block_size` and `blocks_count` are set by `detect_card_type_and_capacity()`.

### pn5180_uids_array_t

```c
typedef struct {
    int          uids_count;
    pn5180_uid_t uids[1];   /* uids_count entries */
} pn5180_uids_array_t;
```

The result of a poll, on the heap; `free()` it.

### pn5180_card_type_t

| Value | Card |
| ----- | ---- |
| `PN5180_MIFARE_UNKNOWN` | not identified, or not detected yet |
| `PN5180_MIFARE_CLASSIC_1K`, `PN5180_MIFARE_CLASSIC_MINI`, `PN5180_MIFARE_CLASSIC_4K` | MIFARE Classic |
| `PN5180_MIFARE_PLUS_2K`, `PN5180_MIFARE_PLUS_4K` | MIFARE Plus in security level 2 |
| `PN5180_MIFARE_ULTRALIGHT`, `PN5180_MIFARE_ULTRALIGHT_C`, `PN5180_MIFARE_ULTRALIGHT_EV1` | MIFARE Ultralight |
| `PN5180_MIFARE_NTAG210`, `PN5180_MIFARE_NTAG212`, `PN5180_MIFARE_NTAG213`, `PN5180_MIFARE_NTAG215`, `PN5180_MIFARE_NTAG216` | NTAG |
| `PN5180_MIFARE_DESFIRE` | any ISO14443-4 card |
| `PN5180_15693` | an ISO15693 tag |

A packed enum: one byte.

### pn5180_poll_status_t

| Value | Meaning |
| ----- | ------- |
| `PN5180_POLL_FOUND` | at least one card; the array is returned |
| `PN5180_POLL_NO_TARGET` | no card answered |
| `PN5180_POLL_TRANSPORT_ERROR` | the PN5180 could not be driven: SPI failure, the field did not come up |
| `PN5180_POLL_PROTOCOL_ERROR` | ISO14443A only: a card answered but the anticollision or selection failed |
| `PN5180_POLL_NO_MEMORY` | the array could not be allocated |
| `PN5180_POLL_INVALID_ARGUMENT` | `NULL` protocol object or device |

### pn5180_rf_result_t

| Value | Meaning |
| ----- | ------- |
| `PN5180_RF_OK` | an answer without errors |
| `PN5180_RF_TIMEOUT` | no answer within the timeout |
| `PN5180_RF_COLLISION` | an answer with a bit collision; the data (cut to the buffer) and RX_STATUS are returned |
| `PN5180_RF_RX_ERROR` | protocol, parity or CRC error; the data is returned unless a general error was raised |
| `PN5180_RF_OVERFLOW` | the answer is longer than the buffer; no data is returned |
| `PN5180_RF_FATAL` | the PN5180 could not be driven: SPI failure, the transmission did not finish |

### pn5180_transceive_state_t

The state of the transceiver of the PN5180, from `pn5180_get_transceive_state()`: `PN5180_TS_IDLE`,
`PN5180_TS_WAIT_TRANSMIT`, `PN5180_TS_TRANSMITTING`, `PN5180_TS_WAIT_RECEIVE`, `PN5180_TS_WAIT_FOR_DATA`,
`PN5180_TS_RECEIVING`, `PN5180_TS_LOOPBACK`, and `PN5180_TS_RESERVED`, which is also returned when the state cannot be
read.

## pn5180.h: the device

### pn5180_spi_init

```c
pn5180_spi_t *pn5180_spi_init(spi_host_device_t host_id, gpio_num_t sck, gpio_num_t miso, gpio_num_t mosi,
                              int clock_speed_hz);
```

Initializes the SPI bus of `host_id` with a DMA channel and adds the PN5180 to it. A clock above
`PN5180_SPI_MAX_CLOCK_HZ` (7 MHz) is lowered to it. `NULL` on failure; a pin that is not a GPIO of the chip
(`GPIO_NUM_NC` among them), SCK or MOSI on an input-only GPIO, or a MISO pin `gpio_config()` refuses gives `NULL` before
the SPI host is touched.

### pn5180_spi_attach

```c
pn5180_spi_t *pn5180_spi_attach(spi_host_device_t host_id, int clock_speed_hz);
```

Adds the PN5180 to a bus the program has initialized; it works right after `spi_bus_initialize()`, with no other
device on the host yet. The bus must carry `PN5180_MAX_BUF_SIZE` (512) bytes per transaction, which needs a DMA
channel. `NULL` when the host is not initialized, carries less, or the device cannot be added; no PN5180 device is
left on the host then. The bus is never freed by the driver.

### pn5180_spi_deinit

```c
void pn5180_spi_deinit(pn5180_spi_t *spi, bool free_spi_bus);
```

Removes the PN5180 device and frees the structure, for an SPI structure no `pn5180_t` uses, for example after
`pn5180_init()` failed. With `free_spi_bus` it also frees a bus that `pn5180_spi_init()` initialized.

### pn5180_init

```c
pn5180_t *pn5180_init(pn5180_spi_t *spi, gpio_num_t nss, gpio_num_t busy, gpio_num_t rst);
```

Configures the pins, resets the PN5180, waits for its boot, reads its firmware version (3.4 or later is required) and
allocates the device with its two DMA-capable buffers. `NULL` on failure, with `spi` untouched: call it again or
release `spi` with `pn5180_spi_deinit()`. A pin that is not a GPIO of the chip, NSS or RST on an input-only GPIO, or a
pin `gpio_config()` refuses gives `NULL` before the PN5180 is accessed.

### pn5180_irq_attach

```c
bool pn5180_irq_attach(pn5180_t *pn5180, gpio_num_t irq);
```

Uses the IRQ pin instead of polling the IRQ status over SPI; the polarity is read from the EEPROM. Call it once after
`pn5180_init()`. `false` on failure, the driver then keeps polling; `false` at once for a `NULL` device or a pin that is
not a GPIO of the chip. Required for `pn5180_lpcd_wait()`.

### pn5180_deinit

```c
void pn5180_deinit(pn5180_t *pn5180, bool free_spi_bus);
```

Frees the device and its SPI device; with `free_spi_bus`, also a bus that `pn5180_spi_init()` initialized. A bus the
PN5180 was attached to is never freed. Free the protocol objects first.

### pn5180_reset

```c
bool pn5180_reset(pn5180_t *pn5180);
```

Hardware reset through RST. The RF configuration and the field are gone, cards have to be selected again, an
ISO14443-4 session is marked as closed. `pn5180_recover()` resets and restores.

### pn5180_recover

```c
bool pn5180_recover(pn5180_t *pn5180);
```

Resets the PN5180 and restores the RF configuration and the field state it had. For a reader that stopped
responding, for example when a poll returned `PN5180_POLL_TRANSPORT_ERROR`. Cards have to be selected again.

## pn5180.h: the field

### pn5180_load_rf_config

```c
bool pn5180_load_rf_config(pn5180_t *pn5180, uint8_t tx_conf);
```

Loads an RF configuration of the PN5180 for transmitter and receiver: 00h to 1Ch, FFh for no change. 00h is ISO14443A
106 kbit/s, 0Dh and 0Eh are ISO15693 ASK 100 % and ASK 10 %. `setup_rf()` does this for its protocol.

### pn5180_set_rf_on, pn5180_set_rf_off

```c
bool pn5180_set_rf_on(pn5180_t *pn5180);
bool pn5180_set_rf_off(pn5180_t *pn5180);
```

Switch the field on and off. `pn5180_set_rf_on()` checks the field itself, not only the driver's flag, waits the guard
time after switching it on, and fails when RF collision avoidance holds it off. `pn5180_set_rf_off()` ends the sessions
of all cards; an ISO14443-4 session is marked as closed.

### pn5180_set_rf_guard_time_us

```c
void pn5180_set_rf_guard_time_us(pn5180_t *pn5180, uint32_t guard_time_us);
```

The wait after the field was switched on, before the first command: 5100 µs by default, which covers ISO14443A;
ISO15693 needs 1000 µs.

### pn5180_set_rfca

```c
void pn5180_set_rfca(pn5180_t *pn5180, bool enable);
```

RF collision avoidance, on by default: the field is not switched on while another field is present. With `false` the
field goes on regardless.

### pn5180_set_hw_rx_timeout

```c
void pn5180_set_hw_rx_timeout(pn5180_t *pn5180, bool enable);
```

On by default: the wait for a card's answer runs on Timer1 of the PN5180. Off: a host-side timeout, less precise and
slower to report a missing card.

### PN5180_RF_OFF_TIME_US

```c
#define PN5180_RF_OFF_TIME_US 5100u
```

How long the field has to stay off for cards to return to their idle state. 5 ms is not enough.

## pn5180.h: RF exchanges

### pn5180_rf_transceive

```c
pn5180_rf_result_t pn5180_rf_transceive(pn5180_t *pn5180, const uint8_t *tx, size_t tx_len, uint8_t tx_last_bits,
                                        uint8_t *rx, size_t rx_size, size_t *rx_len, uint32_t timeout_us,
                                        uint32_t *rx_status);
```

Sends a frame and receives the answer; the protocol code is built on it.

- `tx`, `tx_len` (1 to 260): the frame; `tx_last_bits`: the valid bits of its last byte, 0 for all 8.
- `rx`, `rx_size`: the receive buffer, `rx` `NULL` to discard the answer; `rx_len` (may be `NULL`) gets the bytes
  stored.
- `timeout_us`: the time until the answer begins, timed by Timer1 from the end of the transmission, up to about 19.7 s.
  0 means that no answer is expected: the call returns when the transmission has ended.
- `rx_status` (may be `NULL`) gets the RX_STATUS register, with the position of a collision and the valid bits of the
  last byte; see the `PN5180_RX_*` constants.

CRC and parity follow the current configuration: `pn5180_enable_crc()`, `pn5180_disable_crc()` and their `_rx_` and
`_tx_` variants switch the CRC of each direction (static inline functions of the header). After `select_by_uid()` of
an ISO14443A card the CRC is on in both directions.

### pn5180_send_data, pn5180_read_data, pn5180_rx_bytes_received

```c
bool     pn5180_send_data(pn5180_t *pn5180, const uint8_t *data, int len, uint8_t valid_bits);
bool     pn5180_read_data(pn5180_t *pn5180, int len, uint8_t *buffer);
uint32_t pn5180_rx_bytes_received(pn5180_t *pn5180);
```

The host commands SEND_DATA (0 to 260 bytes, `valid_bits` of the last byte, 0 for all) and READ_DATA (0 to 508
bytes), and the byte count of the last reception from RX_STATUS. Lower level than `pn5180_rf_transceive()`: the
program handles the transceiver state, the IRQ flags and the timeout itself.

## pn5180.h: MIFARE authentication

### pn5180_mifare_authenticate

```c
int16_t pn5180_mifare_authenticate(pn5180_t *pn5180, uint8_t blockno, const uint8_t *key, uint8_t key_type,
                                   const uint8_t uid[4]);
```

The MIFARE_AUTHENTICATE command of the PN5180 with a 6-byte key and the 4 UID bytes the card authenticates with. The
`authenticate` callback calls it with the right UID bytes. Returns the status the PN5180 reports (datasheet, table 26),
which is also kept in `pn5180->iso14443_last_auth_status`:

| Value | Meaning |
| ----- | ------- |
| `PN5180_MIFARE_AUTH_OK` (0) | the key was accepted |
| `PN5180_MIFARE_AUTH_REFUSED` (1) | the card turned the key down; also when the PN5180 reports success but Crypto1 is off |
| `PN5180_MIFARE_AUTH_NO_ANSWER` (2) | the card did not answer |
| another positive value | another status byte of the PN5180 |
| `PN5180_MIFARE_AUTH_NONE` (-1) | nothing sent: a `NULL` argument or a key type other than 60h and 61h |
| -3 | the SPI transfer failed |
| -4 | the result could not be checked |

`PN5180_MIFARE_CLASSIC_KEYA` (60h) and `PN5180_MIFARE_CLASSIC_KEYB` (61h) are the key types.

## pn5180.h: low power card detection

### pn5180_lpcd_prepare

```c
bool pn5180_lpcd_prepare(pn5180_t *pn5180);
```

Writes the LPCD settings into the EEPROM of the PN5180 (field-on time, a high sensitivity, self calibration), each byte
only if it differs. Call it once.

### pn5180_lpcd_enter

```c
bool pn5180_lpcd_enter(pn5180_t *pn5180, uint16_t wakeup_counter_ms);
```

Switches the PN5180 to LPCD mode, checking for a card every `wakeup_counter_ms` (1 to `PN5180_MAX_WAKEUP_COUNTER_MS`,
2690). On firmware 3.A and later the reference value is measured first. The field is off from now on, and an
ISO14443-4 session is marked as closed.

### pn5180_lpcd_wait

```c
bool pn5180_lpcd_wait(pn5180_t *pn5180, int timeout_ms, uint32_t *irq_status);
```

Waits on the IRQ pin, without SPI access, until the PN5180 leaves LPCD mode; `timeout_ms` -1 waits forever. `true` when
it woke up because of a card or metal (LPCD IRQ); the RF configuration is then reloaded and the field is off.
`false` on timeout (still in LPCD mode), another wake-up reason, or without an IRQ pin. `irq_status` (may be `NULL`)
gets the IRQ status read at wake-up.

## pn5180.h: registers, EEPROM, commands

### pn5180_read_register, pn5180_write_register

```c
bool pn5180_read_register(pn5180_t *pn5180, uint8_t reg, uint32_t *value);
bool pn5180_write_register(pn5180_t *pn5180, uint8_t reg, uint32_t value);
bool pn5180_write_register_or_mask(pn5180_t *pn5180, uint8_t addr, uint32_t mask);   /* sets bits */
bool pn5180_write_register_and_mask(pn5180_t *pn5180, uint8_t addr, uint32_t mask);  /* clears the 0 bits */
```

Registers of the PN5180, 32 bits each. The addresses (`PN5180_SYSTEM_CONFIG`, `PN5180_IRQ_STATUS`, `PN5180_RX_STATUS`,
`PN5180_RF_STATUS`, ...) and the bits used by the driver are defined in the header.

### pn5180_read_eeprom, pn5180_write_eeprom

```c
bool pn5180_read_eeprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len);
bool pn5180_write_eeprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len);
```

The EEPROM of the PN5180: reading from address 0, writing from 16h (`PN5180_EEPROM_MIN_ADDR`), both up to FEh
(`PN5180_EEPROM_MAX_ADDR`); `addr + len` must not pass the last address. `PN5180_DIE_IDENTIFIER` (16 bytes),
`PN5180_PRODUCT_VERSION`, `PN5180_FIRMWARE_VERSION` and `PN5180_EEPROM_VERSION` (2 bytes each, minor first) are the
identity of the chip; `PN5180_IRQ_PIN_CONFIG` holds the polarity of the IRQ pin. The EEPROM has a limited number of
write cycles: do not write it in a loop.

### pn5180_send_command

```c
bool pn5180_send_command(pn5180_t *pn5180, uint8_t *send_buffer, size_t send_buffer_len, uint8_t *recv_buffer,
                         size_t recv_buffer_len);
```

Sends a raw host command (first byte the command code) and reads `recv_buffer_len` bytes of answer into
`recv_buffer`, which may be `NULL` for a command without one. Handles NSS and BUSY.

### IRQ status

```c
uint32_t pn5180_get_irq_status(pn5180_t *pn5180);           /* 0 when it cannot be read */
bool     pn5180_clear_irq_status(pn5180_t *pn5180, uint32_t irq_mask);
bool     pn5180_clear_all_irqs(pn5180_t *pn5180);           /* static inline */
bool     pn5180_wait_for_irq(pn5180_t *pn5180, uint32_t irq_mask, const char *operation, uint32_t *irq_status);
```

The IRQ status register and its bits `PN5180_*_IRQ_STAT` (`PN5180_RX_IRQ_STAT`, `PN5180_TX_IRQ_STAT`,
`PN5180_IDLE_IRQ_STAT`, ..., `PN5180_LPCD_IRQ_STAT`). `pn5180_wait_for_irq()` waits, with the IRQ pin or by polling,
until one of the flags of `irq_mask` is set, at most `pn5180->timeout_ms`; `operation` names the wait in the log.

### Transceiver state

```c
pn5180_transceive_state_t pn5180_get_transceive_state(pn5180_t *pn5180);
bool                      pn5180_set_transceiver_idle(pn5180_t *pn5180);   /* static inline */
```

The state of the transceiver, and a command to return it to idle, which also clears the IRQ flags.

## pn5180.h: timing

### pn5180_delay_ms, pn5180_delay_us

```c
void pn5180_delay_ms(int ms);
void pn5180_delay_us(uint32_t us);
```

Precise waits without a device: whole RTOS ticks are slept, the rest is a busy wait, which keeps the CPU for up to one
tick. For a pause that need not be precise, use `vTaskDelay()`. The driver's own waits sleep on a timer of the device
instead.

## pn5180.h: constants

| Constant | Value | Meaning |
| -------- | ----- | ------- |
| `PN5180_MAX_BUF_SIZE` | 512 | the size of each SPI buffer, and the least a shared bus must carry per transaction |
| `PN5180_SPI_MAX_CLOCK_HZ` | 7000000 | the fastest SPI clock |
| `PN5180_RF_OFF_TIME_US` | 5100 | field-off time for cards to reset |
| `PN5180_MIN_FIRMWARE_VERSION` | 0x0304 | the oldest firmware `pn5180_init()` accepts |
| `PN5180_FIRMWARE_VERSION_3_A` | 0x030A | the first firmware with the LPCD reference modes of datasheet rev. 4.0 |
| `PN5180_MAX_WAKEUP_COUNTER_MS` | 2690 | the longest LPCD interval |
| `PN5180_MIFARE_CLASSIC_KEYA`, `_KEYB` | 0x60, 0x61 | key types |
| `PN5180_MIFARE_AUTH_OK`, `_REFUSED`, `_NO_ANSWER`, `_NONE` | 0, 1, 2, -1 | authentication status |
| `PN5180_*_IRQ_STAT` | bits | IRQ_STATUS flags |
| `PN5180_RX_*` | bits and positions | fields of RX_STATUS: collision, errors, valid last bits, frames and bytes received |
| `PN5180_RF_STATUS_*` | masks | fields of RF_STATUS: AGC value, own field on, external field detected |
| register and EEPROM addresses | | `PN5180_SYSTEM_CONFIG`, `PN5180_TIMER1_CONFIG`, `PN5180_FIRMWARE_VERSION`, ... |

## pn5180-14443.h

### pn5180_14443_init

```c
pn5180_proto_t *pn5180_14443_init(pn5180_t *pn5180, int max_cards);
```

Creates the ISO14443A protocol object. `max_cards` is the most cards one poll enumerates, 0 for the default of 14; it
is there for a card that ignores HLTA and shows a new UID every time. `NULL` when `max_cards` is negative or memory
ran out. Release with `free()`.

### pn5180_14443_get_all_uids_ex

```c
pn5180_uids_array_t *pn5180_14443_get_all_uids_ex(pn5180_proto_t *proto, pn5180_poll_status_t *status);
```

The ISO14443A poll with a status (`status` may be `NULL`). The heap array for `PN5180_POLL_FOUND`, `NULL` otherwise.

### pn5180_14443_4_transceive

```c
bool pn5180_14443_4_transceive(pn5180_t *pn5180, const uint8_t *apdu, size_t apdu_len, uint8_t *rx, size_t *rx_len);
```

Exchanges an APDU with the selected ISO14443-4 card: chaining both ways, waiting time extensions, retransmission.
`rx_len` is the size of `rx` in and the length of the response (data, SW1, SW2) out. `false` on failure or when no
ISO14443-4 session is active; a failed exchange ends the session with S(DESELECT), and the card has to be selected
again.

### pn5180_14443_4_select_file

```c
bool pn5180_14443_4_select_file(pn5180_t *pn5180, const uint8_t *file_id, size_t file_id_len);
```

ISO 7816-4 SELECT: by AID for more than two bytes (P1 04h, P2 00h), by file identifier otherwise (P1 00h, P2 0Ch), with
one retry with P2 00h when the card refuses the file select. `true` for `90 00`.

### pn5180_14443_4_read_binary

```c
bool pn5180_14443_4_read_binary(pn5180_t *pn5180, uint16_t offset, uint8_t le, uint8_t *buffer, size_t *got);
```

ISO 7816-4 READ BINARY of the selected file: `offset` up to 7FFFh, `le` the bytes asked for (0 for 256). `got` is the
buffer size in and the bytes returned out; when the answer does not fit, `false` with the size needed in `got`. `false`
also for an error status word.

### APDU utilities

```c
typedef struct {
    uint8_t cla, ins, p1, p2;
    const uint8_t *data;      /* points into the parsed buffer */
    size_t         data_len;
    bool           has_le;
    uint16_t       le;        /* an encoded Le of 0 is 256 */
} pn5180_apdu_command_t;

typedef struct {
    const uint8_t *data;      /* points into the parsed buffer */
    size_t         data_len;
    uint8_t        sw1, sw2;
} pn5180_apdu_response_t;

esp_err_t pn5180_apdu_parse_command(const uint8_t *buffer, size_t length, pn5180_apdu_command_t *command);
esp_err_t pn5180_apdu_parse_response(const uint8_t *buffer, size_t length, pn5180_apdu_response_t *response);
esp_err_t pn5180_apdu_build_response(uint8_t *buffer, size_t buffer_size, const uint8_t *data, size_t data_len,
                                     uint8_t sw1, uint8_t sw2, size_t *response_len);
uint16_t  pn5180_apdu_get_status(const pn5180_apdu_response_t *response);
```

No allocation, no hardware.

- `pn5180_apdu_parse_command()`: short APDUs of cases 1, 2S, 3S and 4S. `ESP_OK`, `ESP_ERR_NOT_SUPPORTED` for an
  extended-length APDU, `ESP_ERR_INVALID_ARG` for malformed input.
- `pn5180_apdu_parse_response()`: data and SW1 SW2. `ESP_ERR_INVALID_ARG` for fewer than two bytes.
- `pn5180_apdu_build_response()`: writes `DATA SW1 SW2`. `ESP_ERR_NO_MEM` when the buffer is too small,
  `ESP_ERR_INVALID_ARG` for invalid arguments.
- `pn5180_apdu_get_status()`: SW1 SW2 as one word, 0 for `NULL`.
- `PN5180_APDU_SW_SUCCESS` (9000h), `PN5180_APDU_SW_WRONG_LENGTH` (6700h), `PN5180_APDU_SW_WRONG_P1P2` (6A86h),
  `PN5180_APDU_SW_INS_NOT_SUPPORTED` (6D00h), `PN5180_APDU_SW_CLA_NOT_SUPPORTED` (6E00h).

## pn5180-15693.h

### pn5180_15693_init

```c
typedef enum {
    PN5180_15693_26KASK100 = 0x0D,   /* 26 kbit/s, ASK 100 % */
    PN5180_15693_26KASK10  = 0x0E,   /* 26 kbit/s, ASK 10 % */
} pn5180_15693_rf_config_t;

pn5180_proto_t *pn5180_15693_init(pn5180_t *pn5180, pn5180_15693_rf_config_t rf_config);
```

Creates the ISO15693 protocol object; `rf_config` is what `setup_rf()` loads. The inventory runs with ASK 10 % first
and ASK 100 % as a fallback, whatever `rf_config` says. `authenticate` is `NULL`. `NULL` when memory ran out. Release
with `free()`.

### pn5180_15693_get_all_uids_ex

```c
pn5180_uids_array_t *pn5180_15693_get_all_uids_ex(pn5180_proto_t *proto, pn5180_poll_status_t *status);
```

The ISO15693 inventory with a status (`status` may be `NULL`): `PN5180_POLL_FOUND`, `PN5180_POLL_NO_TARGET`,
`PN5180_POLL_TRANSPORT_ERROR`, `PN5180_POLL_NO_MEMORY` or `PN5180_POLL_INVALID_ARGUMENT`; never
`PN5180_POLL_PROTOCOL_ERROR`. The entries are sorted by `agc`, the strongest first.

## pn5180-mifare.h

Raw operations on the selected ISO14443A card. The `block_read`, `block_write` and `authenticate` callbacks are the
usual way; these add the value operations.

### pn5180_mifare_block_read

```c
bool pn5180_mifare_block_read(pn5180_t *pn5180, int blockno, uint8_t *buffer, size_t buffer_len);
```

READ (30h) of block or first page `blockno` (0 to 255): a Classic block, or four Ultralight / NTAG pages, wrapping to
page 0 at the end of the memory. `true` when the card answered 16 bytes; the first `buffer_len` are copied.

### pn5180_mifare_block_write

```c
int pn5180_mifare_block_write(pn5180_t *pn5180, int blockno, const uint8_t *buffer, size_t buffer_len);
```

`buffer_len` exactly 4: WRITE (A2h) of one Ultralight / NTAG page. 16 or more: MIFARE WRITE (A0h) of a 16-byte block.
0 on success; negative on failure: -1 invalid arguments or no answer, -2 an acknowledge of the wrong length, -3 a NAK
of the command, -5, -6 and -8 the same for the data.

### Value blocks

```c
bool pn5180_mifare_value_read(pn5180_t *pn5180, uint8_t blockno, int32_t *value);
bool pn5180_mifare_value_write(pn5180_t *pn5180, uint8_t blockno, int32_t value, uint8_t addr);
bool pn5180_mifare_increment(pn5180_t *pn5180, uint8_t blockno, uint32_t delta);
bool pn5180_mifare_decrement(pn5180_t *pn5180, uint8_t blockno, uint32_t delta);
bool pn5180_mifare_restore(pn5180_t *pn5180, uint8_t blockno);
bool pn5180_mifare_transfer(pn5180_t *pn5180, uint8_t blockno);
```

The sector must be authenticated.

- `pn5180_mifare_value_read()` reads a block and checks the value block format (value, inverted value, value, then
  the address byte four times, twice inverted); `false` for a block that is not one, with `*value` unchanged.
- `pn5180_mifare_value_write()` formats a block as a value block with `value` and the address byte `addr`, usually the
  block number.
- `pn5180_mifare_increment()`, `pn5180_mifare_decrement()` and `pn5180_mifare_restore()` put their result into the
  card's transfer buffer; `pn5180_mifare_transfer()` stores the transfer buffer into a block.

## pn5180-ndef.h

### Types

```c
typedef enum {
    PN5180_NDEF_TNF_EMPTY, PN5180_NDEF_TNF_WELL_KNOWN, PN5180_NDEF_TNF_MEDIA_TYPE, PN5180_NDEF_TNF_ABSOLUTE_URI,
    PN5180_NDEF_TNF_EXTERNAL, PN5180_NDEF_TNF_UNKNOWN, PN5180_NDEF_TNF_UNCHANGED, PN5180_NDEF_TNF_RESERVED
} pn5180_ndef_tnf_t;

typedef struct {
    pn5180_ndef_tnf_t tnf;
    uint8_t           type_len;
    uint8_t           id_len;
    uint32_t          payload_len;
    const uint8_t    *type;
    const uint8_t    *id;
    const uint8_t    *payload;
} pn5180_ndef_record_t;

typedef struct {
    pn5180_ndef_record_t *records;      /* array of the caller */
    size_t                record_count;
    size_t                capacity;
} pn5180_ndef_message_t;

typedef struct {
    uint8_t              *raw_data;     /* the encoded message */
    size_t                raw_data_len;
    pn5180_ndef_record_t *records;      /* chunks put together */
    size_t                record_count;
} pn5180_ndef_message_parsed_t;
```

A record points into memory it does not own. `pn5180_ndef_message_t` is a message being built, in memory of the
caller; `pn5180_ndef_message_parsed_t` is a message read or parsed, on the heap.

Record header flags: `PN5180_NDEF_MB`, `PN5180_NDEF_ME`, `PN5180_NDEF_CF`, `PN5180_NDEF_SR`, `PN5180_NDEF_IL`,
`PN5180_NDEF_TNF_MASK`. Well-known types: `PN5180_NDEF_RTD_TEXT` (`T`), `PN5180_NDEF_RTD_URI` (`U`),
`PN5180_NDEF_RTD_SMARTPOSTER` (`Sp`), with their `_LEN` constants.

### pn5180_ndef_result_t

| Value | Code | Meaning |
| ----- | ---- | ------- |
| `PN5180_NDEF_OK` | 0 | success |
| `PN5180_NDEF_ERR_INVALID_PARAM` | -1 | a `NULL` pointer or a bad size |
| `PN5180_NDEF_ERR_NO_MEMORY` | -2 | an allocation failed |
| `PN5180_NDEF_ERR_READ_FAILED` | -3 | the card did not deliver |
| `PN5180_NDEF_ERR_WRITE_FAILED` | -4 | the card did not take a write |
| `PN5180_NDEF_ERR_NO_NDEF` | -5 | not NDEF formatted, or no message |
| `PN5180_NDEF_ERR_PARSE_FAILED` | -6 | the tag or the message is inconsistent |
| `PN5180_NDEF_ERR_BUFFER_TOO_SMALL` | -7 | reserved, not returned |
| `PN5180_NDEF_ERR_CARD_FULL` | -8 | the message does not fit |
| `PN5180_NDEF_ERR_UNSUPPORTED` | -9 | a card type, mapping version or access condition the driver does not handle |
| `PN5180_NDEF_ERR_ACCESS_DENIED` | -10 | the message is read protected |
| `PN5180_NDEF_ERR_READ_ONLY` | -11 | the capability container does not grant write access |

`const char *pn5180_ndef_result_to_string(pn5180_ndef_result_t result)` returns a static text for the log.

### pn5180_ndef_read_card_auto

```c
pn5180_ndef_result_t pn5180_ndef_read_card_auto(pn5180_proto_t *proto, pn5180_uid_t *uid,
                                                pn5180_ndef_message_parsed_t **out_msg);
```

Reads the NDEF message of the selected card with the mapping its `subtype` calls for: Type 2, MIFARE Classic, Type 4
or Type 5. `detect_card_type_and_capacity()` must have run. A failed read is repeated once after a new select. Free
the message with `pn5180_ndef_free_parsed_message()`. See [Reading](ndef.md#reading) for the results of each mapping.

### pn5180_ndef_write_card_auto

```c
pn5180_ndef_result_t pn5180_ndef_write_card_auto(pn5180_proto_t *proto, const pn5180_uid_t *uid,
                                                 const pn5180_ndef_message_t *msg);
```

Writes a message of at least one record into the NDEF TLV of a formatted Type 2 or Type 5 tag. See
[Writing to a tag](ndef.md#writing-to-a-tag).

### pn5180_ndef_free_parsed_message

```c
void pn5180_ndef_free_parsed_message(pn5180_ndef_message_parsed_t *msg);
```

Frees a message from `pn5180_ndef_read_card_auto()`, `pn5180_ndef_parse_message()` or
`pn5180_ndef_read_from_selected_card()`. `NULL` is allowed.

### Building

```c
void   pn5180_ndef_message_init(pn5180_ndef_message_t *msg, pn5180_ndef_record_t *records, size_t capacity);
bool   pn5180_ndef_message_add(pn5180_ndef_message_t *msg, const pn5180_ndef_record_t *rec);
void   pn5180_ndef_record_init(pn5180_ndef_record_t *rec, pn5180_ndef_tnf_t tnf, const uint8_t *type,
                               uint8_t type_len, const uint8_t *id, uint8_t id_len, const uint8_t *payload,
                               uint32_t payload_len);
bool   pn5180_ndef_make_text_record(pn5180_ndef_record_t *rec, const char *lang_code, const uint8_t *text,
                                    size_t text_len, bool utf16, uint8_t *payload_buf, size_t payload_buf_len);
bool   pn5180_ndef_make_uri_record(pn5180_ndef_record_t *rec, const char *uri, bool abbreviate,
                                   uint8_t *payload_buf, size_t payload_buf_len);
bool   pn5180_ndef_make_mime_record(pn5180_ndef_record_t *rec, const char *mime_type, const uint8_t *data,
                                    size_t data_len, uint8_t *type_buf, size_t type_buf_len);
bool   pn5180_ndef_make_external_record(pn5180_ndef_record_t *rec, const char *type_name, const uint8_t *data,
                                        size_t data_len, uint8_t *type_buf, size_t type_buf_len);
size_t pn5180_ndef_encode_message(const pn5180_ndef_message_t *msg, uint8_t *out, size_t out_len);
```

- `pn5180_ndef_message_add()` copies the record, not its data; `false` when the array is full.
- `pn5180_ndef_make_text_record()`: the payload (status byte, language code of at most 63 bytes, text) goes into
  `payload_buf`, which needs `1 + strlen(lang_code) + text_len` bytes.
- `pn5180_ndef_make_uri_record()`: the payload (prefix code, rest of the URI) goes into `payload_buf`, which needs
  `1 + strlen(uri)` bytes; with `abbreviate` the longest known prefix becomes its code.
- `pn5180_ndef_make_mime_record()`, `pn5180_ndef_make_external_record()`: the type (1 to 255 bytes) is copied into
  `type_buf` without NUL; the payload points at `data`, which may be `NULL` only with `data_len` 0.
- `pn5180_ndef_encode_message()`: the encoded size when `out` is `NULL` or `out_len` 0, otherwise the bytes written; 0
  on failure, with nothing written: no records, a buffer too small, a length without its pointer, an Empty record with
  a type, ID or payload, an Unknown record with a type, or TNF Unchanged or Reserved.

All buffers a record points to must stay valid until the message is encoded or written.

### Records

```c
pn5180_ndef_record_type_t pn5180_ndef_get_record_type(const pn5180_ndef_record_t *rec);
bool   pn5180_ndef_record_is_text(const pn5180_ndef_record_t *rec);
bool   pn5180_ndef_record_is_uri(const pn5180_ndef_record_t *rec);
bool   pn5180_ndef_record_is_smartposter(const pn5180_ndef_record_t *rec);
bool   pn5180_ndef_extract_text(const pn5180_ndef_record_t *rec, const uint8_t **text_out, size_t *text_len_out,
                                char *lang_buf, size_t lang_buf_len, bool *is_utf16);
size_t pn5180_ndef_extract_uri(const pn5180_ndef_record_t *rec, char *uri_buf, size_t uri_buf_len);
size_t pn5180_ndef_decode_smartposter(const pn5180_ndef_record_t *rec, pn5180_ndef_record_t *records,
                                      size_t capacity);
```

- `pn5180_ndef_get_record_type()`: `PN5180_NDEF_RECORD_TYPE_TEXT`, `_URI`, `_SMARTPOSTER`, `_MIME`, `_EXTERNAL`,
  `_EMPTY` or `_UNKNOWN`.
- `pn5180_ndef_extract_text()`: `true` for a valid Text record. `*text_out` points into the payload, `*text_len_out`
  bytes, not NUL-terminated. The language code goes into `lang_buf` NUL-terminated, truncated if longer (64 bytes hold
  any); `lang_buf` and `is_utf16` may be `NULL`. On failure `lang_buf` is left as it was.
- `pn5180_ndef_extract_uri()`: the length of the full URI with its prefix expanded, without NUL, or 0 for a record
  that is not a URI. `uri_buf` gets a NUL-terminated string when `uri_buf_len` > 0, truncated when the result is
  `uri_buf_len` or more; `NULL` asks for the length.
- `pn5180_ndef_decode_smartposter()`: the records of the message inside a Smart Poster, pointing into its payload. 0
  for a malformed inner message, chunked records, or more records than `capacity`.

### Parsing

```c
pn5180_ndef_result_t pn5180_ndef_parse_message(const uint8_t *raw_data, size_t raw_data_len,
                                               pn5180_ndef_message_parsed_t **out_msg);
size_t pn5180_ndef_decode_message(const uint8_t *in, size_t in_len, pn5180_ndef_record_t *records, size_t capacity);
bool   pn5180_ndef_decode_next(const uint8_t *in, size_t in_len, size_t *offset, pn5180_ndef_record_t *out_rec,
                               bool *is_begin, bool *is_end);
```

- `pn5180_ndef_parse_message()`: an encoded message (without TLV) into a heap message that owns a copy, chunked records
  put together; the first chunk gives TNF, type and ID, the next ones must have TNF Unchanged.
- `pn5180_ndef_decode_message()`: into the caller's array, records pointing into `in`, chunks as separate records. The
  number of records, 0 on error or when the array is too small.
- `pn5180_ndef_decode_next()`: one record at `*offset`, which is advanced; `is_begin` and `is_end` (may be `NULL`) get
  the MB and ME flags.

Both message parsers check that Message Begin is on the first record only, Message End on the last, nothing follows,
and the chunk sequences are valid.

### pn5180_ndef_read_from_selected_card (deprecated)

```c
pn5180_ndef_result_t pn5180_ndef_read_from_selected_card(pn5180_proto_t *proto, int start_block, int block_size,
                                                         int max_blocks, pn5180_ndef_auth_callback_t auth_cb,
                                                         pn5180_ndef_sector_id_callback_t sector_cb, void *auth_ctx,
                                                         pn5180_ndef_message_parsed_t **out_msg);
```

Reads raw blocks from `start_block` until a complete NDEF TLV is found, calling `auth_cb` before a block (only when
`sector_cb` reports a new sector, if given). Deprecated in favour of `pn5180_ndef_read_card_auto()`, which knows the
layout of each card type: on a Type 2 tag this function needs page 4 and 4-byte blocks, and with 16-byte reads it
returns any message longer than the first read damaged.

## pn5180-ndef-tlv.h

### pn5180_ndef_tlv_find_ndef

```c
bool pn5180_ndef_tlv_find_ndef(const uint8_t *data, size_t data_len, size_t *search_pos, size_t *ndef_offset,
                               size_t *ndef_length);
```

Finds the NDEF TLV (type 03h) in bytes of a tag's data area, skipping other TLVs. `true` when its type and length were
found: `*ndef_offset` is the offset of the message in `data`, `*ndef_length` its declared length, and the message may
run past `data_len` when `data` holds only the first part of the memory; check before reading it. `false` when there is
no complete NDEF TLV header yet, or a Terminator TLV came first; `*search_pos` then points at the TLV where the search
stopped, so that it can go on with more data.
