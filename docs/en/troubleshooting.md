# Troubleshooting

*[По-русски](../ru/troubleshooting.md)*

Symptoms, their usual causes, and what to try. The log lines quoted come from the driver; raise the log level of the
tags `PN5180` and `pn5180-14443` to see more.

## The reader

- **`pn5180_init()` returns `NULL`** — the PN5180 did not boot or did not report a supported firmware. Check power
  (5 V and 3.3 V on the usual breakout), ground, and the NSS, BUSY and RST pins. Try a lower SPI clock. It also returns
  `NULL`, before it touches the PN5180, for a pin that is not a GPIO of the chip (`GPIO_NUM_NC` among them) or for NSS
  or RST on an input-only GPIO; `pn5180_spi_init()` does the same for its pins, and the log names the pin.
- **`pn5180_spi_attach()` returns `NULL`** — the host is not initialized, it has no DMA channel, or its
  `max_transfer_sz` is below 512 bytes. See [Sharing the SPI bus](hardware.md#sharing-the-spi-bus).
- **`PN5180 ... timeout waiting for busy level`** — the BUSY line does not follow the SPI transfers: wrong BUSY pin, or
  NSS not reaching the module.
- **The board does not boot with the module connected** — a strapping pin is held at the wrong level at power-up; on
  the classic ESP32, GPIO 12 is the usual one. Move that signal to another GPIO.
- **Everything times out after an update to 0.3.0 or later** — the receive timeout runs on a PN5180 timer;
  `pn5180_set_hw_rx_timeout(pn5180, false)` switches to a host-side timeout to tell a timer problem from an RF problem.
- **A poll returns `PN5180_POLL_TRANSPORT_ERROR`** — the PN5180 did not respond, or the field did not come up. Call
  `pn5180_recover()`. If it keeps happening, check the supply under load: the field draws far more current than the
  idle chip.

## The field

- **`setup_rf()` returns `false`, log `RF_ON blocked by external RF field (RFCA)`** — another reader's field is present.
  Two readers of your own should take turns with the field (see [RF collision avoidance and two
  readers](hardware.md#rf-collision-avoidance-and-two-readers)); after `pn5180_set_rfca(pn5180, false)` the field goes
  on regardless.
- **No cards found, `PN5180_POLL_NO_TARGET`** — check that the field comes up (`setup_rf()` returns `true`) and that
  the antenna is not on a metal surface. A card that was halted by the previous scan answers again only after the field
  was off for at least 5.1 ms (`PN5180_RF_OFF_TIME_US`); 5 ms is too short.
- **A card is found once and then never again** — the loop does not reset the field between polls, and a card that
  stays in the field is halted. That is how [only new cards](polling.md#a-scanning-loop) are found; to see every card on
  every pass, reset the field before each poll.
- **One of several cards turns up rarely** — with the field reset before each poll ISO14443A settles collisions at
  random, so every card turns up, but not equally often. With the field left on, the next poll goes on with the cards
  not found yet. See [Several cards in the field](polling.md#several-cards-in-the-field).
- **A log warning `Scan stopped at 14 cards, more are in the field`** — the poll reached `max_cards`; pass a larger
  value to `pn5180_14443_init()` if that many cards are expected.

## Selecting and reading

- **`select_by_uid()` fails on a card that was just read** — the card is still selected and ignores the wake-up. Call
  `halt()` first, then `select_by_uid()`. A card still in its ISO14443-4 session is released by `select_by_uid()`
  itself.
- **Reads fail after one refused command** — Ultralight and NTAG cards leave the selected state after any NAK (for
  example a read beyond the last page), MIFARE Classic after a refused authentication. Select the card again.
- **A card shows a different UID starting with `08` on every scan** — a random UID, typically a phone. See [Targets
  with a random UID](polling.md#targets-with-a-random-uid).
- **MIFARE Classic authentication fails** — check `pn5180->iso14443_last_auth_status`: `PN5180_MIFARE_AUTH_REFUSED`
  is a wrong key or key type, `PN5180_MIFARE_AUTH_NO_ANSWER` a card that is gone or was not selected. After either,
  select the card again before the next key.
- **An NTAG reads as an Ultralight with 16 pages** — the card did not answer GET_VERSION: an NTAG203 or an original
  Ultralight, or a card that moved. The NDEF functions take the size from the capability container anyway.
- **ISO15693 `halt()` returns `false`** — the tag does not implement Reset to Ready, which is an optional command. The
  tag stays selected until the field is switched off.
- **`pn5180_14443_4_transceive()` returns `false`** — the card did not answer after the retries, sent a protocol error,
  or the response is larger than the buffer. The session is closed: select the card again before the next APDU.

## NDEF

- **`PN5180_NDEF_ERR_NO_NDEF` on a MIFARE Classic card** — the card has no NFC Forum MAD, the MAD has a wrong CRC, the
  directory sector turns down both the MAD key and the default key, or its NDEF sectors are not contiguous. Read raw
  blocks with your own keys instead.
- **`PN5180_NDEF_ERR_ACCESS_DENIED` on a MIFARE Classic card** — an NDEF sector the directory lists turns down both the
  NFC key and the default key, or the first NDEF sector opens with the NFC key and its general purpose byte denies
  reading.
- **`PN5180_NDEF_ERR_NO_NDEF` on a Type 4 card** — the card has no NDEF application of mapping 2.0 or later (AID
  `D2 76 00 00 85 01 01`); a mapping 1.0 tag has another AID and is not read.
- **`pn5180_ndef_write_card_auto()` returns `PN5180_NDEF_ERR_NO_NDEF`** — the tag is not NDEF formatted: it has no
  capability container, or its data area holds no NDEF TLV for the message to go into. NTAG and ICODE tags usually
  leave the factory formatted with an empty NDEF TLV; formatting a blank tag is not implemented.
- **`PN5180_NDEF_ERR_UNSUPPORTED` on an NTAG, Ultralight or ISO15693 tag** — the capability container declares another
  major mapping version than 1 or access conditions other than the standard ones (read/write, read-only), or a write
  would touch lock or reserved bytes that a Type 2 tag keeps inside its data area. A read goes around such bytes, a
  write does not. Read or write the blocks yourself with `block_read` / `block_write`.
- **`PN5180_NDEF_ERR_NO_MEMORY` on a phone or Type 4 card** — the message, or its records, do not fit the heap. See
  [NDEF memory](ndef.md#memory).
- **The NDEF read of a second card returns the message of the first** — fixed in 0.8.2: a card left in its ISO14443-4
  session answered for the next one. Update, and `halt()` each card before selecting the next.

## Recovery

```c
if (status == PN5180_POLL_TRANSPORT_ERROR) {
    pn5180_recover(pn5180);
}
```

`pn5180_recover()` resets the PN5180 and restores the RF configuration and the field state it had. Cards have to be
selected again; an ISO14443-4 session is marked as closed, as it is whenever the field is switched off. It returns
`false` when the PN5180 does not come back; then check the supply and the wiring.

## Asking for help

Open an issue on [GitHub](https://github.com/jef-sure/esp32-component-pn5180/issues) with the version of the component
and of ESP-IDF, the chip, the wiring, the card, a minimal program and the log.
