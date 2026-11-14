# Finding cards

*[По-русски](../ru/polling.md)*

A poll returns all the cards in the field, not just the first one. This page is about polls: what they return, how
several cards are found, how a scanning loop is built, and what to do with phones whose UID changes.

## A poll

```c
pn5180_poll_status_t status;
pn5180_uids_array_t *cards = pn5180_14443_get_all_uids_ex(proto, &status);
switch (status) {
case PN5180_POLL_FOUND:
    for (int i = 0; i < cards->uids_count; i++) {
        pn5180_uid_t *card = &cards->uids[i];
        if (!proto->select_by_uid(proto, card)) {
            continue;
        }
        int blocks = 0, block_size = 0;
        if (proto->detect_card_type_and_capacity(proto->pn5180, card, &blocks, &block_size)) {
            proto->select_by_uid(proto, card);
        }
        printf("SAK %02X ATQA %02X%02X type %d: %d blocks of %d bytes\n", card->sak, card->atqa[0], card->atqa[1],
               card->subtype, blocks, block_size);
        proto->halt(proto);
    }
    free(cards);
    break;
case PN5180_POLL_NO_TARGET:
    break; /* nothing in the field */
case PN5180_POLL_TRANSPORT_ERROR:
    pn5180_recover(proto->pn5180);
    break;
default:
    break; /* a card answered but could not be singled out; try again */
}
```

`pn5180_14443_get_all_uids_ex()` and `pn5180_15693_get_all_uids_ex()` return the array of cards and a status. The
`get_all_uids()` callback of the protocol object is the same poll without the status: it returns `NULL` for every
outcome but `PN5180_POLL_FOUND`.

The array is allocated on the heap; `free()` releases it. `cards->uids_count` is at least 1 when the status is
`PN5180_POLL_FOUND`.

Cards are returned ordered as found, which for ISO14443A changes from poll to poll. ISO15693 tags are sorted by signal
strength, the strongest first (the lowest `agc`).

## Poll status

| Status | ISO14443A | ISO15693 |
| ------ | --------- | -------- |
| `PN5180_POLL_FOUND` | at least one card; the array is returned | the same |
| `PN5180_POLL_NO_TARGET` | no card answered | no tag answered, or only damaged or colliding answers came |
| `PN5180_POLL_TRANSPORT_ERROR` | the PN5180 could not be driven: SPI failure, the field did not come up | the same |
| `PN5180_POLL_PROTOCOL_ERROR` | a card answered but the anticollision or the selection failed | never |
| `PN5180_POLL_NO_MEMORY` | the array could not be allocated | the same |
| `PN5180_POLL_INVALID_ARGUMENT` | a `NULL` protocol object or device | the same |

The ISO15693 poll has no `PN5180_POLL_PROTOCOL_ERROR`: answers that arrive damaged or collide and cannot be resolved
give `PN5180_POLL_NO_TARGET`, because the PN5180 reports noise in the same way and such an answer does not prove that a
tag is there.

When the poll found some cards and then ran into an error, it returns the cards it has with `PN5180_POLL_FOUND`; the
error statuses come only with an empty result.

## Several cards in the field

Neither protocol limits the number of cards, the driver does, so that a misbehaving card cannot keep a poll going. A
poll that stops at its limit logs a warning and still returns `PN5180_POLL_FOUND` with the cards it has.

### ISO14443A

The poll sends REQA, resolves one UID through all its cascade levels, halts that card with HLTA, and sends REQA again,
until no card answers. Each card takes about 8 RF frames and one `pn5180_uid_t` of heap.

- **The limit** is `max_cards` of `pn5180_14443_init()`, 14 if it is 0. The warning appears only when one more card
  did answer; that card is sent HLTA, which takes a card that is not selected back to IDLE, so that it answers the next
  poll.
- **A card that answers again** after its HLTA (the frame got lost) is halted once more; a second such repeat ends the
  poll, so a card that ignores HLTA cannot keep it going.
- **A failed anticollision** sends the cards back to IDLE with HLTA; the poll returns the cards found before it, or
  `PN5180_POLL_PROTOCOL_ERROR` if there are none.
- `agc` of each entry is read right after its card was resolved.

### ISO15693

The poll is an inventory with a mask: the driver asks only the tags whose lowest UID bits match the mask, and on a
collision it makes the mask one bit longer and tries both values of that bit. Each tag found is sent Stay Quiet, so
that it no longer answers.

- **The limit** is 192 inventory frames, enough for about 50 tags with unrelated UIDs. Tags that differ only in the
  last UID bits take more frames each: two tags that differ only in the last bit take 129.
- **A tag behind a stronger one.** The receiver takes an answer under half as strong as another one for no signal
  (PN5180 datasheet), so a tag far from the antenna turns up only once the nearer tags are quiet. A pass that found tags
  is therefore followed by one more inventory of the whole field; that costs one frame when no tag is left.
- **Modulation.** The inventory runs with ASK 10 % first and falls back to ASK 100 % only when it found nothing, so
  the signal strengths of one poll are measured with one RF configuration.

### The cards a poll left out

With the field left on, the next poll finds the cards that were left out: the cards found before are halted or quiet
and do not answer again. For ISO15693 that holds while the tags found stay quiet: `select_by_uid()` and `halt()` bring
a tag back to Ready, and the next poll counts it again, which matters only when more tags are in the field than one
poll takes.

After a field reset all cards answer again: ISO14443A settles collisions at random, so over several polls every card
turns up, though not equally often, and ISO15693 finds the same tags again.

## A scanning loop

What a loop does between polls decides which cards each poll returns.

**Every card on every pass.** Reset the field before each poll, so that the cards halted by the last pass answer
again:

```c
pn5180_set_rf_off(pn5180);
pn5180_delay_us(PN5180_RF_OFF_TIME_US); /* 5.1 ms */
proto->setup_rf(proto);
pn5180_uids_array_t *cards = pn5180_14443_get_all_uids_ex(proto, &status);
```

**Only new cards.** Leave the field on, and a card that stays in the field is not returned again until it leaves and
comes back, or until the field is reset:

- ISO14443A: `setup_rf()` with the protocol's own configuration loaded keeps the field. A card that was selected and
  halted is halted again and stays out of the next poll.
- ISO15693: call `get_all_uids()` without `setup_rf()` in between. The inventory loads its own configuration (ASK 10 %,
  see above) and keeps the field when that one is loaded already, while `setup_rf()` loads the configuration given to
  `pn5180_15693_init()` and, when that is another one, switches the field off and on. A tag that was selected, or
  halted with Reset to Ready, is back in Ready and is returned again.

**Both protocols.** Poll one after the other. `setup_rf()` of the other protocol switches the field off for 5.1 ms
itself, so both polls start from cards in their idle state:

```c
iso14443->setup_rf(iso14443);
pn5180_uids_array_t *a = iso14443->get_all_uids(iso14443);
/* ... */
iso15693->setup_rf(iso15693);
pn5180_uids_array_t *v = iso15693->get_all_uids(iso15693);
/* ... */
```

**The pause between passes.** Use `vTaskDelay()`: it releases the CPU for the whole pause. Switching the field off
during a long pause saves power and leaves other readers nearby alone; the
[low power card detection](hardware.md#low-power-card-detection) of the PN5180 can wake the program when a card comes
near.

**Errors.** `PN5180_POLL_TRANSPORT_ERROR` means that the PN5180 did not respond: call `pn5180_recover()`, which resets
it and restores the RF configuration and the field. `PN5180_POLL_PROTOCOL_ERROR` usually means that cards answered at
once and one of them moved; the next poll tries again.

## Targets with a random UID

A phone in card emulation, and some cards, answer with a random 4-byte UID whose first byte is `08` and pick a new one
when the RF field comes back (ISO/IEC 14443-3). Such a UID identifies the target only until the field is switched off:

- Select and use the target in the scan that found it, before the field goes off.
- After the field was off (`setup_rf()` of the other protocol, `pn5180_set_rf_off()`, `pn5180_recover()`), the target
  comes back under another UID. A `pn5180_uid_t` kept from before no longer matches anything: `select_by_uid()` returns
  `false` for it, and so does the second attempt of `pn5180_ndef_read_card_auto()` if it has to select the card again.
  Scan again and take the new entry.
- Do not use such a UID as an identity: the same phone shows up as a new card after every field cycle.

```c
bool random_uid = card->uid_length == 4 && card->uid[0] == 0x08;
```

A phone is an ISO14443-4 target: after `select_by_uid()` it speaks APDUs, and its NDEF message, if an app emulates a
Type 4 tag, is read by `pn5180_ndef_read_card_auto()`. See [ISO14443-4 and APDUs](iso14443-4.md).
