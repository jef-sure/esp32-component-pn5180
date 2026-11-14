# NDEF

*[По-русски](../ru/ndef.md)*

NDEF is the format of the NFC Forum for data on a tag: a message of records, each a URI, a text, a MIME object or a
type an application defines. A phone reads it when it touches the tag. The driver reads NDEF from all four tag mappings
it knows, writes it to two of them, and builds and parses messages in memory.

```c
#include "pn5180-ndef.h"
```

| Tag | Mapping | Read | Write |
| --- | ------- | ---- | ----- |
| Ultralight, NTAG | NFC Forum Type 2 | yes | yes |
| MIFARE Classic, MIFARE Plus in security level 2 | MIFARE Classic mapping (MAD) | yes | no |
| ISO14443-4 cards, phones | NFC Forum Type 4 | yes | no |
| ISO15693 tags | NFC Forum Type 5 | yes | yes |

Not implemented: formatting a blank tag, writing NDEF to MIFARE Classic and Type 4 cards.

## Reading

```c
pn5180_ndef_message_parsed_t *msg = NULL;
pn5180_ndef_result_t result = pn5180_ndef_read_card_auto(proto, card, &msg);
if (result == PN5180_NDEF_OK) {
    for (size_t i = 0; i < msg->record_count; i++) {
        const pn5180_ndef_record_t *rec = &msg->records[i];
        char uri[256];
        const uint8_t *text;
        size_t text_len;
        char lang[64];
        if (pn5180_ndef_extract_uri(rec, uri, sizeof(uri)) > 0) {
            printf("URI: %s\n", uri);
        } else if (pn5180_ndef_extract_text(rec, &text, &text_len, lang, sizeof(lang), NULL)) {
            printf("Text (%s): %.*s\n", lang, (int)text_len, text);
        }
    }
    pn5180_ndef_free_parsed_message(msg);
} else {
    ESP_LOGW(TAG, "%s", pn5180_ndef_result_to_string(result));
}
```

`pn5180_ndef_read_card_auto()` picks the mapping from `card->subtype`, so the card must be selected and its type
detected first (`select_by_uid()`, `detect_card_type_and_capacity()`, and a second `select_by_uid()` when the
detection asks for it). It does not check which card is selected: the caller selects the card it passes.

On success `msg` holds the encoded message (`raw_data`, `raw_data_len`) and its records (`records`, `record_count`);
chunked records are already put together. `pn5180_ndef_free_parsed_message()` releases all of it.

### Results

| Result | Meaning |
| ------ | ------- |
| `PN5180_NDEF_OK` | the message was read and parsed |
| `PN5180_NDEF_ERR_NO_NDEF` | the card works but is not NDEF formatted or carries no message |
| `PN5180_NDEF_ERR_UNSUPPORTED` | the card type has no NDEF mapping here, or the tag declares a mapping version or access conditions the driver does not know |
| `PN5180_NDEF_ERR_ACCESS_DENIED` | the tag protects its message against reading |
| `PN5180_NDEF_ERR_PARSE_FAILED` | the tag or the message is inconsistent |
| `PN5180_NDEF_ERR_READ_FAILED` | reading failed, also after the card was selected again |
| `PN5180_NDEF_ERR_NO_MEMORY` | the message could not be allocated |
| `PN5180_NDEF_ERR_INVALID_PARAM` | a `NULL` argument |

The checks are those of the NXP reader library (NxpNfcRdLib).

A read that fails is repeated once after the card was selected again, because several card families leave the
selected state after an error. `PN5180_NDEF_ERR_READ_FAILED` means that the second attempt failed too. Afterwards the
card may be out of the selected state: select it again before other commands.

### Type 2: Ultralight and NTAG

The capability container is page 3: magic number E1h, mapping version, size of the data area, access conditions. The
TLVs start at page 4. Lock Control and Memory Control TLVs mark lock and reserved bytes inside the data area; the read
goes around them, so a message continues behind them. The data area is the one the capability container declares,
bounded by the memory the detection found. A tag without GET_VERSION (the original Ultralight, NTAG203) is detected as
an Ultralight with 16 pages, a guess, so for it the capability container alone sets the size.

A capability container with another major version than 1, or with access conditions other than read/write and
read-only, is `PN5180_NDEF_ERR_UNSUPPORTED`.

### MIFARE Classic

The directory sector (MAD, sector 0, and sector 16 on a 4K card) lists which sectors belong to which application; the
NDEF sectors carry the application ID 03E1h.

- The directory sector is opened with the MAD key `A0 A1 A2 A3 A4 A5` or the default key `FF FF FF FF FF FF`. A card
  that turns down both has no public MAD: `PN5180_NDEF_ERR_NO_NDEF`. So is a MAD with a wrong CRC, and a card whose NDEF
  sectors are not contiguous.
- The NDEF sectors are opened with the NFC key `D3 F7 D3 F7 D3 F7` or the default key. Sectors that turn down both are
  `PN5180_NDEF_ERR_ACCESS_DENIED`.
- The general purpose byte of the first NDEF sector (mapping version and read access) is checked when the NFC key
  opened it. A sector that only the default key opens was never NFC formatted and keeps the factory byte 69h, which
  says nothing about NDEF, so it is read without that check.
- A card that does not answer the authentication of a directory or NDEF sector (it left the field for a moment), and a
  READ of the directory that fails after the MAD key was accepted, are read errors: read again after a new select. A
  card that turns down both keys of a sector answers the same way the second time and is not read again.
- An NDEF TLV longer than the sectors the directory lists is `PN5180_NDEF_ERR_PARSE_FAILED`.

### Type 4: ISO14443-4 cards and phones

The NDEF application of mapping 2.0 and later is selected (AID `D2 76 00 00 85 01 01`), as in the NXP reader library,
then the capability container file E103h, then the NDEF file it names. A mapping 1.0 tag has another AID and reads as
`PN5180_NDEF_ERR_NO_NDEF`.

A SELECT that the card refuses with a status word is `PN5180_NDEF_ERR_NO_NDEF`; a SELECT whose answer carries no status
word is a read error and is read again. An NDEF file that the capability container declares unreadable is
`PN5180_NDEF_ERR_ACCESS_DENIED`. A Type 4 message can be up to 32 KB long, see [Memory](#memory).

### Type 5: ISO15693

The capability container is in block 0 (4 bytes, or 8 for a large tag), the TLVs follow. The same checks of version and
access conditions as for Type 2 apply.

### Memory

The message is read from the tag into one heap buffer and parsed into one block, which
`pn5180_ndef_free_parsed_message()` releases; it holds the message once more and a `pn5180_ndef_record_t` (24 bytes on
the ESP32) for every record. The tag decides how large that is, and the driver sets no limit of its own.

The worst case is a Type 4 card or a phone acting as one: up to 32 KB of message, and 32 KB of the smallest possible
records (3 bytes each) take about 320 KB at the peak. Without PSRAM such an allocation fails and the read returns
`PN5180_NDEF_ERR_NO_MEMORY`; with PSRAM and `CONFIG_SPIRAM_USE_MALLOC` it succeeds and stays allocated until the
message is freed. A Type 2 tag holds at most about 900 bytes, an ISO15693 tag usually a few KB.

## Records

```c
typedef struct {
    pn5180_ndef_tnf_t tnf;         /* Type Name Format */
    uint8_t           type_len;
    uint8_t           id_len;
    uint32_t          payload_len;
    const uint8_t    *type;
    const uint8_t    *id;
    const uint8_t    *payload;
} pn5180_ndef_record_t;
```

A record points into memory it does not own: into the parsed message, into the buffer it was decoded from, or into
the buffers given to the builders below.

`pn5180_ndef_get_record_type()` sorts a record into one of the kinds the driver knows:

| Kind | TNF and type | Helper |
| ---- | ------------ | ------ |
| `PN5180_NDEF_RECORD_TYPE_URI` | Well-known, `U` | `pn5180_ndef_extract_uri()` |
| `PN5180_NDEF_RECORD_TYPE_TEXT` | Well-known, `T` | `pn5180_ndef_extract_text()` |
| `PN5180_NDEF_RECORD_TYPE_SMARTPOSTER` | Well-known, `Sp` | `pn5180_ndef_decode_smartposter()` |
| `PN5180_NDEF_RECORD_TYPE_MIME` | Media type, for example `application/json` | `type` and `payload` as they are |
| `PN5180_NDEF_RECORD_TYPE_EXTERNAL` | External, for example `example.com:mytype` | `type` and `payload` as they are |
| `PN5180_NDEF_RECORD_TYPE_EMPTY` | Empty | none |
| `PN5180_NDEF_RECORD_TYPE_UNKNOWN` | anything else | none |

`pn5180_ndef_record_is_uri()`, `_is_text()` and `_is_smartposter()` answer the same question for one kind.

### URI

```c
char   uri[256];
size_t len = pn5180_ndef_extract_uri(rec, uri, sizeof(uri));
if (len >= sizeof(uri)) {
    /* truncated: len is the full length */
}
```

The prefix code of the record (`https://www.`, `tel:`, `mailto:` and the others of the URI record definition) is
expanded. The result is the length of the whole URI without the terminating NUL, 0 for a record that is not a URI;
`uri` always gets a NUL-terminated string, truncated when the result is `sizeof(uri)` or more. `NULL` with size 0 asks
for the length only.

### Text

```c
const uint8_t *text;
size_t         text_len;
char           lang[64];
bool           utf16;
if (pn5180_ndef_extract_text(rec, &text, &text_len, lang, sizeof(lang), &utf16)) {
    /* text points into the record: text_len bytes, not NUL-terminated */
}
```

The text is not copied: `text` points into the payload. The language code is copied into `lang`, NUL-terminated; the
card sets its length, up to 63 bytes, so 64 bytes hold any code, and a smaller buffer gets it truncated. `utf16` tells
UTF-16 from UTF-8; `lang` may be `NULL`, and so may `utf16`.

### Smart Poster

A Smart Poster carries a message of its own in its payload: a URI, titles in several languages, an action, an icon.

```c
pn5180_ndef_record_t inner[8];
size_t n = pn5180_ndef_decode_smartposter(rec, inner, 8);
for (size_t i = 0; i < n; i++) {
    /* pn5180_ndef_extract_uri(&inner[i], ...), pn5180_ndef_extract_text(&inner[i], ...) */
}
```

The inner records point into the payload of `rec`. The function returns 0 when the inner message is malformed, has
chunked records, or has more records than the array holds.

## Building a message

```c
pn5180_ndef_record_t  records[2];
pn5180_ndef_message_t message;
uint8_t               text_payload[64];
uint8_t               uri_payload[128];

pn5180_ndef_message_init(&message, records, 2);

pn5180_ndef_record_t rec;
pn5180_ndef_make_text_record(&rec, "en", (const uint8_t *)"Hello NFC", 9, false, text_payload, sizeof(text_payload));
pn5180_ndef_message_add(&message, &rec);
pn5180_ndef_make_uri_record(&rec, "https://www.example.com", true, uri_payload, sizeof(uri_payload));
pn5180_ndef_message_add(&message, &rec);
```

- `pn5180_ndef_message_init()` gives a message an array of records of the caller; `pn5180_ndef_message_add()` copies a
  record into it (the record, not its data) and returns `false` when the array is full.
- `pn5180_ndef_make_text_record()` writes the payload, status byte, language code and text, into the given buffer,
  which needs `1 + strlen(lang) + text_len` bytes; the language code has at most 63 bytes.
- `pn5180_ndef_make_uri_record()` writes the payload into the given buffer, which needs `1 + strlen(uri)` bytes; with
  `abbreviate` the longest known prefix is replaced by its code.
- `pn5180_ndef_make_mime_record()` and `pn5180_ndef_make_external_record()` copy the type into `type_buf` (no NUL
  needed, at most 255 bytes) and point the payload at `data`, which is not copied.
- `pn5180_ndef_record_init()` sets up a record of any TNF from pointers of the caller.

Every buffer a record points to must stay valid until the message is encoded or written.

### Encoding

```c
size_t size = pn5180_ndef_encode_message(&message, NULL, 0);   /* size query */
uint8_t *bytes = malloc(size);
size_t written = pn5180_ndef_encode_message(&message, bytes, size);
```

`pn5180_ndef_encode_message()` sets the Message Begin and Message End flags and chooses short records where the
payload allows. It returns the number of bytes written, or with `out` `NULL` the number needed; 0 when the message is
empty, the buffer too small, or a record is one the parser would refuse: an Empty record with a type, ID or payload, an
Unknown record with a type, TNF Unchanged or Reserved, or a length without its pointer. Nothing is written on failure.

## Writing to a tag

```c
pn5180_ndef_record_t  record;
pn5180_ndef_record_t  storage[1];
pn5180_ndef_message_t message;
uint8_t               payload[128];

pn5180_ndef_make_uri_record(&record, "https://www.example.com", true, payload, sizeof(payload));
pn5180_ndef_message_init(&message, storage, 1);
pn5180_ndef_message_add(&message, &record);

/* card: selected, after detect_card_type_and_capacity(). The data area is found on the tag. */
pn5180_ndef_result_t result = pn5180_ndef_write_card_auto(proto, card, &message);
```

`pn5180_ndef_write_card_auto()` is the counterpart of `pn5180_ndef_read_card_auto()`: it writes Ultralight / NTAG and
ISO15693 tags and returns `PN5180_NDEF_ERR_UNSUPPORTED` for MIFARE Classic and ISO14443-4 cards. It follows the
procedure of the NXP reader library:

1. The capability container must show a supported version and read/write access, and the data area must hold an NDEF
   TLV, an empty one on a new tag. NTAG and ICODE tags usually leave the factory formatted that way.
2. The message replaces the content of that TLV; TLVs in front of it, such as the Lock Control TLV of an NTAG, are
   kept.
3. The TLV length is set to 0 first and to its real value last, so an interrupted write leaves an empty message
   instead of a damaged one.
4. A Terminator TLV follows the message if the data area has room for it.

| Result | Meaning |
| ------ | ------- |
| `PN5180_NDEF_OK` | written |
| `PN5180_NDEF_ERR_NO_NDEF` | the tag is not NDEF formatted: no capability container, or no NDEF TLV |
| `PN5180_NDEF_ERR_READ_ONLY` | the capability container does not grant write access |
| `PN5180_NDEF_ERR_CARD_FULL` | the message does not fit the data area |
| `PN5180_NDEF_ERR_UNSUPPORTED` | a card type this function does not write, an unknown mapping version, proprietary access conditions, or a Type 2 tag with lock or reserved bytes inside the blocks to write |
| `PN5180_NDEF_ERR_READ_FAILED`, `PN5180_NDEF_ERR_WRITE_FAILED` | the card refused a command; select it again |

A read goes around the lock and reserved bytes of a Type 2 tag, a write does not: such a write is refused. Write the
blocks yourself with `block_write` in that case.

## Messages in memory

For data that does not come from a tag through `pn5180_ndef_read_card_auto()`, such as a message received over another
channel:

- `pn5180_ndef_parse_message()` parses an encoded message into a `pn5180_ndef_message_parsed_t` that owns a copy of it,
  with chunked records put together; free it with `pn5180_ndef_free_parsed_message()`.
- `pn5180_ndef_decode_message()` decodes into an array of the caller and allocates nothing; the records point into the
  input, and chunks stay separate records. It returns 0 for a malformed message or one with more records than the
  array holds.
- `pn5180_ndef_decode_next()` decodes one record at an offset and advances it, for walking through a message record by
  record.
- `pn5180_ndef_tlv_find_ndef()` (`pn5180-ndef-tlv.h`) finds the NDEF TLV in the bytes of a tag's data area: it returns
  the offset and the declared length of the message; the message may run past the end of the bytes given, which the
  caller checks.

Both parsers check the structure of the message: Message Begin on the first record only, Message End on the last one,
nothing after it, valid chunk sequences.

`pn5180_ndef_read_from_selected_card()` is deprecated: it reads raw blocks from a start block and needs the layout of
the card, which `pn5180_ndef_read_card_auto()` knows. Given page 4 of a Type 2 tag and 16-byte blocks, it returns
any message longer than the first read damaged.
