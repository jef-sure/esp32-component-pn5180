#include "pn5180-ndef.h"
#include "pn5180-ndef-tlv.h"
#include "pn5180.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

const uint8_t PN5180_NDEF_RTD_TEXT[]        = {'T'};
const uint8_t PN5180_NDEF_RTD_URI[]         = {'U'};
const uint8_t PN5180_NDEF_RTD_SMARTPOSTER[] = {'S', 'p'};

// NFC Forum URI RTD 1.0, table 3: URI identifier codes; index must match the encoded prefix code values.
static const char *const uri_prefix_table[] = {
    "",                           // 0x00 - no prefix
    "http://www.",                // 0x01
    "https://www.",               // 0x02
    "http://",                    // 0x03
    "https://",                   // 0x04
    "tel:",                       // 0x05
    "mailto:",                    // 0x06
    "ftp://anonymous:anonymous@", // 0x07
    "ftp://ftp.",                 // 0x08
    "ftps://",                    // 0x09
    "sftp://",                    // 0x0A
    "smb://",                     // 0x0B
    "nfs://",                     // 0x0C
    "ftp://",                     // 0x0D
    "dav://",                     // 0x0E
    "news:",                      // 0x0F
    "telnet://",                  // 0x10
    "imap:",                      // 0x11
    "rtsp://",                    // 0x12
    "urn:",                       // 0x13
    "pop:",                       // 0x14
    "sip:",                       // 0x15
    "sips:",                      // 0x16
    "tftp:",                      // 0x17
    "btspp://",                   // 0x18
    "btl2cap://",                 // 0x19
    "btgoep://",                  // 0x1A
    "tcpobex://",                 // 0x1B
    "irdaobex://",                // 0x1C
    "file://",                    // 0x1D
    "urn:epc:id:",                // 0x1E
    "urn:epc:tag:",               // 0x1F
    "urn:epc:pat:",               // 0x20
    "urn:epc:raw:",               // 0x21
    "urn:epc:",                   // 0x22
    "urn:nfc:",                   // 0x23
};

#define URI_PREFIX_COUNT (sizeof(uri_prefix_table) / sizeof(uri_prefix_table[0]))
#define TLV_TERMINATOR   0xFE

void pn5180_ndef_message_init(pn5180_ndef_message_t *msg, pn5180_ndef_record_t *records, size_t capacity)
{
    if (!msg) return;
    msg->records      = records;
    msg->record_count = 0;
    msg->capacity     = capacity;
}

bool pn5180_ndef_message_add(pn5180_ndef_message_t *msg, const pn5180_ndef_record_t *rec)
{
    if (!msg || !rec || msg->record_count >= msg->capacity) return false;
    // Shallow copy: caller retains ownership of type/id/payload buffers.
    msg->records[msg->record_count++] = *rec;
    return true;
}

void pn5180_ndef_record_init(pn5180_ndef_record_t *rec, pn5180_ndef_tnf_t tnf, const uint8_t *type, uint8_t type_len, const uint8_t *id, uint8_t id_len, const uint8_t *payload,
                      uint32_t payload_len)
{
    if (!rec) return;
    rec->tnf         = tnf;
    rec->type_len    = type_len;
    rec->id_len      = id_len;
    rec->payload_len = payload_len;
    rec->type        = type;
    rec->id          = id;
    rec->payload     = payload;
}

static bool ndef_size_add(size_t base, size_t add, size_t *out)
{
    if (out == NULL || add > (SIZE_MAX - base)) {
        return false;
    }
    *out = base + add;
    return true;
}

// A record that declares a length must also carry the bytes.
static bool pn5180_ndef_record_has_consistent_storage(const pn5180_ndef_record_t *rec)
{
    return !((rec->type_len > 0 && rec->type == NULL) || (rec->id_len > 0 && rec->id == NULL) || (rec->payload_len > 0 && rec->payload == NULL));
}

// The rules the parser applies on the way back, so the encoder never produces a message its own
// parser refuses.
static bool pn5180_ndef_record_is_encodable(const pn5180_ndef_record_t *rec)
{
    if (!pn5180_ndef_record_has_consistent_storage(rec)) return false;
    switch (rec->tnf) {
    case PN5180_NDEF_TNF_EMPTY:
        return rec->type_len == 0 && rec->id_len == 0 && rec->payload_len == 0;
    case PN5180_NDEF_TNF_UNKNOWN:
        return rec->type_len == 0;
    case PN5180_NDEF_TNF_UNCHANGED: // continuation chunks only; the encoder writes none
    case PN5180_NDEF_TNF_RESERVED:
        return false;
    default:
        return ((unsigned)rec->tnf & ~PN5180_NDEF_TNF_MASK) == 0;
    }
}

static bool pn5180_ndef_record_encoded_size(const pn5180_ndef_record_t *rec, size_t *size_out)
{
    if (!pn5180_ndef_record_is_encodable(rec)) return false;

    // Header byte, type length, payload length (1 or 4 bytes), optional ID length
    size_t size = 2u + ((rec->payload_len <= 255) ? 1u : 4u) + ((rec->id_len > 0) ? 1u : 0u);
    if (!ndef_size_add(size, rec->type_len, &size) || !ndef_size_add(size, rec->id_len, &size) || !ndef_size_add(size, rec->payload_len, &size)) {
        return false;
    }
    *size_out = size;
    return true;
}

static uint8_t pn5180_ndef_build_header_byte(const pn5180_ndef_record_t *rec, bool is_begin, bool is_end)
{
    uint8_t hdr = 0;
    if (is_begin) hdr |= PN5180_NDEF_MB;
    if (is_end) hdr |= PN5180_NDEF_ME;
    // No chunking support in this simple encoder
    if (rec->payload_len <= 255) hdr |= PN5180_NDEF_SR;
    if (rec->id_len > 0) hdr |= PN5180_NDEF_IL;
    hdr |= (uint8_t)(rec->tnf & PN5180_NDEF_TNF_MASK);
    return hdr;
}

size_t pn5180_ndef_encode_message(const pn5180_ndef_message_t *msg, uint8_t *out, size_t out_len)
{
    if (!msg || (!out && out_len > 0)) return 0;
    size_t required = 0;
    for (size_t i = 0; i < msg->record_count; ++i) {
        size_t record_size = 0;
        if (!pn5180_ndef_record_encoded_size(&msg->records[i], &record_size) || !ndef_size_add(required, record_size, &required)) {
            return 0;
        }
    }
    if (!out || out_len == 0) return required;
    if (out_len < required) return 0;

    uint8_t *p = out;
    for (size_t i = 0; i < msg->record_count; ++i) {
        const pn5180_ndef_record_t *rec          = &msg->records[i];
        bool                 is_begin     = (i == 0);
        bool                 is_end       = (i == (msg->record_count - 1));
        bool                 short_record = rec->payload_len <= 255;

        *p++ = pn5180_ndef_build_header_byte(rec, is_begin, is_end);
        *p++ = rec->type_len;
        if (short_record) {
            *p++ = (uint8_t)rec->payload_len;
        } else {
            *p++ = (uint8_t)((rec->payload_len >> 24) & 0xFF);
            *p++ = (uint8_t)((rec->payload_len >> 16) & 0xFF);
            *p++ = (uint8_t)((rec->payload_len >> 8) & 0xFF);
            *p++ = (uint8_t)(rec->payload_len & 0xFF);
        }
        if (rec->id_len > 0) {
            *p++ = rec->id_len;
        }
        if (rec->type_len > 0) {
            memcpy(p, rec->type, rec->type_len);
            p += rec->type_len;
        }
        if (rec->id_len > 0) {
            memcpy(p, rec->id, rec->id_len);
            p += rec->id_len;
        }
        if (rec->payload_len > 0) {
            memcpy(p, rec->payload, rec->payload_len);
            p += rec->payload_len;
        }
    }

    return (size_t)(p - out);
}

static uint8_t pn5180_ndef_uri_prefix_code(const char *uri, size_t *prefix_len)
{
    // Longest matching prefix wins (e.g. "https://www." over "https://").
    uint8_t best_code = 0x00;
    size_t  best_len  = 0;
    for (size_t code = 1; code < URI_PREFIX_COUNT; ++code) {
        size_t len = strlen(uri_prefix_table[code]);
        if (len > best_len && strncmp(uri, uri_prefix_table[code], len) == 0) {
            best_code = (uint8_t)code;
            best_len  = len;
        }
    }
    if (prefix_len) *prefix_len = best_len;
    return best_code;
}

bool pn5180_ndef_make_text_record(pn5180_ndef_record_t *rec, const char *lang_code, const uint8_t *text, size_t text_len, bool utf16, uint8_t *payload_buf,
                           size_t payload_buf_len)
{
    if (!rec || !text || !payload_buf) return false;
    size_t lang_len = (lang_code) ? strlen(lang_code) : 0;
    if (lang_len > 63) return false;
    size_t needed = 1 + lang_len + text_len;
    if (payload_buf_len < needed) return false;

    uint8_t status = (utf16 ? 0x80 : 0x00) | (uint8_t)lang_len;
    payload_buf[0] = status;
    if (lang_len && lang_code) memcpy(&payload_buf[1], lang_code, lang_len);
    if (text_len && text) memcpy(&payload_buf[1 + lang_len], text, text_len);

    rec->tnf         = PN5180_NDEF_TNF_WELL_KNOWN;
    rec->type        = PN5180_NDEF_RTD_TEXT;
    rec->type_len    = 1;
    rec->id          = NULL;
    rec->id_len      = 0;
    rec->payload     = payload_buf;
    rec->payload_len = (uint32_t)needed;
    return true;
}

bool pn5180_ndef_make_uri_record(pn5180_ndef_record_t *rec, const char *uri, bool abbreviate, uint8_t *payload_buf, size_t payload_buf_len)
{
    if (!rec || !uri || !payload_buf) return false;
    size_t  uri_len       = strlen(uri);
    size_t  prefix_len    = 0;
    uint8_t code          = abbreviate ? pn5180_ndef_uri_prefix_code(uri, &prefix_len) : 0x00;
    size_t  remaining_len = uri_len - prefix_len;
    size_t  needed        = 1 + remaining_len;
    if (payload_buf_len < needed) return false;

    payload_buf[0] = code;
    memcpy(&payload_buf[1], uri + prefix_len, remaining_len);

    rec->tnf         = PN5180_NDEF_TNF_WELL_KNOWN;
    rec->type        = PN5180_NDEF_RTD_URI;
    rec->type_len    = 1;
    rec->id          = NULL;
    rec->id_len      = 0;
    rec->payload     = payload_buf;
    rec->payload_len = (uint32_t)needed;
    return true;
}

static bool ndef_decode_next_ex(const uint8_t *in, size_t in_len, size_t *offset, pn5180_ndef_record_t *out_rec, bool *is_begin, bool *is_end, bool *is_chunk)
{
    if (!in || !offset || !out_rec) return false;
    // out_rec fields point into the input buffer; do not free or modify input until done.
    if (*offset >= in_len) return false;

    size_t     pos = *offset;
    uint8_t    hdr = in[pos++];
    bool       mb  = (hdr & PN5180_NDEF_MB) != 0;
    bool       me  = (hdr & PN5180_NDEF_ME) != 0;
    bool       sr  = (hdr & PN5180_NDEF_SR) != 0;
    bool       il  = (hdr & PN5180_NDEF_IL) != 0;
    pn5180_ndef_tnf_t tnf = (pn5180_ndef_tnf_t)(hdr & PN5180_NDEF_TNF_MASK);

    if (tnf == PN5180_NDEF_TNF_RESERVED) {
        // TNF 0x07 is reserved and must not appear in a message.
        return false;
    }

    if (pos >= in_len) return false;
    uint8_t type_len = in[pos++];

    uint32_t payload_len = 0;
    if (sr) {
        if (pos >= in_len) return false;
        payload_len = in[pos++];
    } else {
        if (in_len - pos < 4) return false;
        payload_len = ((uint32_t)in[pos] << 24) | ((uint32_t)in[pos + 1] << 16) | ((uint32_t)in[pos + 2] << 8) | ((uint32_t)in[pos + 3]);
        pos += 4;
    }

    uint8_t id_len = 0;
    if (il) {
        if (pos >= in_len) return false;
        id_len = in[pos++];
    }

    const uint8_t *type_ptr = NULL;
    if (type_len > 0) {
        if (type_len > in_len - pos) return false;
        type_ptr = &in[pos];
        pos += type_len;
    }

    const uint8_t *id_ptr = NULL;
    if (id_len > 0) {
        if (id_len > in_len - pos) return false;
        id_ptr = &in[pos];
        pos += id_len;
    }

    const uint8_t *payload_ptr = NULL;
    if (payload_len > 0) {
        if (payload_len > in_len - pos) return false;
        payload_ptr = &in[pos];
        pos += payload_len;
    }

    if (tnf == PN5180_NDEF_TNF_UNKNOWN && type_len != 0) {
        // NDEF 1.0: an unknown-type record carries no type.
        return false;
    }
    if (tnf == PN5180_NDEF_TNF_EMPTY && (type_len != 0 || id_len != 0 || payload_len != 0)) {
        // An empty record must carry no type, ID, or payload.
        return false;
    }

    out_rec->tnf         = tnf;
    out_rec->type_len    = type_len;
    out_rec->id_len      = id_len;
    out_rec->payload_len = payload_len;
    out_rec->type        = type_ptr;
    out_rec->id          = id_ptr;
    out_rec->payload     = payload_ptr;

    if (is_begin) *is_begin = mb;
    if (is_end) *is_end = me;
    if (is_chunk) *is_chunk = (hdr & PN5180_NDEF_CF) != 0;

    *offset = pos;
    return true;
}

bool pn5180_ndef_decode_next(const uint8_t *in, size_t in_len, size_t *offset, pn5180_ndef_record_t *out_rec, bool *is_begin, bool *is_end)
{
    return ndef_decode_next_ex(in, in_len, offset, out_rec, is_begin, is_end, NULL);
}

typedef struct
{
    size_t logical_record_count;
    size_t chunk_payload_size;
    bool   has_chunks;
} ndef_decode_plan_t;

// First pass over a message: validates the record sequence (MB/ME, chunk rules) and sizes the result.
static bool ndef_plan_decode(const uint8_t *data, size_t data_len, ndef_decode_plan_t *plan)
{
    if (data == NULL || data_len == 0 || plan == NULL) {
        return false;
    }

    memset(plan, 0, sizeof(*plan));
    size_t   pos             = 0;
    size_t   physical_count  = 0;
    uint32_t chunk_total_len = 0;
    bool     in_chunk        = false;
    bool     message_ended   = false;

    while (pos < data_len) {
        pn5180_ndef_record_t physical;
        bool                 mb = false;
        bool                 me = false;
        bool                 cf = false;
        if (!ndef_decode_next_ex(data, data_len, &pos, &physical, &mb, &me, &cf)) {
            return false;
        }

        if ((physical_count == 0 && !mb) || (physical_count != 0 && mb) || message_ended) {
            return false;
        }
        physical_count++;

        if (in_chunk) {
            // Continuation chunks use TNF "unchanged" and carry neither type nor ID.
            if (physical.tnf != PN5180_NDEF_TNF_UNCHANGED || physical.type_len != 0 || physical.id_len != 0 || (cf && me)) {
                return false;
            }
            if (physical.payload_len > UINT32_MAX - chunk_total_len ||
                !ndef_size_add(plan->chunk_payload_size, physical.payload_len, &plan->chunk_payload_size)) {
                return false;
            }
            chunk_total_len += physical.payload_len;
            if (!cf) {
                in_chunk = false;
                plan->logical_record_count++;
            }
        } else {
            if (physical.tnf == PN5180_NDEF_TNF_UNCHANGED) {
                return false;
            }
            if (cf) {
                if (me) {
                    return false;
                }
                in_chunk         = true;
                plan->has_chunks = true;
                chunk_total_len  = physical.payload_len;
                if (!ndef_size_add(plan->chunk_payload_size, physical.payload_len, &plan->chunk_payload_size)) {
                    return false;
                }
            } else {
                plan->logical_record_count++;
            }
        }

        if (me) {
            if (in_chunk) {
                return false;
            }
            message_ended = true;
        }
    }

    return message_ended && !in_chunk && plan->logical_record_count > 0;
}

size_t pn5180_ndef_decode_message(const uint8_t *in, size_t in_len, pn5180_ndef_record_t *records, size_t capacity)
{
    if (!in || !records || capacity == 0) return 0;

    // Same structural rules as for a message read from a card
    ndef_decode_plan_t plan;
    if (!ndef_plan_decode(in, in_len, &plan)) return 0;

    size_t pos   = 0;
    size_t count = 0;
    for (;;) {
        if (count == capacity) {
            // More records than the caller has room for: a part of a message is not a message.
            return 0;
        }
        bool me = false;
        if (!pn5180_ndef_decode_next(in, in_len, &pos, &records[count], NULL, &me)) {
            return 0;
        }
        count++;
        if (me) break;
    }
    return count;
}

// Second pass: fills the logical records; chunked payloads are concatenated into chunk_payload.
static bool ndef_decode_logical_records(const uint8_t *data, size_t data_len, pn5180_ndef_record_t *records, size_t record_count, uint8_t *chunk_payload)
{
    size_t                pos          = 0;
    size_t                logical      = 0;
    size_t                payload_used = 0;
    pn5180_ndef_record_t *chunk_record = NULL;

    while (pos < data_len && logical < record_count) {
        pn5180_ndef_record_t physical;
        bool                 cf = false;
        if (!ndef_decode_next_ex(data, data_len, &pos, &physical, NULL, NULL, &cf)) {
            return false;
        }

        if (chunk_record != NULL) {
            if (physical.payload_len > 0) {
                memcpy(chunk_payload + payload_used, physical.payload, physical.payload_len);
                payload_used += physical.payload_len;
                chunk_record->payload_len += physical.payload_len;
            }
            if (!cf) {
                logical++;
                chunk_record = NULL;
            }
        } else if (cf) {
            records[logical]             = physical;
            records[logical].payload     = chunk_payload + payload_used;
            records[logical].payload_len = 0;
            chunk_record                 = &records[logical];
            if (physical.payload_len > 0) {
                memcpy(chunk_payload + payload_used, physical.payload, physical.payload_len);
                payload_used += physical.payload_len;
                chunk_record->payload_len = physical.payload_len;
            }
        } else {
            records[logical++] = physical;
        }
    }

    return logical == record_count && chunk_record == NULL;
}

pn5180_ndef_result_t pn5180_ndef_parse_message(const uint8_t *raw_data, size_t raw_data_len, pn5180_ndef_message_parsed_t **out_msg)
{
    if (out_msg == NULL) {
        return PN5180_NDEF_ERR_INVALID_PARAM;
    }
    *out_msg = NULL;
    if (raw_data == NULL || raw_data_len == 0) {
        return PN5180_NDEF_ERR_PARSE_FAILED;
    }

    ndef_decode_plan_t plan;
    if (!ndef_plan_decode(raw_data, raw_data_len, &plan)) {
        return PN5180_NDEF_ERR_PARSE_FAILED;
    }

    if (plan.logical_record_count > SIZE_MAX / sizeof(pn5180_ndef_record_t)) {
        return PN5180_NDEF_ERR_NO_MEMORY;
    }
    // Single allocation: header + records array + raw NDEF data + assembled chunk payloads, for one-shot free.
    size_t records_size = sizeof(pn5180_ndef_record_t) * plan.logical_record_count;
    size_t total_size;
    if (!ndef_size_add(sizeof(pn5180_ndef_message_parsed_t), records_size, &total_size) || !ndef_size_add(total_size, raw_data_len, &total_size) ||
        !ndef_size_add(total_size, plan.chunk_payload_size, &total_size)) {
        return PN5180_NDEF_ERR_NO_MEMORY;
    }

    uint8_t *block_ptr = malloc(total_size);
    if (block_ptr == NULL) {
        return PN5180_NDEF_ERR_NO_MEMORY;
    }

    pn5180_ndef_message_parsed_t *result        = (pn5180_ndef_message_parsed_t *)block_ptr;
    pn5180_ndef_record_t         *records       = (pn5180_ndef_record_t *)(block_ptr + sizeof(pn5180_ndef_message_parsed_t));
    uint8_t                      *ndef_data     = block_ptr + sizeof(pn5180_ndef_message_parsed_t) + records_size;
    uint8_t                      *chunk_payload = ndef_data + raw_data_len;

    memcpy(ndef_data, raw_data, raw_data_len);
    if (!ndef_decode_logical_records(ndef_data, raw_data_len, records, plan.logical_record_count, chunk_payload)) {
        free(block_ptr);
        return PN5180_NDEF_ERR_PARSE_FAILED;
    }

    result->raw_data     = ndef_data;
    result->raw_data_len = raw_data_len;
    result->records      = records;
    result->record_count = plan.logical_record_count;
    *out_msg             = result;
    return PN5180_NDEF_OK;
}

#define PN5180_NDEF_DEFAULT_MAX_BLOCKS 256
#define INIT_SIZES_COUNT        (sizeof(init_sizes) / sizeof(init_sizes[0]))

pn5180_ndef_result_t pn5180_ndef_read_from_selected_card( //
    pn5180_proto_t           *proto,        //
    int                       start_block,  //
    int                       block_size,   //
    int                       max_blocks,   //
    pn5180_ndef_auth_callback_t      auth_cb,      //
    pn5180_ndef_sector_id_callback_t sector_cb,    //
    void                     *auth_ctx,     //
    pn5180_ndef_message_parsed_t   **out_msg       //
)
{
    if (!proto || !proto->block_read || block_size <= 0 || !out_msg) {
        return PN5180_NDEF_ERR_INVALID_PARAM;
    }
    *out_msg = NULL;

    int block_limit = (max_blocks > 0) ? max_blocks : PN5180_NDEF_DEFAULT_MAX_BLOCKS;

    // Start with a larger buffer and grow as needed to minimize reallocs on large NDEFs.
    static const size_t init_sizes[] = {1024, 768, 512, 384, 256};
    size_t              capacity     = 0;
    uint8_t            *buf          = NULL;
    for (size_t i = 0; i < INIT_SIZES_COUNT; i++) {
        if (init_sizes[i] >= (size_t)block_size) {
            buf = malloc(init_sizes[i]);
            if (buf) {
                capacity = init_sizes[i];
                break;
            }
        }
    }
    if (!buf) return PN5180_NDEF_ERR_NO_MEMORY;

    size_t len         = 0;
    size_t tlv_pos     = 0;
    size_t ndef_offset = 0, ndef_len = 0;
    bool   found   = false;
    bool   read_ok = true;

    bool have_last_sector = false;
    int  last_sector_id   = 0;

    for (int block = start_block; block - start_block < block_limit; block++) {
        if (len + block_size > capacity) {
            capacity *= 2;
            uint8_t *new_buf = realloc(buf, capacity);
            if (!new_buf) {
                free(buf);
                return PN5180_NDEF_ERR_NO_MEMORY;
            }
            buf = new_buf;
        }

        if (auth_cb) {
            bool call_auth = true;
            if (sector_cb) {
                int sector_id = sector_cb(block, auth_ctx);
                if (have_last_sector && sector_id == last_sector_id) {
                    call_auth = false;
                } else {
                    have_last_sector = true;
                    last_sector_id   = sector_id;
                }
            }
            if (call_auth && !auth_cb(proto, block, auth_ctx)) {
                read_ok = false;
                break;
            }
        }

        if (!proto->block_read(proto, block, buf + len, block_size)) {
            read_ok = false;
            break;
        }
        len += block_size;

        if (pn5180_ndef_tlv_find_ndef(buf, len, &tlv_pos, &ndef_offset, &ndef_len)) {
            if (ndef_offset + ndef_len <= len) {
                found = true;
                break;
            }
        } else if (tlv_pos < len && buf[tlv_pos] == TLV_TERMINATOR) {
            // Terminator TLV: there is no NDEF message beyond this point.
            break;
        }
    }

    // If no NDEF TLV was found, distinguish between empty/unsupported and read failure.
    if (!found || ndef_len == 0) {
        free(buf);
        return read_ok ? PN5180_NDEF_ERR_NO_NDEF : PN5180_NDEF_ERR_READ_FAILED;
    }

    pn5180_ndef_result_t parse_res = pn5180_ndef_parse_message(buf + ndef_offset, ndef_len, out_msg);
    free(buf);
    return parse_res;
}

void pn5180_ndef_free_parsed_message(pn5180_ndef_message_parsed_t *msg)
{
    // Single allocation; freeing the head releases all associated buffers.
    free(msg);
}

bool pn5180_ndef_extract_text(const pn5180_ndef_record_t *rec, const uint8_t **text_out, size_t *text_len_out, char *lang_buf, bool *is_utf16)
{
    if (!rec || !text_out || !text_len_out) return false;

    if (rec->tnf != PN5180_NDEF_TNF_WELL_KNOWN) return false;
    if (rec->type_len != 1 || !rec->type) return false;
    if (rec->type[0] != 'T') return false;
    if (!rec->payload || rec->payload_len < 1) return false;

    uint8_t status   = rec->payload[0];
    size_t  lang_len = status & 0x3F;
    bool    utf16    = (status & 0x80) != 0;

    if (1 + lang_len > rec->payload_len) return false;

    if (lang_buf) {
        if (lang_len > 0) {
            memcpy(lang_buf, rec->payload + 1, lang_len);
        }
        lang_buf[lang_len] = '\0';
    }

    if (is_utf16) *is_utf16 = utf16;

    *text_out     = rec->payload + 1 + lang_len;
    *text_len_out = rec->payload_len - 1 - lang_len;
    return true;
}

size_t pn5180_ndef_extract_uri(const pn5180_ndef_record_t *rec, char *uri_buf, size_t uri_buf_len)
{
    if (!rec) return 0;

    if (rec->tnf != PN5180_NDEF_TNF_WELL_KNOWN) return 0;
    if (rec->type_len != 1 || !rec->type) return 0;
    if (rec->type[0] != 'U') return 0;
    if (!rec->payload || rec->payload_len < 1) return 0;

    uint8_t     code       = rec->payload[0];
    const char *prefix     = (code < URI_PREFIX_COUNT) ? uri_prefix_table[code] : "";
    size_t      prefix_len = strlen(prefix);
    size_t      suffix_len = rec->payload_len - 1;
    size_t      total_len  = prefix_len + suffix_len;

    // Always compute total length; caller can size a buffer using the return value.
    if (uri_buf && uri_buf_len > 0) {
        size_t copy_prefix = (prefix_len < uri_buf_len) ? prefix_len : uri_buf_len - 1;
        memcpy(uri_buf, prefix, copy_prefix);

        size_t remaining   = uri_buf_len - 1 - copy_prefix;
        size_t copy_suffix = (suffix_len < remaining) ? suffix_len : remaining;
        if (copy_suffix > 0) {
            memcpy(uri_buf + copy_prefix, rec->payload + 1, copy_suffix);
        }
        uri_buf[copy_prefix + copy_suffix] = '\0';
    }

    return total_len;
}

pn5180_ndef_record_type_t pn5180_ndef_get_record_type(const pn5180_ndef_record_t *rec)
{
    if (!rec) return PN5180_NDEF_RECORD_TYPE_UNKNOWN;

    if (rec->tnf == PN5180_NDEF_TNF_EMPTY) {
        return PN5180_NDEF_RECORD_TYPE_EMPTY;
    }

    if (rec->tnf == PN5180_NDEF_TNF_MEDIA_TYPE) {
        return PN5180_NDEF_RECORD_TYPE_MIME;
    }

    if (rec->tnf == PN5180_NDEF_TNF_EXTERNAL) {
        return PN5180_NDEF_RECORD_TYPE_EXTERNAL;
    }

    if (rec->tnf == PN5180_NDEF_TNF_WELL_KNOWN && rec->type && rec->type_len > 0) {
        if (rec->type_len == 1 && rec->type[0] == 'T') {
            return PN5180_NDEF_RECORD_TYPE_TEXT;
        }
        if (rec->type_len == 1 && rec->type[0] == 'U') {
            return PN5180_NDEF_RECORD_TYPE_URI;
        }
        if (rec->type_len == 2 && rec->type[0] == 'S' && rec->type[1] == 'p') {
            return PN5180_NDEF_RECORD_TYPE_SMARTPOSTER;
        }
    }

    return PN5180_NDEF_RECORD_TYPE_UNKNOWN;
}

bool pn5180_ndef_record_is_text(const pn5180_ndef_record_t *rec)
{
    return pn5180_ndef_get_record_type(rec) == PN5180_NDEF_RECORD_TYPE_TEXT;
}

bool pn5180_ndef_record_is_uri(const pn5180_ndef_record_t *rec)
{
    return pn5180_ndef_get_record_type(rec) == PN5180_NDEF_RECORD_TYPE_URI;
}

bool pn5180_ndef_record_is_smartposter(const pn5180_ndef_record_t *rec)
{
    return pn5180_ndef_get_record_type(rec) == PN5180_NDEF_RECORD_TYPE_SMARTPOSTER;
}

bool pn5180_ndef_make_mime_record(pn5180_ndef_record_t *rec, const char *mime_type, const uint8_t *data, size_t data_len, uint8_t *type_buf, size_t type_buf_len)
{
    if (!rec || !mime_type || !type_buf) return false;

    size_t type_len = strlen(mime_type);
    if (type_len == 0 || type_len > 255 || type_len > type_buf_len) return false;

    memcpy(type_buf, mime_type, type_len);

    rec->tnf         = PN5180_NDEF_TNF_MEDIA_TYPE;
    rec->type        = type_buf;
    rec->type_len    = (uint8_t)type_len;
    rec->id          = NULL;
    rec->id_len      = 0;
    rec->payload     = data;
    rec->payload_len = (uint32_t)data_len;
    return true;
}

bool pn5180_ndef_make_external_record(pn5180_ndef_record_t *rec, const char *type_name, const uint8_t *data, size_t data_len, uint8_t *type_buf, size_t type_buf_len)
{
    if (!rec || !type_name || !type_buf) return false;

    size_t type_len = strlen(type_name);
    if (type_len == 0 || type_len > 255 || type_len > type_buf_len) return false;

    memcpy(type_buf, type_name, type_len);

    rec->tnf         = PN5180_NDEF_TNF_EXTERNAL;
    rec->type        = type_buf;
    rec->type_len    = (uint8_t)type_len;
    rec->id          = NULL;
    rec->id_len      = 0;
    rec->payload     = data;
    rec->payload_len = (uint32_t)data_len;
    return true;
}

size_t pn5180_ndef_decode_smartposter(const pn5180_ndef_record_t *rec, pn5180_ndef_record_t *records, size_t capacity)
{
    if (!pn5180_ndef_record_is_smartposter(rec)) return 0;
    if (!rec->payload || rec->payload_len == 0) return 0;

    // Same structural rules as for a message read from a card. The nested records point into the
    // payload, so a chunked record, which needs its payload assembled, cannot be returned.
    ndef_decode_plan_t plan;
    if (!ndef_plan_decode(rec->payload, rec->payload_len, &plan) || plan.has_chunks) return 0;

    return pn5180_ndef_decode_message(rec->payload, rec->payload_len, records, capacity);
}

const char *pn5180_ndef_result_to_string(pn5180_ndef_result_t result)
{
    switch (result) {
    case PN5180_NDEF_OK:
        return "Success";
    case PN5180_NDEF_ERR_INVALID_PARAM:
        return "Invalid parameter";
    case PN5180_NDEF_ERR_NO_MEMORY:
        return "Memory allocation failed";
    case PN5180_NDEF_ERR_READ_FAILED:
        return "Card read failed";
    case PN5180_NDEF_ERR_WRITE_FAILED:
        return "Card write failed";
    case PN5180_NDEF_ERR_NO_NDEF:
        return "No NDEF data found";
    case PN5180_NDEF_ERR_PARSE_FAILED:
        return "NDEF parse failed";
    case PN5180_NDEF_ERR_BUFFER_TOO_SMALL:
        return "Buffer too small";
    case PN5180_NDEF_ERR_CARD_FULL:
        return "Card capacity exceeded";
    case PN5180_NDEF_ERR_UNSUPPORTED:
        return "Card type not supported";
    case PN5180_NDEF_ERR_ACCESS_DENIED:
        return "NDEF data is access protected";
    default:
        return "Unknown error";
    }
}
