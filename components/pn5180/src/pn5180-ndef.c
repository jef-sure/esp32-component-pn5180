#include "pn5180-ndef.h"
#include "pn5180-ndef-tlv.h"
#include "pn5180.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

const uint8_t NDEF_RTD_TEXT[]        = {'T'};
const uint8_t NDEF_RTD_URI[]         = {'U'};
const uint8_t NDEF_RTD_SMARTPOSTER[] = {'S', 'p'};

// NFC Forum URI Prefix Code table; index must match the encoded prefix code values.
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
    "smsto:",                     // 0x0B
    "sms:",                       // 0x0C
    "mms:",                       // 0x0D
    "mmsto:",                     // 0x0E
    "_ndef/_rtd_",                // 0x0F (reserved)
    "_ndef/_urn_",                // 0x10 (reserved)
    "_ndef/_pop_",                // 0x11 (reserved)
    "_ndef/_sip_",                // 0x12 (reserved)
    "geo:",                       // 0x13
    "magnet:?",                   // 0x14
    "urn:",                       // 0x15
    "urn:epc:id:",                // 0x16
    "urn:epc:tag:",               // 0x17
    "urn:epc:pat:",               // 0x18
    "urn:epc:raw:",               // 0x19
    "urn:epc:",                   // 0x1A
    "urn:nfc:",                   // 0x1B
};

#define URI_PREFIX_COUNT (sizeof(uri_prefix_table) / sizeof(uri_prefix_table[0]))
#define TLV_NDEF         0x03
#define TLV_TERMINATOR   0xFE

// Prefixes sorted by length to ensure longest-prefix match during encoding.
typedef struct
{
    uint8_t code;
    uint8_t len;
} uri_encode_order_entry_t;

static const uri_encode_order_entry_t uri_encode_order[] = {
    {0x07, 26},
    {0x02, 12},
    {0x01, 11},
    {0x08, 9 },
    {0x04, 8 },
    {0x09, 7 },
    {0x0A, 7 },
    {0x06, 7 },
    {0x14, 8 },
    {0x03, 7 },
    {0x0B, 6 },
    {0x0E, 6 },
    {0x05, 4 },
    {0x0C, 4 },
    {0x0D, 4 },
    {0x13, 4 },
    {0x15, 4 },
};
#define URI_ENCODE_ORDER_COUNT (sizeof(uri_encode_order) / sizeof(uri_encode_order[0]))

void ndef_message_init(ndef_message_t *msg, ndef_record_t *records, size_t capacity)
{
    if (!msg) return;
    msg->records      = records;
    msg->record_count = 0;
    msg->capacity     = capacity;
}

bool ndef_message_add(ndef_message_t *msg, const ndef_record_t *rec)
{
    if (!msg || !rec || msg->record_count >= msg->capacity) return false;
    // Shallow copy: caller retains ownership of type/id/payload buffers.
    msg->records[msg->record_count++] = *rec;
    return true;
}

void ndef_record_init(ndef_record_t *rec, ndef_tnf_t tnf, const uint8_t *type, uint8_t type_len, const uint8_t *id, uint8_t id_len, const uint8_t *payload,
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

static size_t ndef_record_encoded_size(const ndef_record_t *rec, bool is_begin, bool is_end)
{
    if (!rec) return 0;
    bool short_record = rec->payload_len <= 255;

    size_t size = 1;
    size += 1;
    size += short_record ? 1 : 4;
    if (rec->id_len > 0) size += 1;
    size += rec->type_len;
    if (rec->id_len > 0) size += rec->id_len;
    size += rec->payload_len;
    (void)is_begin;
    (void)is_end;
    return size;
}

static uint8_t ndef_build_header_byte(const ndef_record_t *rec, bool is_begin, bool is_end)
{
    uint8_t hdr = 0;
    if (is_begin) hdr |= NDEF_MB;
    if (is_end) hdr |= NDEF_ME;
    // No chunking support in this simple encoder
    if (rec->payload_len <= 255) hdr |= NDEF_SR;
    if (rec->id_len > 0) hdr |= NDEF_IL;
    hdr |= (uint8_t)(rec->tnf & NDEF_TNF_MASK);
    return hdr;
}

size_t ndef_encode_message(const ndef_message_t *msg, uint8_t *out, size_t out_len)
{
    if (!msg || (!out && out_len > 0)) return 0;
    size_t required = 0;
    for (size_t i = 0; i < msg->record_count; ++i) {
        const ndef_record_t *rec = &msg->records[i];
        required += ndef_record_encoded_size(rec, i == 0, i == (msg->record_count - 1));
    }
    if (!out || out_len == 0) return required;
    if (out_len < required) return 0;

    uint8_t *p = out;
    for (size_t i = 0; i < msg->record_count; ++i) {
        const ndef_record_t *rec          = &msg->records[i];
        bool                 is_begin     = (i == 0);
        bool                 is_end       = (i == (msg->record_count - 1));
        bool                 short_record = rec->payload_len <= 255;

        *p++ = ndef_build_header_byte(rec, is_begin, is_end);
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
        if (rec->type_len > 0 && rec->type) {
            memcpy(p, rec->type, rec->type_len);
            p += rec->type_len;
        }
        if (rec->id_len > 0 && rec->id) {
            memcpy(p, rec->id, rec->id_len);
            p += rec->id_len;
        }
        if (rec->payload_len > 0 && rec->payload) {
            memcpy(p, rec->payload, rec->payload_len);
            p += rec->payload_len;
        }
    }

    return (size_t)(p - out);
}

static uint8_t ndef_uri_prefix_code(const char *uri, size_t *prefix_len)
{
    for (size_t i = 0; i < URI_ENCODE_ORDER_COUNT; ++i) {
        uint8_t     code   = uri_encode_order[i].code;
        const char *prefix = uri_prefix_table[code];
        size_t      len    = uri_encode_order[i].len;
        if (strncmp(uri, prefix, len) == 0) {
            if (prefix_len) *prefix_len = len;
            return code;
        }
    }
    if (prefix_len) *prefix_len = 0;
    return 0x00;
}

bool ndef_make_text_record(ndef_record_t *rec, const char *lang_code, const uint8_t *text, size_t text_len, bool utf16, uint8_t *payload_buf,
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

    rec->tnf         = NDEF_TNF_WELL_KNOWN;
    rec->type        = NDEF_RTD_TEXT;
    rec->type_len    = 1;
    rec->id          = NULL;
    rec->id_len      = 0;
    rec->payload     = payload_buf;
    rec->payload_len = (uint32_t)needed;
    return true;
}

bool ndef_make_uri_record(ndef_record_t *rec, const char *uri, bool abbreviate, uint8_t *payload_buf, size_t payload_buf_len)
{
    if (!rec || !uri || !payload_buf) return false;
    size_t  uri_len       = strlen(uri);
    size_t  prefix_len    = 0;
    uint8_t code          = abbreviate ? ndef_uri_prefix_code(uri, &prefix_len) : 0x00;
    size_t  remaining_len = uri_len - prefix_len;
    size_t  needed        = 1 + remaining_len;
    if (payload_buf_len < needed) return false;

    payload_buf[0] = code;
    memcpy(&payload_buf[1], uri + prefix_len, remaining_len);

    rec->tnf         = NDEF_TNF_WELL_KNOWN;
    rec->type        = NDEF_RTD_URI;
    rec->type_len    = 1;
    rec->id          = NULL;
    rec->id_len      = 0;
    rec->payload     = payload_buf;
    rec->payload_len = (uint32_t)needed;
    return true;
}

bool ndef_decode_next(const uint8_t *in, size_t in_len, size_t *offset, ndef_record_t *out_rec, bool *is_begin, bool *is_end)
{
    if (!in || !offset || !out_rec) return false;
    // out_rec fields point into the input buffer; do not free or modify input until done.
    if (*offset >= in_len) return false;

    size_t     pos = *offset;
    uint8_t    hdr = in[pos++];
    bool       mb  = (hdr & NDEF_MB) != 0;
    bool       me  = (hdr & NDEF_ME) != 0;
    bool       sr  = (hdr & NDEF_SR) != 0;
    bool       il  = (hdr & NDEF_IL) != 0;
    ndef_tnf_t tnf = (ndef_tnf_t)(hdr & NDEF_TNF_MASK);

    if (pos >= in_len) return false;
    uint8_t type_len = in[pos++];

    uint32_t payload_len = 0;
    if (sr) {
        if (pos >= in_len) return false;
        payload_len = in[pos++];
    } else {
        if (pos + 4 > in_len) return false;
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
        if (pos + type_len > in_len) return false;
        type_ptr = &in[pos];
        pos += type_len;
    }

    const uint8_t *id_ptr = NULL;
    if (id_len > 0) {
        if (pos + id_len > in_len) return false;
        id_ptr = &in[pos];
        pos += id_len;
    }

    const uint8_t *payload_ptr = NULL;
    if (payload_len > 0) {
        if (pos + payload_len > in_len) return false;
        payload_ptr = &in[pos];
        pos += payload_len;
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

    *offset = pos;
    return true;
}

size_t ndef_decode_message(const uint8_t *in, size_t in_len, ndef_record_t *records, size_t capacity)
{
    if (!in || !records || capacity == 0) return 0;
    size_t pos   = 0;
    size_t count = 0;
    while (count < capacity) {
        bool mb = false, me = false;
        if (!ndef_decode_next(in, in_len, &pos, &records[count], &mb, &me)) {
            return 0;
        }
        count++;
        if (me) break;
        if (pos >= in_len) break;
    }
    return count;
}

static size_t ndef_count_records(const uint8_t *data, size_t data_len)
{
    size_t        count = 0, pos = 0;
    ndef_record_t rec;
    while (pos < data_len) {
        bool me = false;
        if (!ndef_decode_next(data, data_len, &pos, &rec, NULL, &me)) break;
        count++;
        if (me) break;
    }
    return count;
}

#define NDEF_DEFAULT_MAX_BLOCKS 256
#define INIT_SIZES_COUNT        (sizeof(init_sizes) / sizeof(init_sizes[0]))

ndef_result_t ndef_read_from_selected_card(pn5180_proto_t *proto, int start_block, int block_size, int max_blocks, ndef_message_parsed_t **out_msg)
{
    if (!proto || !proto->block_read || block_size <= 0 || !out_msg) {
        return NDEF_ERR_INVALID_PARAM;
    }
    *out_msg = NULL;

    int block_limit = (max_blocks > 0) ? max_blocks : NDEF_DEFAULT_MAX_BLOCKS;

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
    if (!buf) return NDEF_ERR_NO_MEMORY;

    size_t len         = 0;
    size_t tlv_pos     = 0;
    size_t ndef_offset = 0, ndef_len = 0;
    bool   found   = false;
    bool   read_ok = true;

    for (int block = start_block; block - start_block < block_limit; block++) {
        if (len + block_size > capacity) {
            capacity *= 2;
            uint8_t *new_buf = realloc(buf, capacity);
            if (!new_buf) {
                free(buf);
                return NDEF_ERR_NO_MEMORY;
            }
            buf = new_buf;
        }

        if (!proto->block_read(proto, block, buf + len, block_size)) {
            read_ok = false;
            break;
        }
        len += block_size;

        if (ndef_tlv_find_ndef(buf, len, &tlv_pos, &ndef_offset, &ndef_len)) {
            if (ndef_offset + ndef_len <= len) {
                found = true;
                break;
            }
        }
    }

    // If no NDEF TLV was found, distinguish between empty/unsupported and read failure.
    if (!found || ndef_len == 0) {
        free(buf);
        return read_ok ? NDEF_ERR_NO_NDEF : NDEF_ERR_READ_FAILED;
    }

    size_t count = ndef_count_records(buf + ndef_offset, ndef_len);
    if (count == 0) {
        free(buf);
        return NDEF_ERR_PARSE_FAILED;
    }

    // Single allocation: header + records array + raw NDEF data
    // Single allocation: header + records array + raw NDEF data for one-shot free.
    size_t records_size = sizeof(ndef_record_t) * count;
    size_t total_size   = sizeof(ndef_message_parsed_t) + records_size + ndef_len;

    uint8_t *block_ptr = malloc(total_size);
    if (!block_ptr) {
        free(buf);
        return NDEF_ERR_NO_MEMORY;
    }

    ndef_message_parsed_t *result    = (ndef_message_parsed_t *)block_ptr;
    ndef_record_t         *records   = (ndef_record_t *)(block_ptr + sizeof(ndef_message_parsed_t));
    uint8_t               *ndef_data = block_ptr + sizeof(ndef_message_parsed_t) + records_size;

    memcpy(ndef_data, buf + ndef_offset, ndef_len);
    free(buf);

    if (ndef_decode_message(ndef_data, ndef_len, records, count) != count) {
        free(block_ptr);
        return NDEF_ERR_PARSE_FAILED;
    }

    result->raw_data     = ndef_data;
    result->raw_data_len = ndef_len;
    result->records      = records;
    result->record_count = count;
    *out_msg             = result;
    return NDEF_OK;
}

void ndef_free_parsed_message(ndef_message_parsed_t *msg)
{
    // Single allocation; freeing the head releases all associated buffers.
    free(msg);
}

bool ndef_extract_text(const ndef_record_t *rec, const uint8_t **text_out, size_t *text_len_out, char *lang_buf, bool *is_utf16)
{
    if (!rec || !text_out || !text_len_out) return false;

    if (rec->tnf != NDEF_TNF_WELL_KNOWN) return false;
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

size_t ndef_extract_uri(const ndef_record_t *rec, char *uri_buf, size_t uri_buf_len)
{
    if (!rec) return 0;

    if (rec->tnf != NDEF_TNF_WELL_KNOWN) return 0;
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

ndef_result_t ndef_write_to_selected_card(pn5180_proto_t *proto, const ndef_message_t *msg, int start_block, int block_size, int max_blocks)
{
    if (!proto || !proto->block_write || !msg || block_size <= 0) {
        return NDEF_ERR_INVALID_PARAM;
    }

    size_t ndef_len = ndef_encode_message(msg, NULL, 0);
    if (ndef_len == 0) {
        return NDEF_ERR_INVALID_PARAM;
    }

    // Wrap NDEF in a TLV with a short or extended length and a terminator byte.
    size_t tlv_len_bytes = (ndef_len < 0xFF) ? 1 : 3;
    size_t total_len     = 1 + tlv_len_bytes + ndef_len + 1;

    size_t blocks_needed = (total_len + block_size - 1) / block_size;

    if (max_blocks > 0 && (int)blocks_needed > max_blocks) {
        return NDEF_ERR_CARD_FULL;
    }

    size_t   buf_size = blocks_needed * block_size;
    uint8_t *buf      = calloc(buf_size, 1);
    if (!buf) {
        return NDEF_ERR_NO_MEMORY;
    }

    size_t pos = 0;

    buf[pos++] = TLV_NDEF;

    if (ndef_len < 0xFF) {
        buf[pos++] = (uint8_t)ndef_len;
    } else {
        buf[pos++] = 0xFF;
        buf[pos++] = (uint8_t)(ndef_len >> 8);
        buf[pos++] = (uint8_t)(ndef_len & 0xFF);
    }

    if (ndef_encode_message(msg, buf + pos, ndef_len) != ndef_len) {
        free(buf);
        return NDEF_ERR_INVALID_PARAM;
    }
    pos += ndef_len;

    buf[pos++] = TLV_TERMINATOR;

    for (size_t i = 0; i < blocks_needed; i++) {
        int block_num = start_block + (int)i;
        if (proto->block_write(proto, block_num, buf + (i * block_size), (size_t)block_size) < 0) {
            free(buf);
            return NDEF_ERR_WRITE_FAILED;
        }
    }

    free(buf);
    return NDEF_OK;
}

ndef_record_type_t ndef_get_record_type(const ndef_record_t *rec)
{
    if (!rec) return NDEF_RECORD_TYPE_UNKNOWN;

    if (rec->tnf == NDEF_TNF_EMPTY) {
        return NDEF_RECORD_TYPE_EMPTY;
    }

    if (rec->tnf == NDEF_TNF_MEDIA_TYPE) {
        return NDEF_RECORD_TYPE_MIME;
    }

    if (rec->tnf == NDEF_TNF_EXTERNAL) {
        return NDEF_RECORD_TYPE_EXTERNAL;
    }

    if (rec->tnf == NDEF_TNF_WELL_KNOWN && rec->type && rec->type_len > 0) {
        if (rec->type_len == 1 && rec->type[0] == 'T') {
            return NDEF_RECORD_TYPE_TEXT;
        }
        if (rec->type_len == 1 && rec->type[0] == 'U') {
            return NDEF_RECORD_TYPE_URI;
        }
        if (rec->type_len == 2 && rec->type[0] == 'S' && rec->type[1] == 'p') {
            return NDEF_RECORD_TYPE_SMARTPOSTER;
        }
    }

    return NDEF_RECORD_TYPE_UNKNOWN;
}

bool ndef_record_is_text(const ndef_record_t *rec)
{
    return ndef_get_record_type(rec) == NDEF_RECORD_TYPE_TEXT;
}

bool ndef_record_is_uri(const ndef_record_t *rec)
{
    return ndef_get_record_type(rec) == NDEF_RECORD_TYPE_URI;
}

bool ndef_record_is_smartposter(const ndef_record_t *rec)
{
    return ndef_get_record_type(rec) == NDEF_RECORD_TYPE_SMARTPOSTER;
}

bool ndef_make_mime_record(ndef_record_t *rec, const char *mime_type, const uint8_t *data, size_t data_len, uint8_t *type_buf, size_t type_buf_len)
{
    if (!rec || !mime_type || !type_buf) return false;

    size_t type_len = strlen(mime_type);
    if (type_len == 0 || type_len > 255 || type_len > type_buf_len) return false;

    memcpy(type_buf, mime_type, type_len);

    rec->tnf         = NDEF_TNF_MEDIA_TYPE;
    rec->type        = type_buf;
    rec->type_len    = (uint8_t)type_len;
    rec->id          = NULL;
    rec->id_len      = 0;
    rec->payload     = data;
    rec->payload_len = (uint32_t)data_len;
    return true;
}

bool ndef_make_external_record(ndef_record_t *rec, const char *type_name, const uint8_t *data, size_t data_len, uint8_t *type_buf, size_t type_buf_len)
{
    if (!rec || !type_name || !type_buf) return false;

    size_t type_len = strlen(type_name);
    if (type_len == 0 || type_len > 255 || type_len > type_buf_len) return false;

    memcpy(type_buf, type_name, type_len);

    rec->tnf         = NDEF_TNF_EXTERNAL;
    rec->type        = type_buf;
    rec->type_len    = (uint8_t)type_len;
    rec->id          = NULL;
    rec->id_len      = 0;
    rec->payload     = data;
    rec->payload_len = (uint32_t)data_len;
    return true;
}

size_t ndef_decode_smartposter(const ndef_record_t *rec, ndef_record_t *records, size_t capacity)
{
    if (!ndef_record_is_smartposter(rec)) return 0;
    if (!rec->payload || rec->payload_len == 0) return 0;

    return ndef_decode_message(rec->payload, rec->payload_len, records, capacity);
}

const char *ndef_result_to_string(ndef_result_t result)
{
    switch (result) {
    case NDEF_OK:
        return "Success";
    case NDEF_ERR_INVALID_PARAM:
        return "Invalid parameter";
    case NDEF_ERR_NO_MEMORY:
        return "Memory allocation failed";
    case NDEF_ERR_READ_FAILED:
        return "Card read failed";
    case NDEF_ERR_WRITE_FAILED:
        return "Card write failed";
    case NDEF_ERR_NO_NDEF:
        return "No NDEF data found";
    case NDEF_ERR_PARSE_FAILED:
        return "NDEF parse failed";
    case NDEF_ERR_BUFFER_TOO_SMALL:
        return "Buffer too small";
    case NDEF_ERR_CARD_FULL:
        return "Card capacity exceeded";
    default:
        return "Unknown error";
    }
}
