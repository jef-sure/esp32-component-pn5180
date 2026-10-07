/**
 * @file pn5180-ndef-auto.c
 * @brief NDEF reading by tag type: Type 2, MIFARE Classic, Type 4 and Type 5 mappings
 *
 * Everything except Type 4 goes through the pn5180_proto_t callbacks, so the same code serves
 * ISO14443A and ISO15693 cards. Type 4 uses the ISO14443-4 helpers of pn5180-14443.h.
 */

#include "esp_log.h"
#include "pn5180-14443.h"
#include "pn5180-internal.h"
#include "pn5180-ndef-tlv.h"
#include "pn5180-ndef.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG __attribute__((unused)) = "pn5180-ndef";

#define TLV_NDEF       0x03
#define TLV_TERMINATOR 0xFE

/* ---- Byte stream collected from the card, searched for the NDEF TLV ---- */

typedef struct
{
    uint8_t *data;
    size_t   len;
    size_t   capacity;
} ndef_stream_t;

static bool stream_reserve(ndef_stream_t *stream, size_t extra)
{
    if (extra <= stream->capacity - stream->len) {
        return true;
    }
    size_t new_cap = (stream->capacity == 0) ? 256 : stream->capacity;
    while (new_cap - stream->len < extra) {
        if (new_cap > SIZE_MAX / 2) {
            return false;
        }
        new_cap *= 2;
    }
    uint8_t *new_data = realloc(stream->data, new_cap);
    if (new_data == NULL) {
        return false;
    }
    stream->data     = new_data;
    stream->capacity = new_cap;
    return true;
}

static bool stream_append(ndef_stream_t *stream, const uint8_t *bytes, size_t count)
{
    if (!stream_reserve(stream, count)) {
        return false;
    }
    memcpy(stream->data + stream->len, bytes, count);
    stream->len += count;
    return true;
}

typedef enum
{
    TLV_SCAN_MORE,  /**< Nothing conclusive yet: read more data */
    TLV_SCAN_FOUND, /**< A complete NDEF TLV is in the stream */
    TLV_SCAN_END    /**< Terminator TLV reached: there is no NDEF message */
} tlv_scan_t;

static tlv_scan_t stream_scan(const ndef_stream_t *stream, size_t *tlv_pos, size_t *ndef_offset, size_t *ndef_len)
{
    if (pn5180_ndef_tlv_find_ndef(stream->data, stream->len, tlv_pos, ndef_offset, ndef_len)) {
        return (*ndef_len <= stream->len - *ndef_offset) ? TLV_SCAN_FOUND : TLV_SCAN_MORE;
    }
    if (*tlv_pos < stream->len && stream->data[*tlv_pos] == TLV_TERMINATOR) {
        return TLV_SCAN_END;
    }
    return TLV_SCAN_MORE;
}

// Parses the NDEF TLV value and releases the stream.
static pn5180_ndef_result_t stream_finish(ndef_stream_t *stream, bool found, bool read_ok, bool no_memory, size_t ndef_offset, size_t ndef_len,
                                          pn5180_ndef_message_parsed_t **out_msg)
{
    pn5180_ndef_result_t result;
    if (no_memory) {
        result = PN5180_NDEF_ERR_NO_MEMORY;
    } else if (!found || ndef_len == 0) {
        result = read_ok ? PN5180_NDEF_ERR_NO_NDEF : PN5180_NDEF_ERR_READ_FAILED;
    } else {
        result = pn5180_ndef_parse_message(stream->data + ndef_offset, ndef_len, out_msg);
    }
    free(stream->data);
    stream->data = NULL;
    return result;
}

// Puts the card back into the selected state. Several card families drop out of it after an error:
// Ultralight and NTAG reset to IDLE after any NAK, MIFARE Classic after a failed authentication.
static bool ndef_reselect(pn5180_proto_t *proto, pn5180_uid_t *uid)
{
    if (proto->halt != NULL) {
        proto->halt(proto);
    }
    return proto->select_by_uid != NULL && proto->select_by_uid(proto, uid);
}

/* ---- Type 2 and Type 5: TLVs in a data area that the capability container describes ---- */

/*
 * Checks and procedures follow the NXP reader library (phalTop, T2T and T5T: CheckNdef, ReadNdef,
 * WriteNdef):
 *   - the capability container must show a supported version and known access conditions;
 *   - the NDEF TLV is found by walking the TLVs of the data area;
 *   - writing puts the message into the NDEF TLV the tag already has, so TLVs in front of it
 *     (lock control, memory control, proprietary) and the bytes sharing its first block are kept;
 *     the TLV length is set to 0 first, then the message is written, then the real length; a
 *     Terminator TLV follows the message if the data area has room for it.
 */

#define NDEF_AREA_MAX_RESERVED 4

typedef struct
{
    size_t stream_base; /**< tag address of the first stream byte, on a block boundary */
    size_t area_start;  /**< tag address of the first TLV byte */
    size_t area_end;    /**< tag address after the data area */
    size_t block_size;
    bool   type2; /**< READ answers 16 bytes; control TLVs reserve bytes of the tag */
    struct
    {
        size_t addr;
        size_t size;
    } reserved[NDEF_AREA_MAX_RESERVED]; /**< lock and reserved bytes named by control TLVs */
    size_t reserved_count;
} ndef_area_t;

// Appends the next block (Type 2: the next four pages) of the data area to the stream.
// PN5180_NDEF_ERR_NO_NDEF means that the data area ended.
static pn5180_ndef_result_t area_read_more(pn5180_proto_t *proto, const ndef_area_t *ctx, ndef_stream_t *stream)
{
    size_t addr = ctx->stream_base + stream->len;
    if (addr >= ctx->area_end) {
        return PN5180_NDEF_ERR_NO_NDEF;
    }
    uint8_t data[32];
    size_t  got = ctx->type2 ? 16u : ctx->block_size;
    if (!proto->block_read(proto, (int)(addr / ctx->block_size), data, got)) {
        return PN5180_NDEF_ERR_READ_FAILED;
    }
    if (got > ctx->area_end - addr) {
        got = ctx->area_end - addr;
    }
    return stream_append(stream, data, got) ? PN5180_NDEF_OK : PN5180_NDEF_ERR_NO_MEMORY;
}

static pn5180_ndef_result_t area_need(pn5180_proto_t *proto, const ndef_area_t *ctx, ndef_stream_t *stream, size_t len)
{
    while (stream->len < len) {
        pn5180_ndef_result_t result = area_read_more(proto, ctx, stream);
        if (result != PN5180_NDEF_OK) {
            return result;
        }
    }
    return PN5180_NDEF_OK;
}

// Walks the TLVs of the data area up to the NDEF TLV and returns the tag address of its T byte,
// as phalTop_Sw_Int_T2T_DetectTlvBlocks() / ..._T5T_DetectTlvBlocks() of the NXP reader library do.
// A data area without NDEF TLV is PN5180_NDEF_ERR_NO_NDEF: the tag is not set up for NDEF.
static pn5180_ndef_result_t area_find_ndef_tlv(pn5180_proto_t *proto, ndef_area_t *ctx, ndef_stream_t *stream, size_t *header_addr)
{
    size_t pos        = ctx->area_start - ctx->stream_base;
    int    null_count = 0;
    for (;;) {
        pn5180_ndef_result_t result = area_need(proto, ctx, stream, pos + 1);
        if (result != PN5180_NDEF_OK) {
            return result;
        }
        uint8_t type = stream->data[pos];
        // NULL TLV: a single byte, known to Type 2 only (on Type 5, 00h is a reserved TLV with a
        // length like any other). A Type 2 tag must not carry more than three of them in a row.
        if (ctx->type2 && type == 0x00) {
            if (++null_count > 3) {
                return PN5180_NDEF_ERR_NO_NDEF;
            }
            pos++;
            continue;
        }
        null_count = 0;
        if (type == TLV_TERMINATOR) {
            return PN5180_NDEF_ERR_NO_NDEF;
        }
        if (type == TLV_NDEF) {
            *header_addr = ctx->stream_base + pos;
            return PN5180_NDEF_OK;
        }

        // Any other TLV is skipped by its length.
        if ((result = area_need(proto, ctx, stream, pos + 2)) != PN5180_NDEF_OK) {
            return result;
        }
        size_t length      = stream->data[pos + 1];
        size_t length_size = 1;
        if (length == 0xFF) {
            if ((result = area_need(proto, ctx, stream, pos + 4)) != PN5180_NDEF_OK) {
                return result;
            }
            length      = ((size_t)stream->data[pos + 2] << 8) | stream->data[pos + 3];
            length_size = 3;
        }
        // Lock Control (01h) and Memory Control (02h) TLV of a Type 2 tag: position byte (page
        // address, byte offset), size (bits for lock bytes, bytes for reserved ones), page control
        // (low nibble: bytes per page as a power of two).
        if (ctx->type2 && (type == 0x01 || type == 0x02) && length == 3) {
            if ((result = area_need(proto, ctx, stream, pos + 1 + length_size + 3)) != PN5180_NDEF_OK) {
                return result;
            }
            if (ctx->reserved_count >= NDEF_AREA_MAX_RESERVED) {
                return PN5180_NDEF_ERR_UNSUPPORTED;
            }
            const uint8_t *value                    = &stream->data[pos + 1 + length_size];
            size_t         bytes_per_page           = (size_t)1 << (value[2] & 0x0F);
            ctx->reserved[ctx->reserved_count].addr = (size_t)(value[0] >> 4) * bytes_per_page + (value[0] & 0x0F);
            ctx->reserved[ctx->reserved_count].size = (type == 0x01) ? ((size_t)value[1] + 7u) / 8u : value[1];
            ctx->reserved_count++;
        }
        pos += 1 + length_size + length;
    }
}

// True if a Lock Control or Memory Control TLV puts lock or reserved bytes into [from, to).
static bool area_has_reserved_bytes(const ndef_area_t *ctx, size_t from, size_t to)
{
    for (size_t i = 0; i < ctx->reserved_count; i++) {
        if (ctx->reserved[i].size > 0 && ctx->reserved[i].addr < to && ctx->reserved[i].addr + ctx->reserved[i].size > from) {
            PN5180_LOGD(TAG, "NDEF: lock or reserved bytes at %u inside the data area", (unsigned)ctx->reserved[i].addr);
            return true;
        }
    }
    return false;
}

// Reads the message out of the NDEF TLV of the data area. Takes over the stream.
static pn5180_ndef_result_t ndef_read_from_area(pn5180_proto_t *proto, ndef_area_t *ctx, ndef_stream_t *seeded, pn5180_ndef_message_parsed_t **out_msg)
{
    ndef_stream_t        stream      = *seeded;
    size_t               header_addr = 0;
    pn5180_ndef_result_t result      = area_find_ndef_tlv(proto, ctx, &stream, &header_addr);
    if (result != PN5180_NDEF_OK) {
        goto done;
    }

    size_t pos = header_addr - ctx->stream_base;
    if ((result = area_need(proto, ctx, &stream, pos + 2)) != PN5180_NDEF_OK) {
        goto done;
    }
    size_t length      = stream.data[pos + 1];
    size_t length_size = 1;
    if (length == 0xFF) {
        if ((result = area_need(proto, ctx, &stream, pos + 4)) != PN5180_NDEF_OK) {
            goto done;
        }
        length      = ((size_t)stream.data[pos + 2] << 8) | stream.data[pos + 3];
        length_size = 3;
    }
    if (length == 0) {
        // Formatted tag without a message
        result = PN5180_NDEF_ERR_NO_NDEF;
        goto done;
    }
    size_t value_addr = header_addr + 1 + length_size;
    if (value_addr > ctx->area_end || length > ctx->area_end - value_addr) {
        // The message does not fit the data area the capability container describes.
        result = PN5180_NDEF_ERR_PARSE_FAILED;
        goto done;
    }
    // The NXP library leaves lock and reserved bytes out of the message; this driver does not
    // read around them.
    if (area_has_reserved_bytes(ctx, value_addr, value_addr + length)) {
        result = PN5180_NDEF_ERR_UNSUPPORTED;
        goto done;
    }
    if ((result = area_need(proto, ctx, &stream, pos + 1 + length_size + length)) != PN5180_NDEF_OK) {
        goto done;
    }
    result = pn5180_ndef_parse_message(stream.data + pos + 1 + length_size, length, out_msg);

done:
    free(stream.data);
    return result;
}

// Writes the message into the NDEF TLV of the data area. Takes over the stream.
static pn5180_ndef_result_t ndef_write_into_area(pn5180_proto_t *proto, ndef_area_t *ctx, ndef_stream_t *seeded, const pn5180_ndef_message_t *msg)
{
    ndef_stream_t stream = *seeded;
    size_t        ndef_len = pn5180_ndef_encode_message(msg, NULL, 0);
    if (ndef_len == 0) {
        free(stream.data);
        return PN5180_NDEF_ERR_INVALID_PARAM;
    }
    if (ndef_len > 0xFFFE) {
        // The three-byte TLV length format ends at FFFEh.
        free(stream.data);
        return PN5180_NDEF_ERR_CARD_FULL;
    }

    size_t               header_addr = 0;
    uint8_t             *image       = NULL;
    pn5180_ndef_result_t result      = area_find_ndef_tlv(proto, ctx, &stream, &header_addr);
    if (result != PN5180_NDEF_OK) {
        goto done;
    }

    // T, L (one byte, or FFh and two bytes from 255 on) and the message have to fit between the
    // NDEF TLV and the end of the data area.
    size_t block_size  = ctx->block_size;
    size_t length_size = (ndef_len < 0xFF) ? 1 : 3;
    size_t tlv_len     = 1 + length_size + ndef_len;
    size_t room        = ctx->area_end - header_addr;
    if (tlv_len > room) {
        result = PN5180_NDEF_ERR_CARD_FULL;
        goto done;
    }
    // Lock or reserved bytes inside the part of the data area that would be written: the message
    // would have to go around them, which this driver does not do.
    if (area_has_reserved_bytes(ctx, header_addr, ctx->area_end)) {
        result = PN5180_NDEF_ERR_UNSUPPORTED;
        goto done;
    }
    bool terminator = tlv_len < room;

    // Image of the blocks to write, starting with the block of the NDEF TLV.
    size_t image_addr = header_addr - header_addr % block_size;
    size_t prefix     = header_addr - image_addr;
    size_t used       = prefix + tlv_len + (terminator ? 1u : 0u);
    size_t blocks     = (used + block_size - 1) / block_size;
    image             = calloc(blocks + 1, block_size); // one spare block for the zero-length step
    if (image == NULL) {
        result = PN5180_NDEF_ERR_NO_MEMORY;
        goto done;
    }
    size_t last_addr = image_addr + (blocks - 1) * block_size;
    if (last_addr + block_size > ctx->area_end) {
        // The last block reaches beyond the data area: those bytes keep their content.
        if (!proto->block_read(proto, (int)(last_addr / block_size), image + (blocks - 1) * block_size, block_size)) {
            result = PN5180_NDEF_ERR_READ_FAILED;
            goto done;
        }
        memset(image + (blocks - 1) * block_size, 0, ctx->area_end - last_addr);
    }
    memcpy(image, stream.data + (image_addr - ctx->stream_base), prefix);
    size_t pos   = prefix;
    image[pos++] = TLV_NDEF;
    if (length_size == 1) {
        image[pos++] = (uint8_t)ndef_len;
    } else {
        image[pos++] = 0xFF;
        image[pos++] = (uint8_t)(ndef_len >> 8);
        image[pos++] = (uint8_t)(ndef_len & 0xFF);
    }
    if (pn5180_ndef_encode_message(msg, image + pos, ndef_len) != ndef_len) {
        result = PN5180_NDEF_ERR_INVALID_PARAM;
        goto done;
    }
    pos += ndef_len;
    if (terminator) {
        image[pos++] = TLV_TERMINATOR;
    }

    // The block with the first length byte decides whether the tag shows a message.
    size_t key_block  = (prefix + 1) / block_size;
    int    first_block = (int)(image_addr / block_size);
    if (blocks > 1) {
        // Length 0 while the other blocks are written: a reader never sees the new length together
        // with old data, also after an interrupted write.
        uint8_t *zeroed = image + blocks * block_size;
        memcpy(zeroed, image + key_block * block_size, block_size);
        zeroed[(prefix + 1) % block_size] = 0x00;
        if (proto->block_write(proto, first_block + (int)key_block, zeroed, block_size) < 0) {
            result = PN5180_NDEF_ERR_WRITE_FAILED;
        }
    }
    for (size_t i = 0; i < blocks && result == PN5180_NDEF_OK; i++) {
        if (i != key_block && proto->block_write(proto, first_block + (int)i, image + i * block_size, block_size) < 0) {
            result = PN5180_NDEF_ERR_WRITE_FAILED;
        }
    }
    if (result == PN5180_NDEF_OK && proto->block_write(proto, first_block + (int)key_block, image + key_block * block_size, block_size) < 0) {
        result = PN5180_NDEF_ERR_WRITE_FAILED;
    }

done:
    free(image);
    free(stream.data);
    return result;
}

/* ---- Type 2: Ultralight, NTAG ---- */

// Reads the capability container and describes the data area. The stream receives the bytes of
// the data area that came along with the capability container.
static pn5180_ndef_result_t type2_open_area(pn5180_proto_t *proto, const pn5180_uid_t *uid, bool for_write, ndef_area_t *ctx, ndef_stream_t *stream)
{
    // READ returns four pages: page 3 is the capability container (magic, version, data area size
    // in units of 8 bytes, access), pages 4..6 the start of the data area.
    uint8_t first[16];
    if (!proto->block_read(proto, 3, first, sizeof(first))) {
        return PN5180_NDEF_ERR_READ_FAILED;
    }
    // No magic number, or a data area below the 48 bytes of the smallest Type 2 tag
    if (first[0] != 0xE1 || first[2] < 6) {
        PN5180_LOGD(TAG, "T2: tag is not NDEF formatted (capability container %02X %02X %02X %02X)", first[0], first[1], first[2], first[3]);
        return PN5180_NDEF_ERR_NO_NDEF;
    }
    if ((first[1] & 0xF0) != 0x10) {
        PN5180_LOGD(TAG, "T2: unsupported mapping version %02X", first[1]);
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }
    // Access byte: 00h read and write, 0Fh read only; other values are proprietary.
    if (first[3] != 0x00 && first[3] != 0x0F) {
        PN5180_LOGD(TAG, "T2: unsupported access conditions %02X", first[3]);
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }
    if (for_write && first[3] == 0x0F) {
        return PN5180_NDEF_ERR_ACCESS_DENIED;
    }

    // The size excludes pages 0..3 and the lock and configuration pages at the end, so it bounds
    // how far reads and writes may go.
    *ctx = (ndef_area_t){.stream_base = 16, .area_start = 16, .area_end = 16u + (size_t)first[2] * 8u, .block_size = 4, .type2 = true};
    if (uid->blocks_count >= 4 + 12 && ctx->area_end > (size_t)uid->blocks_count * 4u) {
        // A capability container must not promise more than the tag has.
        ctx->area_end = (size_t)uid->blocks_count * 4u;
    }
    return stream_append(stream, &first[4], 12) ? PN5180_NDEF_OK : PN5180_NDEF_ERR_NO_MEMORY;
}

static pn5180_ndef_result_t type2_read_ndef(pn5180_proto_t *proto, pn5180_uid_t *uid, pn5180_ndef_message_parsed_t **out_msg)
{
    ndef_area_t          ctx;
    ndef_stream_t        stream = {0};
    pn5180_ndef_result_t result = type2_open_area(proto, uid, false, &ctx, &stream);
    if (result != PN5180_NDEF_OK) {
        free(stream.data);
        return result;
    }
    uid->block_size = 4;
    return ndef_read_from_area(proto, &ctx, &stream, out_msg);
}

static pn5180_ndef_result_t type2_write_ndef(pn5180_proto_t *proto, const pn5180_uid_t *uid, const pn5180_ndef_message_t *msg)
{
    ndef_area_t          ctx;
    ndef_stream_t        stream = {0};
    pn5180_ndef_result_t result = type2_open_area(proto, uid, true, &ctx, &stream);
    if (result != PN5180_NDEF_OK) {
        free(stream.data);
        return result;
    }
    return ndef_write_into_area(proto, &ctx, &stream, msg);
}

/* ---- Type 5: ISO15693 ---- */

/*
 * Type 5 capability container, from block 0:
 *   [0] magic: E1 (blocks addressed with one byte) or E2 (two bytes)
 *   [1] major version in bits 7..6, read access in bits 3..2, write access in bits 1..0
 *   [2] MLEN: size of the data area after the CC in units of 8 bytes; 0 means that an
 *       8-byte CC is used and the size is in bytes 6..7
 *   [3] feature flags
 * TLVs follow directly after the capability container.
 */
static pn5180_ndef_result_t type5_open_area(pn5180_proto_t *proto, const pn5180_uid_t *uid, bool for_write, ndef_area_t *ctx, ndef_stream_t *stream)
{
    size_t block_size = (uid->block_size > 0) ? (size_t)uid->block_size : 4u;
    if (block_size > 32u) {
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }

    uint8_t cc[8 + 32] = {0};
    size_t  cc_have    = 0;
    do {
        if (!proto->block_read(proto, (int)(cc_have / block_size), cc + cc_have, block_size)) {
            return PN5180_NDEF_ERR_READ_FAILED;
        }
        cc_have += block_size;
    } while (cc_have < 4 || (cc[2] == 0 && cc_have < 8));

    if (cc[0] != 0xE1 && cc[0] != 0xE2) {
        PN5180_LOGD(TAG, "T5: tag is not NDEF formatted (block 0 starts with %02X)", cc[0]);
        return PN5180_NDEF_ERR_NO_NDEF;
    }
    if ((cc[1] >> 6) > 1) {
        PN5180_LOGD(TAG, "T5: unsupported mapping version %02X", cc[1]);
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }
    // Access nibble: 0h read and write, 3h read only; other values are reserved or proprietary.
    uint8_t access = cc[1] & 0x0F;
    if (access != 0x00 && access != 0x03) {
        PN5180_LOGD(TAG, "T5: unsupported access conditions %02X", cc[1]);
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }
    if (for_write && access == 0x03) {
        return PN5180_NDEF_ERR_ACCESS_DENIED;
    }
    size_t cc_len = 4;
    size_t mlen   = cc[2];
    if (mlen == 0) {
        cc_len = 8;
        mlen   = ((size_t)cc[6] << 8) | cc[7];
    }

    *ctx = (ndef_area_t){.stream_base = 0, .area_start = cc_len, .area_end = cc_len + mlen * 8u, .block_size = block_size, .type2 = false};
    if (uid->blocks_count > 0 && ctx->area_end > (size_t)uid->blocks_count * block_size) {
        // A capability container must not promise more than the tag has.
        ctx->area_end = (size_t)uid->blocks_count * block_size;
    }
    if (ctx->area_end <= ctx->area_start) {
        return PN5180_NDEF_ERR_NO_NDEF;
    }
    if (cc_have > ctx->area_end) {
        cc_have = ctx->area_end;
    }
    return stream_append(stream, cc, cc_have) ? PN5180_NDEF_OK : PN5180_NDEF_ERR_NO_MEMORY;
}

static pn5180_ndef_result_t type5_read_ndef(pn5180_proto_t *proto, pn5180_uid_t *uid, pn5180_ndef_message_parsed_t **out_msg)
{
    ndef_area_t          ctx;
    ndef_stream_t        stream = {0};
    pn5180_ndef_result_t result = type5_open_area(proto, uid, false, &ctx, &stream);
    if (result != PN5180_NDEF_OK) {
        free(stream.data);
        return result;
    }
    return ndef_read_from_area(proto, &ctx, &stream, out_msg);
}

static pn5180_ndef_result_t type5_write_ndef(pn5180_proto_t *proto, const pn5180_uid_t *uid, const pn5180_ndef_message_t *msg)
{
    ndef_area_t          ctx;
    ndef_stream_t        stream = {0};
    pn5180_ndef_result_t result = type5_open_area(proto, uid, true, &ctx, &stream);
    if (result != PN5180_NDEF_OK) {
        free(stream.data);
        return result;
    }
    return ndef_write_into_area(proto, &ctx, &stream, msg);
}

/* ---- MIFARE Classic: NDEF sectors listed in the MIFARE Application Directory ---- */

#define CLASSIC_MAD1_FIRST_DATA_BLOCK  1
#define CLASSIC_MAD1_SECOND_DATA_BLOCK 2
#define CLASSIC_MAD1_TRAILER_BLOCK     3
#define CLASSIC_MAD1_ENTRY_COUNT       15
#define CLASSIC_MAD2_FIRST_DATA_BLOCK  64
#define CLASSIC_MAD2_TRAILER_BLOCK     67
#define CLASSIC_MAD2_ENTRY_COUNT       23
#define CLASSIC_MAX_NDEF_SECTORS       (CLASSIC_MAD1_ENTRY_COUNT + CLASSIC_MAD2_ENTRY_COUNT)

static const uint8_t classic_key_mad[6]     = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
static const uint8_t classic_key_ndef[6]    = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};
static const uint8_t classic_key_default[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Authenticates the sector of blockno with key A, trying a second key if the first is refused.
static bool classic_auth(pn5180_proto_t *proto, pn5180_uid_t *uid, int blockno, const uint8_t *primary_key, const uint8_t *secondary_key)
{
    if (proto->authenticate(proto, primary_key, PN5180_MIFARE_CLASSIC_KEYA, uid, blockno)) {
        return true;
    }
    if (secondary_key == NULL) {
        return false;
    }
    // A refused authentication leaves the card unselected.
    if (!ndef_reselect(proto, uid)) {
        PN5180_LOGD(TAG, "Classic: reselect failed at block %d", blockno);
        return false;
    }
    return proto->authenticate(proto, secondary_key, PN5180_MIFARE_CLASSIC_KEYA, uid, blockno);
}

// CRC of a MIFARE Application Directory: CRC-8 with polynomial x^8 + x^4 + x^3 + x^2 + 1 (1Dh) and
// preset C7h, over the info byte and the application identifiers. Byte 0 of the MAD holds the CRC.
static uint8_t classic_mad_crc(const uint8_t *data, size_t len)
{
    uint8_t crc = 0xC7;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x1D) : (uint8_t)(crc << 1);
        }
    }
    return crc;
}

static bool classic_mad_crc_ok(const uint8_t *mad, size_t mad_len)
{
    return classic_mad_crc(&mad[1], mad_len - 1) == mad[0];
}

static bool classic_mad_entry_is_ndef(const uint8_t *mad, size_t mad_len, int entry, int entry_count)
{
    if (entry < 0 || entry >= entry_count || mad_len < 2u + (size_t)entry_count * 2u) {
        return false;
    }
    // The first two bytes are CRC and info byte; application identifiers follow, two bytes per sector.
    size_t  offset = 2u + (size_t)entry * 2u;
    uint8_t aid0   = mad[offset];
    uint8_t aid1   = mad[offset + 1u];
    // NFC Forum AID: application code 03h, then function cluster code E1h.
    return aid0 == 0x03 && aid1 == 0xE1;
}

// Sector 16 holds MAD2, so the application sector after 15 is 17.
static int classic_next_application_sector(int sector)
{
    return (sector == 15) ? 17 : (sector + 1);
}

// Appends the NDEF sectors of one MAD to the list. NDEF sectors must be contiguous.
static bool classic_collect_ndef_sectors(const uint8_t *mad, size_t mad_len, int first_sector, int entry_count, int *sectors, size_t sectors_capacity,
                                         size_t *sector_count)
{
    size_t count           = *sector_count;
    int    previous_sector = (count > 0) ? sectors[count - 1] : -1;

    for (int entry = 0; entry < entry_count; entry++) {
        if (!classic_mad_entry_is_ndef(mad, mad_len, entry, entry_count)) {
            continue;
        }

        int sector = first_sector + entry;
        if (previous_sector >= 0 && sector != classic_next_application_sector(previous_sector)) {
            return false;
        }
        if (count >= sectors_capacity) {
            return false;
        }

        sectors[count++] = sector;
        previous_sector  = sector;
    }

    *sector_count = count;
    return true;
}

static int classic_sector_first_block(int sector)
{
    if (sector < 0) {
        return -1;
    }
    if (sector < 32) {
        return sector * 4;
    }
    if (sector < 40) {
        return 128 + (sector - 32) * 16;
    }
    return -1;
}

static int classic_sector_block_count(int sector)
{
    if (sector < 0) {
        return 0;
    }
    if (sector < 32) {
        return 4;
    }
    if (sector < 40) {
        return 16;
    }
    return 0;
}

// General purpose byte of the MAD sector trailer: bit 7 says that a MAD is present, bits 1..0 give its version.
static int classic_mad_version_from_gpb(uint8_t gpb)
{
    if ((gpb & 0x80u) == 0) {
        return 0;
    }
    switch (gpb & 0x03u) {
    case 0x01:
        return 1;
    case 0x02:
        return 2;
    default:
        return 0;
    }
}

static pn5180_ndef_result_t classic_read_sectors(pn5180_proto_t *proto, pn5180_uid_t *uid, const int *sectors, size_t sector_count,
                                                 pn5180_ndef_message_parsed_t **out_msg)
{
    ndef_stream_t stream      = {0};
    size_t        tlv_pos     = 0;
    size_t        ndef_offset = 0;
    size_t        ndef_len    = 0;
    bool          read_ok     = true;
    bool          no_memory   = false;
    tlv_scan_t    scan        = TLV_SCAN_MORE;

    for (size_t i = 0; i < sector_count && scan == TLV_SCAN_MORE && read_ok && !no_memory; i++) {
        int first_block = classic_sector_first_block(sectors[i]);
        int block_count = classic_sector_block_count(sectors[i]);

        if (first_block < 0 || block_count <= 1) {
            read_ok = false;
            break;
        }
        if (!classic_auth(proto, uid, first_block, classic_key_ndef, classic_key_default)) {
            PN5180_LOGD(TAG, "Classic: authentication failed for sector %d", sectors[i]);
            read_ok = false;
            break;
        }
        if (i == 0) {
            // General purpose byte of the NDEF sector trailer: mapping version in bits 7..4 (major
            // in 7..6), read access in bits 3..2, write access in bits 1..0; 00b grants access.
            uint8_t trailer[16];
            if (!proto->block_read(proto, first_block + block_count - 1, trailer, sizeof(trailer))) {
                read_ok = false;
                break;
            }
            if ((trailer[9] >> 6) > 1) {
                PN5180_LOGD(TAG, "Classic: unsupported mapping version (general purpose byte %02X)", trailer[9]);
                free(stream.data);
                return PN5180_NDEF_ERR_UNSUPPORTED;
            }
            if ((trailer[9] & 0x0C) != 0) {
                PN5180_LOGD(TAG, "Classic: NDEF sectors are read protected (general purpose byte %02X)", trailer[9]);
                free(stream.data);
                return PN5180_NDEF_ERR_ACCESS_DENIED;
            }
        }

        // The last block of a sector is its trailer and carries no data.
        for (int block = first_block; block < first_block + block_count - 1; block++) {
            uint8_t data[16];
            if (!proto->block_read(proto, block, data, sizeof(data))) {
                read_ok = false;
                break;
            }
            if (!stream_append(&stream, data, sizeof(data))) {
                no_memory = true;
                break;
            }
            scan = stream_scan(&stream, &tlv_pos, &ndef_offset, &ndef_len);
            if (scan != TLV_SCAN_MORE) {
                break;
            }
        }
    }

    return stream_finish(&stream, scan == TLV_SCAN_FOUND, read_ok, no_memory, ndef_offset, ndef_len, out_msg);
}

static pn5180_ndef_result_t classic_read_ndef(pn5180_proto_t *proto, pn5180_uid_t *uid, pn5180_ndef_message_parsed_t **out_msg)
{
    uint8_t mad1[32];
    uint8_t trailer[16];
    int     sectors[CLASSIC_MAX_NDEF_SECTORS];
    size_t  sector_count = 0;

    if (proto->authenticate == NULL) {
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }

    // Sector 0 holds MAD1. A card without readable MAD is not NDEF formatted.
    if (!classic_auth(proto, uid, CLASSIC_MAD1_FIRST_DATA_BLOCK, classic_key_mad, classic_key_default)) {
        return PN5180_NDEF_ERR_NO_NDEF;
    }
    int mad_version = 1;
    if (proto->block_read(proto, CLASSIC_MAD1_TRAILER_BLOCK, trailer, sizeof(trailer))) {
        mad_version = classic_mad_version_from_gpb(trailer[9]);
        if (mad_version == 0) {
            return PN5180_NDEF_ERR_NO_NDEF;
        }
    } else {
        PN5180_LOGD(TAG, "Classic: MAD1 trailer unreadable, assuming MAD version 1");
    }
    if (!proto->block_read(proto, CLASSIC_MAD1_FIRST_DATA_BLOCK, mad1, 16) || !proto->block_read(proto, CLASSIC_MAD1_SECOND_DATA_BLOCK, mad1 + 16, 16)) {
        return PN5180_NDEF_ERR_NO_NDEF;
    }

    if (!classic_mad_crc_ok(mad1, sizeof(mad1))) {
        PN5180_LOGD(TAG, "Classic: MAD1 CRC mismatch");
        return PN5180_NDEF_ERR_NO_NDEF;
    }

    // MIFARE Mini has sectors 1..4, 1K and 4K sectors 1..15 in MAD1.
    int mad1_entries = (uid->subtype == PN5180_MIFARE_CLASSIC_MINI) ? 4 : CLASSIC_MAD1_ENTRY_COUNT;
    if (!classic_collect_ndef_sectors(mad1, sizeof(mad1), 1, mad1_entries, sectors, CLASSIC_MAX_NDEF_SECTORS, &sector_count)) {
        return PN5180_NDEF_ERR_NO_NDEF;
    }

    if (uid->subtype == PN5180_MIFARE_CLASSIC_4K && mad_version == 2) {
        // Sector 16 holds MAD2 for sectors 17..39.
        uint8_t mad2[48];
        if (!classic_auth(proto, uid, CLASSIC_MAD2_TRAILER_BLOCK, classic_key_mad, classic_key_default)) {
            return PN5180_NDEF_ERR_NO_NDEF;
        }
        for (int i = 0; i < 3; i++) {
            if (!proto->block_read(proto, CLASSIC_MAD2_FIRST_DATA_BLOCK + i, mad2 + (size_t)i * 16u, 16)) {
                return PN5180_NDEF_ERR_NO_NDEF;
            }
        }
        if (!classic_mad_crc_ok(mad2, sizeof(mad2))) {
            PN5180_LOGD(TAG, "Classic: MAD2 CRC mismatch");
            return PN5180_NDEF_ERR_NO_NDEF;
        }
        if (!classic_collect_ndef_sectors(mad2, sizeof(mad2), 17, CLASSIC_MAD2_ENTRY_COUNT, sectors, CLASSIC_MAX_NDEF_SECTORS, &sector_count)) {
            return PN5180_NDEF_ERR_NO_NDEF;
        }
    }

    if (sector_count == 0) {
        return PN5180_NDEF_ERR_NO_NDEF;
    }
    return classic_read_sectors(proto, uid, sectors, sector_count, out_msg);
}

/* ---- Type 4: ISO14443-4 cards ---- */

/*
 * Type 4 Tag NDEF mapping:
 *   1. SELECT the NDEF Tag Application by AID D2 76 00 00 85 01 01.
 *   2. SELECT the Capability Container file (E103) and read its 15 bytes:
 *        [0..1]   CCLEN
 *        [2]      Mapping version
 *        [3..4]   MLe (largest response data size)
 *        [5..6]   MLc (largest command data size)
 *        [7]      NDEF File Control TLV tag = 0x04
 *        [8]      NDEF File Control TLV length = 0x06
 *        [9..10]  NDEF file identifier
 *        [11..12] NDEF file size limit
 *        [13]     Read access
 *        [14]     Write access
 *   3. SELECT the NDEF file, read NLEN (2 bytes at offset 0), then NLEN bytes from offset 2.
 */
// A card that refuses a SELECT is alive but carries no NDEF application or file. A SELECT that got
// no usable answer closed the ISO14443-4 session instead, and the read is worth repeating.
static pn5180_ndef_result_t type4_select_failure_result(const pn5180_t *pn5180)
{
    return pn5180->iso14443_layer4_active ? PN5180_NDEF_ERR_NO_NDEF : PN5180_NDEF_ERR_READ_FAILED;
}

static pn5180_ndef_result_t type4_read_ndef(pn5180_proto_t *proto, pn5180_ndef_message_parsed_t **out_msg)
{
    static const uint8_t ndef_aid[]   = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    static const uint8_t cc_file_id[] = {0xE1, 0x03};
    pn5180_t            *pn5180       = proto->pn5180;

    if (!pn5180->iso14443_layer4_active) {
        PN5180_LOGD(TAG, "T4: ISO14443-4 is not active");
        return PN5180_NDEF_ERR_READ_FAILED;
    }
    if (!pn5180_14443_4_select_file(pn5180, ndef_aid, sizeof(ndef_aid))) {
        PN5180_LOGD(TAG, "T4: SELECT NDEF application failed");
        return type4_select_failure_result(pn5180);
    }
    if (!pn5180_14443_4_select_file(pn5180, cc_file_id, sizeof(cc_file_id))) {
        PN5180_LOGD(TAG, "T4: SELECT capability container failed");
        return type4_select_failure_result(pn5180);
    }

    uint8_t cc[15];
    size_t  cc_got = sizeof(cc);
    if (!pn5180_14443_4_read_binary(pn5180, 0, sizeof(cc), cc, &cc_got) || cc_got < sizeof(cc)) {
        PN5180_LOGD(TAG, "T4: READ capability container failed (%u bytes)", (unsigned)cc_got);
        return PN5180_NDEF_ERR_READ_FAILED;
    }

    uint16_t cc_len        = (uint16_t)(((uint16_t)cc[0] << 8) | cc[1]);
    uint16_t mle           = (uint16_t)(((uint16_t)cc[3] << 8) | cc[4]);
    uint8_t  ndef_fid[2]   = {cc[9], cc[10]};
    uint16_t max_ndef_size = (uint16_t)(((uint16_t)cc[11] << 8) | cc[12]);
    // Mapping versions 1.x to 3.x describe the NDEF file with the NDEF File Control TLV (04h) read
    // here; a higher major version may not.
    uint8_t mapping_major = (uint8_t)(cc[2] >> 4);
    if (mapping_major < 1 || mapping_major > 3) {
        PN5180_LOGD(TAG, "T4: unsupported mapping version %02X", cc[2]);
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }
    // A mapping 3.x tag may carry the Extended NDEF File Control TLV (06h) instead: 4-byte file
    // size and NDEF length, for files above 32 KB.
    if (cc[7] == 0x06) {
        PN5180_LOGD(TAG, "T4: extended NDEF file is not supported");
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }
    // The capability container is at least 15 bytes long, MLe at least 15, the NDEF file between
    // 5 and 7FFFh bytes, and it cannot have the identifier of another file or a reserved one.
    uint16_t ndef_fid_value = (uint16_t)(((uint16_t)ndef_fid[0] << 8) | ndef_fid[1]);
    bool     fid_reserved   = ndef_fid_value == 0x0000 || ndef_fid_value == 0xE102 || ndef_fid_value == 0xE103 || ndef_fid_value == 0x3F00 ||
                              ndef_fid_value == 0x3FFF || ndef_fid_value == 0xFFFF;
    if (cc[7] != 0x04 || cc[8] != 0x06 || cc_len < 15 || cc_len > 0x7FFF || mle < 15 || max_ndef_size < 5 || max_ndef_size > 0x7FFF || fid_reserved) {
        PN5180_LOGD(TAG, "T4: bad capability container (CCLEN=%u MLe=%u T=%02X L=%02X file %04X size %u)", cc_len, mle, cc[7], cc[8], ndef_fid_value,
                    max_ndef_size);
        return PN5180_NDEF_ERR_PARSE_FAILED;
    }
    // Read access 00h means free access; anything else needs a security setup this driver does not do.
    if (cc[13] != 0x00) {
        PN5180_LOGD(TAG, "T4: NDEF file is read protected (access byte %02X)", cc[13]);
        return PN5180_NDEF_ERR_ACCESS_DENIED;
    }
    // Chunk size: MLe counts data bytes only, so Le = MLe is legal; two bytes of headroom are kept for
    // cards that size MLe to their whole response buffer. Le is one byte and READ BINARY uses a
    // 260-byte buffer, so 248 data bytes is the ceiling.
    uint16_t chunk_max = (mle > 250) ? 248u : (uint16_t)(mle - 2u);

    if (!pn5180_14443_4_select_file(pn5180, ndef_fid, sizeof(ndef_fid))) {
        PN5180_LOGD(TAG, "T4: SELECT NDEF file %02X%02X failed", ndef_fid[0], ndef_fid[1]);
        return type4_select_failure_result(pn5180);
    }

    uint8_t nlen_buf[2];
    size_t  nlen_got = sizeof(nlen_buf);
    if (!pn5180_14443_4_read_binary(pn5180, 0, 2, nlen_buf, &nlen_got) || nlen_got < 2) {
        return PN5180_NDEF_ERR_READ_FAILED;
    }
    uint16_t nlen = (uint16_t)(((uint16_t)nlen_buf[0] << 8) | nlen_buf[1]);
    if (nlen == 0) {
        return PN5180_NDEF_ERR_NO_NDEF;
    }
    if ((uint32_t)nlen + 2u > max_ndef_size) {
        // The length does not fit the file the capability container describes: the tag is inconsistent.
        return PN5180_NDEF_ERR_PARSE_FAILED;
    }

    uint8_t *raw = malloc(nlen);
    if (raw == NULL) {
        return PN5180_NDEF_ERR_NO_MEMORY;
    }
    uint16_t read_off  = 2;
    uint16_t remaining = nlen;
    while (remaining > 0) {
        uint8_t want = (remaining > chunk_max) ? (uint8_t)chunk_max : (uint8_t)remaining;
        size_t  got  = want;
        if (!pn5180_14443_4_read_binary(pn5180, read_off, want, raw + (read_off - 2), &got) || got != want) {
            free(raw);
            return PN5180_NDEF_ERR_READ_FAILED;
        }
        read_off  = (uint16_t)(read_off + want);
        remaining = (uint16_t)(remaining - want);
    }

    pn5180_ndef_result_t parse_result = pn5180_ndef_parse_message(raw, nlen, out_msg);
    free(raw);
    return parse_result;
}

/* ---- Dispatcher ---- */

typedef enum
{
    NDEF_MAPPING_NONE,
    NDEF_MAPPING_TYPE2,
    NDEF_MAPPING_CLASSIC,
    NDEF_MAPPING_TYPE4,
    NDEF_MAPPING_TYPE5
} ndef_mapping_t;

static ndef_mapping_t ndef_mapping_for(pn5180_card_type_t subtype)
{
    switch (subtype) {
    case PN5180_MIFARE_ULTRALIGHT:
    case PN5180_MIFARE_ULTRALIGHT_C:
    case PN5180_MIFARE_ULTRALIGHT_EV1:
    case PN5180_MIFARE_NTAG210:
    case PN5180_MIFARE_NTAG212:
    case PN5180_MIFARE_NTAG213:
    case PN5180_MIFARE_NTAG215:
    case PN5180_MIFARE_NTAG216:
        return NDEF_MAPPING_TYPE2;
    case PN5180_MIFARE_CLASSIC_1K:
    case PN5180_MIFARE_CLASSIC_4K:
    case PN5180_MIFARE_CLASSIC_MINI:
        return NDEF_MAPPING_CLASSIC;
    case PN5180_MIFARE_DESFIRE:
        return NDEF_MAPPING_TYPE4;
    case PN5180_15693:
        return NDEF_MAPPING_TYPE5;
    default:
        return NDEF_MAPPING_NONE;
    }
}

static pn5180_ndef_result_t ndef_read_mapping(ndef_mapping_t mapping, pn5180_proto_t *proto, pn5180_uid_t *uid, pn5180_ndef_message_parsed_t **out_msg)
{
    switch (mapping) {
    case NDEF_MAPPING_TYPE2:
        return type2_read_ndef(proto, uid, out_msg);
    case NDEF_MAPPING_CLASSIC:
        return classic_read_ndef(proto, uid, out_msg);
    case NDEF_MAPPING_TYPE4:
        return type4_read_ndef(proto, out_msg);
    case NDEF_MAPPING_TYPE5:
        return type5_read_ndef(proto, uid, out_msg);
    default:
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }
}

pn5180_ndef_result_t pn5180_ndef_read_card_auto(pn5180_proto_t *proto, pn5180_uid_t *uid, pn5180_ndef_message_parsed_t **out_msg)
{
    if (proto == NULL || proto->block_read == NULL || uid == NULL || out_msg == NULL) {
        return PN5180_NDEF_ERR_INVALID_PARAM;
    }
    *out_msg = NULL;

    ndef_mapping_t mapping = ndef_mapping_for(uid->subtype);
    if (mapping == NDEF_MAPPING_NONE) {
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }

    pn5180_ndef_result_t result = ndef_read_mapping(mapping, proto, uid, out_msg);
    if (result == PN5180_NDEF_ERR_READ_FAILED) {
        // One more attempt from the selected state: the failed command may have reset the card.
        if (!ndef_reselect(proto, uid)) {
            return result;
        }
        result = ndef_read_mapping(mapping, proto, uid, out_msg);
    }
    return result;
}

/* ---- Writing ---- */

pn5180_ndef_result_t pn5180_ndef_write_card_auto(pn5180_proto_t *proto, const pn5180_uid_t *uid, const pn5180_ndef_message_t *msg)
{
    if (proto == NULL || proto->block_read == NULL || proto->block_write == NULL || uid == NULL || msg == NULL) {
        return PN5180_NDEF_ERR_INVALID_PARAM;
    }

    // MIFARE Classic and Type 4 are not written: a Classic message has to go around the sector
    // trailers and through the MAD, a Type 4 message into the NDEF file.
    switch (ndef_mapping_for(uid->subtype)) {
    case NDEF_MAPPING_TYPE2:
        return type2_write_ndef(proto, uid, msg);
    case NDEF_MAPPING_TYPE5:
        return type5_write_ndef(proto, uid, msg);
    default:
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }
}
