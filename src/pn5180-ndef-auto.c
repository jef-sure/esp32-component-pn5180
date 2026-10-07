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

/* ---- Type 2: Ultralight, NTAG ---- */

static pn5180_ndef_result_t type2_read_ndef(pn5180_proto_t *proto, pn5180_uid_t *uid, pn5180_ndef_message_parsed_t **out_msg)
{
    // READ returns four pages: page 3 is the capability container, pages 4..6 the start of the data area.
    uint8_t first[16];
    if (!proto->block_read(proto, 3, first, sizeof(first))) {
        return PN5180_NDEF_ERR_READ_FAILED;
    }
    if (first[0] != 0xE1) {
        PN5180_LOGD(TAG, "T2: no capability container (page 3 starts with %02X)", first[0]);
        return PN5180_NDEF_ERR_NO_NDEF;
    }
    // CC byte 2 is the size of the data area in units of 8 bytes. It excludes pages 0..3 and the
    // lock and configuration pages at the end, so it bounds how far NDEF reads may go.
    size_t data_bytes = (size_t)first[2] * 8u;
    if (data_bytes == 0) {
        return PN5180_NDEF_ERR_NO_NDEF;
    }
    int end_page    = 4 + (int)(data_bytes / 4u); // first page after the data area
    uid->block_size = 4;

    ndef_stream_t stream      = {0};
    size_t        tlv_pos     = 0;
    size_t        ndef_offset = 0;
    size_t        ndef_len    = 0;
    bool          found       = false;
    bool          read_ok     = true;
    bool          no_memory   = false;

    size_t valid = (data_bytes < 12u) ? data_bytes : 12u;
    if (!stream_append(&stream, &first[4], valid)) {
        return PN5180_NDEF_ERR_NO_MEMORY;
    }
    tlv_scan_t scan = stream_scan(&stream, &tlv_pos, &ndef_offset, &ndef_len);

    for (int page = 7; scan == TLV_SCAN_MORE && page < end_page; page += 4) {
        uint8_t chunk[16];
        if (!proto->block_read(proto, page, chunk, sizeof(chunk))) {
            read_ok = false;
            break;
        }
        // Near the end of the memory a READ wraps around to page 0 (or runs into configuration
        // pages), so only the pages inside the data area are taken.
        valid = (size_t)(end_page - page) * 4u;
        if (valid > sizeof(chunk)) {
            valid = sizeof(chunk);
        }
        if (!stream_append(&stream, chunk, valid)) {
            no_memory = true;
            break;
        }
        scan = stream_scan(&stream, &tlv_pos, &ndef_offset, &ndef_len);
    }
    found = (scan == TLV_SCAN_FOUND);

    return stream_finish(&stream, found, read_ok, no_memory, ndef_offset, ndef_len, out_msg);
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

static bool classic_mad_entry_is_ndef(const uint8_t *mad, size_t mad_len, int entry, int entry_count)
{
    if (entry < 0 || entry >= entry_count || mad_len < 2u + (size_t)entry_count * 2u) {
        return false;
    }
    // The first two bytes are CRC and info byte; application identifiers follow, two bytes per sector.
    size_t  offset = 2u + (size_t)entry * 2u;
    uint8_t aid0   = mad[offset];
    uint8_t aid1   = mad[offset + 1u];
    return (aid0 == 0x03 && aid1 == 0xE1) || (aid0 == 0xE1 && aid1 == 0x03);
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
static pn5180_ndef_result_t type4_read_ndef(pn5180_proto_t *proto, pn5180_ndef_message_parsed_t **out_msg)
{
    static const uint8_t ndef_aid[]   = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    static const uint8_t cc_file_id[] = {0xE1, 0x03};
    pn5180_t            *pn5180       = proto->pn5180;

    if (!pn5180->iso14443_layer4_active) {
        PN5180_LOGD(TAG, "T4: ISO14443-4 is not active");
        return PN5180_NDEF_ERR_READ_FAILED;
    }
    // A card that refuses these selects is alive but carries no NDEF application.
    if (!pn5180_14443_4_select_file(pn5180, ndef_aid, sizeof(ndef_aid))) {
        PN5180_LOGD(TAG, "T4: SELECT NDEF application failed");
        return PN5180_NDEF_ERR_NO_NDEF;
    }
    if (!pn5180_14443_4_select_file(pn5180, cc_file_id, sizeof(cc_file_id))) {
        PN5180_LOGD(TAG, "T4: SELECT capability container failed");
        return PN5180_NDEF_ERR_NO_NDEF;
    }

    uint8_t cc[15];
    size_t  cc_got = sizeof(cc);
    if (!pn5180_14443_4_read_binary(pn5180, 0, sizeof(cc), cc, &cc_got) || cc_got < sizeof(cc)) {
        PN5180_LOGD(TAG, "T4: READ capability container failed (%u bytes)", (unsigned)cc_got);
        return PN5180_NDEF_ERR_READ_FAILED;
    }

    uint16_t mle           = (uint16_t)(((uint16_t)cc[3] << 8) | cc[4]);
    uint8_t  ndef_fid[2]   = {cc[9], cc[10]};
    uint16_t max_ndef_size = (uint16_t)(((uint16_t)cc[11] << 8) | cc[12]);
    if (cc[7] != 0x04 || cc[8] != 0x06 || max_ndef_size < 2) {
        PN5180_LOGD(TAG, "T4: bad NDEF File Control TLV (T=%02X L=%02X)", cc[7], cc[8]);
        return PN5180_NDEF_ERR_PARSE_FAILED;
    }
    // Mapping versions 1.x to 3.x share this capability container layout; a higher major version may not.
    uint8_t mapping_major = (uint8_t)(cc[2] >> 4);
    if (mapping_major < 1 || mapping_major > 3) {
        PN5180_LOGD(TAG, "T4: unsupported mapping version %02X", cc[2]);
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }
    // Read access 00h means free access; anything else needs a security setup this driver does not do.
    if (cc[13] != 0x00) {
        PN5180_LOGD(TAG, "T4: NDEF file is read protected (access byte %02X)", cc[13]);
        return PN5180_NDEF_ERR_ACCESS_DENIED;
    }
    // Chunk size: MLe counts data bytes only, so Le = MLe is legal; two bytes of headroom are kept for
    // cards that size MLe to their whole response buffer. Le is one byte and READ BINARY uses a
    // 260-byte buffer, so 248 data bytes is the ceiling.
    uint16_t chunk_max = (mle <= 2 || mle > 250) ? 248u : (uint16_t)(mle - 2u);

    if (!pn5180_14443_4_select_file(pn5180, ndef_fid, sizeof(ndef_fid))) {
        PN5180_LOGD(TAG, "T4: SELECT NDEF file %02X%02X failed", ndef_fid[0], ndef_fid[1]);
        return PN5180_NDEF_ERR_NO_NDEF;
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

/* ---- Type 5: ISO15693 ---- */

/*
 * Type 5 Tag NDEF mapping: the capability container starts at block 0.
 *   [0] magic: E1 (blocks addressed with one byte) or E2 (two bytes)
 *   [1] version and access conditions
 *   [2] MLEN: size of the data area after the CC in units of 8 bytes; 0 means that an
 *       8-byte CC is used and the size is in bytes 6..7
 *   [3] feature flags
 * TLVs follow directly after the capability container.
 */
static pn5180_ndef_result_t type5_read_ndef(pn5180_proto_t *proto, pn5180_uid_t *uid, pn5180_ndef_message_parsed_t **out_msg)
{
    size_t block_size = (uid->block_size > 0) ? (size_t)uid->block_size : 4u;
    if (block_size > 32u) {
        return PN5180_NDEF_ERR_UNSUPPORTED;
    }

    ndef_stream_t stream      = {0};
    size_t        cc_len      = 4;
    size_t        total_bytes = 8; // enough to hold either form of the CC; replaced once the CC is known
    bool          cc_known    = false;
    size_t        tlv_pos     = 0;
    size_t        ndef_offset = 0;
    size_t        ndef_len    = 0;
    bool          read_ok     = true;
    bool          no_memory   = false;
    tlv_scan_t    scan        = TLV_SCAN_MORE;

    for (int block = 0; scan == TLV_SCAN_MORE && (size_t)block * block_size < total_bytes; block++) {
        if (uid->blocks_count > 0 && block >= uid->blocks_count) {
            break;
        }
        uint8_t data[32];
        if (!proto->block_read(proto, block, data, block_size)) {
            read_ok = false;
            break;
        }
        if (!stream_append(&stream, data, block_size)) {
            no_memory = true;
            break;
        }

        if (!cc_known) {
            if (stream.len < 4) {
                continue;
            }
            if (stream.data[0] != 0xE1 && stream.data[0] != 0xE2) {
                PN5180_LOGD(TAG, "T5: no capability container (block 0 starts with %02X)", stream.data[0]);
                break;
            }
            size_t mlen = stream.data[2];
            if (mlen == 0) {
                if (stream.len < 8) {
                    continue;
                }
                cc_len = 8;
                mlen   = ((size_t)stream.data[6] << 8) | stream.data[7];
            }
            if (mlen == 0) {
                break;
            }
            total_bytes = cc_len + mlen * 8u;
            tlv_pos     = cc_len;
            cc_known    = true;
        }
        scan = stream_scan(&stream, &tlv_pos, &ndef_offset, &ndef_len);
    }

    return stream_finish(&stream, cc_known && scan == TLV_SCAN_FOUND, read_ok, no_memory, ndef_offset, ndef_len, out_msg);
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
