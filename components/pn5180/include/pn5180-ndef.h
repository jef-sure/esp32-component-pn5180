#pragma once

#include "pn5180.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** @brief NDEF Type Name Format (TNF) values */
typedef enum
{
    NDEF_TNF_EMPTY        = 0x00,
    NDEF_TNF_WELL_KNOWN   = 0x01,
    NDEF_TNF_MEDIA_TYPE   = 0x02,
    NDEF_TNF_ABSOLUTE_URI = 0x03,
    NDEF_TNF_EXTERNAL     = 0x04,
    NDEF_TNF_UNKNOWN      = 0x05,
    NDEF_TNF_UNCHANGED    = 0x06,
    NDEF_TNF_RESERVED     = 0x07
} ndef_tnf_t;

/** @brief NDEF operation result codes */
typedef enum
{
    NDEF_OK                   = 0,  /**< Operation successful */
    NDEF_ERR_INVALID_PARAM    = -1, /**< Invalid parameter (NULL pointer, bad size) */
    NDEF_ERR_NO_MEMORY        = -2, /**< Memory allocation failed */
    NDEF_ERR_READ_FAILED      = -3, /**< Card read operation failed */
    NDEF_ERR_WRITE_FAILED     = -4, /**< Card write operation failed */
    NDEF_ERR_NO_NDEF          = -5, /**< No NDEF TLV found on card */
    NDEF_ERR_PARSE_FAILED     = -6, /**< NDEF message parsing failed */
    NDEF_ERR_BUFFER_TOO_SMALL = -7, /**< Output buffer too small */
    NDEF_ERR_CARD_FULL        = -8, /**< Card capacity exceeded */
} ndef_result_t;

/** @name NDEF Record flag bits (header byte)
 * @{
 */
#define NDEF_MB       (1u << 7) /**< Message Begin */
#define NDEF_ME       (1u << 6) /**< Message End */
#define NDEF_CF       (1u << 5) /**< Chunk Flag */
#define NDEF_SR       (1u << 4) /**< Short Record (payload length is 1 byte) */
#define NDEF_IL       (1u << 3) /**< ID Length field is present */
#define NDEF_TNF_MASK (0x07u)   /**< TNF occupies bits [2:0] */
/** @} */

/** @brief NDEF Record structure */
typedef struct
{
    ndef_tnf_t     tnf;         /**< Type Name Format */
    uint8_t        type_len;    /**< Length of type field (in bytes) */
    uint8_t        id_len;      /**< Length of id field (in bytes, 0 if none) */
    uint32_t       payload_len; /**< Length of payload (in bytes) */
    const uint8_t *type;        /**< Pointer to type bytes */
    const uint8_t *id;          /**< Pointer to id bytes (optional) */
    const uint8_t *payload;     /**< Pointer to payload bytes */
} ndef_record_t;

/** @brief NDEF Message structure */
typedef struct
{
    ndef_record_t *records;      /**< Array of records (provided by caller) */
    size_t         record_count; /**< Number of records currently in the message */
    size_t         capacity;     /**< Max number of records writable to 'records' */
} ndef_message_t;

/** @name Common Well-known RTD type values (Type field for TNF=Well-known)
 * @{
 */
extern const uint8_t NDEF_RTD_TEXT[];        /**< Text RTD "T" */
extern const uint8_t NDEF_RTD_URI[];         /**< URI RTD "U" */
extern const uint8_t NDEF_RTD_SMARTPOSTER[]; /**< Smart Poster RTD "Sp" */

#define NDEF_RTD_TEXT_LEN        1 /**< Length of Text RTD type */
#define NDEF_RTD_URI_LEN         1 /**< Length of URI RTD type */
#define NDEF_RTD_SMARTPOSTER_LEN 2 /**< Length of Smart Poster RTD type */
/** @} */

/** @brief Common NDEF record types for easy identification */
typedef enum
{
    NDEF_RECORD_TYPE_UNKNOWN     = 0, /**< Unknown or unsupported type */
    NDEF_RECORD_TYPE_TEXT        = 1, /**< Well-known Text record */
    NDEF_RECORD_TYPE_URI         = 2, /**< Well-known URI record */
    NDEF_RECORD_TYPE_SMARTPOSTER = 3, /**< Well-known Smart Poster record */
    NDEF_RECORD_TYPE_MIME        = 4, /**< MIME type record */
    NDEF_RECORD_TYPE_EXTERNAL    = 5, /**< External type record */
    NDEF_RECORD_TYPE_EMPTY       = 6, /**< Empty record */
} ndef_record_type_t;

/**
 * @brief Initialize NDEF message structure
 * @param msg Pointer to message structure to initialize
 * @param records Array of record structures for storage
 * @param capacity Maximum number of records the array can hold
 */
void ndef_message_init(ndef_message_t *msg, ndef_record_t *records, size_t capacity);

/**
 * @brief Add a record to NDEF message
 * @param msg Pointer to message structure
 * @param rec Pointer to record to add (shallow copy)
 * @return true on success, false if capacity exceeded
 */
bool ndef_message_add(ndef_message_t *msg, const ndef_record_t *rec);

/**
 * @brief Initialize NDEF record structure
 * @param rec Pointer to record to initialize
 * @param tnf Type Name Format value
 * @param type Pointer to type bytes
 * @param type_len Length of type field
 * @param id Pointer to ID bytes (can be NULL)
 * @param id_len Length of ID field (0 if none)
 * @param payload Pointer to payload bytes
 * @param payload_len Length of payload
 */
void ndef_record_init(ndef_record_t *rec, ndef_tnf_t tnf, const uint8_t *type, uint8_t type_len, const uint8_t *id, uint8_t id_len, const uint8_t *payload,
                      uint32_t payload_len);

/**
 * @brief Encode NDEF message to binary format
 *
 * If out is NULL or out_len is 0, returns required buffer size.
 *
 * @param msg Pointer to message to encode
 * @param out Output buffer (can be NULL to query size)
 * @param out_len Size of output buffer
 * @return Number of bytes written/required on success, 0 on failure
 */
size_t ndef_encode_message(const ndef_message_t *msg, uint8_t *out, size_t out_len);

/**
 * @brief Build Well-known RTD Text record (TNF=Well-known, Type="T")
 *
 * Payload format: [status][lang_code][text]
 * - status: bit7 UTF16 flag, bits[5:0] language code length (0..63)
 *
 * Caller provides payload_buf for storage; record references this buffer.
 *
 * @param rec Pointer to record to initialize
 * @param lang_code Language code string (e.g., "en")
 * @param text Text content bytes
 * @param text_len Length of text content
 * @param utf16 true for UTF-16 encoding, false for UTF-8
 * @param payload_buf Buffer to store payload (must remain valid)
 * @param payload_buf_len Size of payload buffer
 * @return true on success, false on failure
 */
bool ndef_make_text_record(ndef_record_t *rec, const char *lang_code, const uint8_t *text, size_t text_len, bool utf16, uint8_t *payload_buf,
                           size_t payload_buf_len);

/**
 * @brief Build Well-known RTD URI record (TNF=Well-known, Type="U")
 *
 * Payload format: [identifier_code][uri_remaining]
 * If abbreviate is true, common prefixes are replaced with a one-byte code.
 *
 * Caller provides payload_buf for storage; record references this buffer.
 *
 * @param rec Pointer to record to initialize
 * @param uri URI string
 * @param abbreviate true to use prefix abbreviation codes
 * @param payload_buf Buffer to store payload (must remain valid)
 * @param payload_buf_len Size of payload buffer
 * @return true on success, false on failure
 */
bool ndef_make_uri_record(ndef_record_t *rec, const char *uri, bool abbreviate, uint8_t *payload_buf, size_t payload_buf_len);

/**
 * @brief Decode next NDEF record from encoded buffer
 *
 * Iteratively decodes records from an encoded NDEF buffer without allocations.
 * The out_rec fields (type/id/payload) point into the input buffer.
 *
 * @param in Input buffer containing encoded NDEF data
 * @param in_len Length of input buffer
 * @param offset Pointer to current offset (starts at 0, advanced on success)
 * @param out_rec Pointer to record structure to fill
 * @param is_begin Optional pointer to receive MB (Message Begin) flag
 * @param is_end Optional pointer to receive ME (Message End) flag
 * @return true on success, false on parse error or if offset exceeds buffer
 */
bool ndef_decode_next(const uint8_t *in, size_t in_len, size_t *offset, ndef_record_t *out_rec, bool *is_begin, bool *is_end);

/**
 * @brief Decode complete NDEF message from buffer
 *
 * Convenience function that decodes up to 'capacity' records.
 * Stops when ME flag is encountered or capacity exhausted.
 *
 * @param in Input buffer containing encoded NDEF data
 * @param in_len Length of input buffer
 * @param records Array to store decoded records
 * @param capacity Maximum number of records to decode
 * @return Number of records decoded, 0 on error
 */
size_t ndef_decode_message(const uint8_t *in, size_t in_len, ndef_record_t *records, size_t capacity);

/** @brief Forward declaration for protocol interface */
struct _pn5180_proto_t;

/** @brief NDEF Message with allocated memory for card reading */
typedef struct
{
    uint8_t       *raw_data;     /**< Allocated buffer containing complete NDEF message */
    size_t         raw_data_len; /**< Length of raw NDEF data */
    ndef_record_t *records;      /**< Array of decoded records (allocated) */
    size_t         record_count; /**< Number of records in message */
} ndef_message_parsed_t;

/**
 * @brief Optional authentication callback used during NDEF read
 *
 * This callback is invoked before each block read. It can perform
 * card-specific authentication (e.g., MIFARE Classic sector auth).
 *
 * @param proto Pointer to protocol interface
 * @param blockno Block number that will be read next
 * @param user_ctx User context pointer
 * @return true to continue reading, false to abort
 */
typedef bool (*ndef_auth_callback_t)(struct _pn5180_proto_t *proto, int blockno, void *user_ctx);

/**
 * @brief Optional sector ID callback used to detect sector boundaries
 *
 * Returns a sector identifier for a given block. When provided, the
 * auth callback is invoked only when the sector ID changes.
 *
 * @param blockno Block number that will be read next
 * @param user_ctx User context pointer
 * @return Sector identifier (any stable integer per sector)
 */
typedef int (*ndef_sector_id_callback_t)(int blockno, void *user_ctx);

/**
 * @brief Read NDEF message from an already selected NFC card
 *
 * Reads blocks from card until complete NDEF TLV is found, allocates memory
 * for raw data and record structures, parses all records.
 *
 * @warning Card must be selected before calling this function
 *
 * @param proto Pointer to protocol interface (card must be selected)
 * @param start_block Starting block number for NDEF data
 * @param block_size Size of each block in bytes
 * @param max_blocks Maximum blocks to read (0 = no limit, uses default 256)
 * @param auth_cb Optional authentication callback (can be NULL)
 * @param sector_cb Optional sector ID callback for auth throttling (can be NULL)
 * @param auth_ctx User context pointer passed to auth/sector callbacks (can be NULL)
 * @param out_msg Pointer to receive parsed message pointer
 * @return NDEF_OK on success, error code on failure
 * @note Caller must free using ndef_free_parsed_message()
 */
ndef_result_t ndef_read_from_selected_card(struct _pn5180_proto_t *proto, int start_block, int block_size, int max_blocks,
                                           ndef_auth_callback_t auth_cb, ndef_sector_id_callback_t sector_cb, void *auth_ctx,
                                           ndef_message_parsed_t **out_msg);

/**
 * @brief Write NDEF message to an already selected NFC card
 *
 * Encodes message with TLV wrapper and writes to card blocks.
 * Writes NULL TLV padding and Terminator TLV at end.
 *
 * @warning Card must be selected before calling this function
 *
 * @param proto Pointer to protocol interface (card must be selected)
 * @param msg Pointer to message to write
 * @param start_block Starting block number for NDEF data
 * @param block_size Size of each block in bytes
 * @param max_blocks Maximum number of blocks available on card (0 = no limit)
 * @return NDEF_OK on success, error code on failure
 */
ndef_result_t ndef_write_to_selected_card(struct _pn5180_proto_t *proto, const ndef_message_t *msg, int start_block, int block_size, int max_blocks);

/**
 * @brief Free memory allocated by ndef_read_from_selected_card
 * @param msg Pointer to parsed message to free (can be NULL)
 */
void ndef_free_parsed_message(ndef_message_parsed_t *msg);

/**
 * @brief Extract text content from a Well-known Text record
 *
 * Extracts the text portion from an NDEF Text record (TNF=Well-known, Type="T").
 * The returned pointer points directly into the record payload (no allocation).
 *
 * @param rec Pointer to record to extract text from
 * @param text_out Pointer to receive text data pointer
 * @param text_len_out Pointer to receive text length
 * @param lang_buf Buffer for language code (at least 64 bytes), or NULL to skip
 * @param is_utf16 Optional pointer to receive encoding flag (true=UTF-16, false=UTF-8)
 * @return true if record is valid Text record, false otherwise
 */
bool ndef_extract_text(const ndef_record_t *rec, const uint8_t **text_out, size_t *text_len_out, char *lang_buf, bool *is_utf16);

/**
 * @brief Extract URI from a Well-known URI record
 *
 * Expands abbreviated URI prefixes and returns complete URI string.
 * Caller provides buffer for the expanded URI.
 *
 * @param rec Pointer to record to extract URI from
 * @param uri_buf Buffer to store expanded URI
 * @param uri_buf_len Size of uri_buf
 * @return Length of URI on success (may exceed uri_buf_len if truncated), 0 on error
 */
size_t ndef_extract_uri(const ndef_record_t *rec, char *uri_buf, size_t uri_buf_len);

/**
 * @brief Get the type of an NDEF record
 * @param rec Pointer to record to check
 * @return Record type enum value
 */
ndef_record_type_t ndef_get_record_type(const ndef_record_t *rec);

/**
 * @brief Check if record is a Well-known Text record
 * @param rec Pointer to record to check
 * @return true if Text record, false otherwise
 */
bool ndef_record_is_text(const ndef_record_t *rec);

/**
 * @brief Check if record is a Well-known URI record
 * @param rec Pointer to record to check
 * @return true if URI record, false otherwise
 */
bool ndef_record_is_uri(const ndef_record_t *rec);

/**
 * @brief Check if record is a Well-known Smart Poster record
 * @param rec Pointer to record to check
 * @return true if Smart Poster record, false otherwise
 */
bool ndef_record_is_smartposter(const ndef_record_t *rec);

/**
 * @brief Build MIME type record (TNF=Media-type)
 *
 * @param rec Pointer to record to initialize
 * @param mime_type MIME type string (e.g., "application/json")
 * @param data Payload data
 * @param data_len Length of payload data
 * @param type_buf Buffer to store MIME type (must remain valid)
 * @param type_buf_len Size of type buffer
 * @return true on success, false on failure
 */
bool ndef_make_mime_record(ndef_record_t *rec, const char *mime_type, const uint8_t *data, size_t data_len, uint8_t *type_buf, size_t type_buf_len);

/**
 * @brief Build External type record (TNF=External)
 *
 * External types use reverse domain name notation (e.g., "example.com:mytype")
 *
 * @param rec Pointer to record to initialize
 * @param type_name External type string (e.g., "example.com:mytype")
 * @param data Payload data
 * @param data_len Length of payload data
 * @param type_buf Buffer to store type name (must remain valid)
 * @param type_buf_len Size of type buffer
 * @return true on success, false on failure
 */
bool ndef_make_external_record(ndef_record_t *rec, const char *type_name, const uint8_t *data, size_t data_len, uint8_t *type_buf, size_t type_buf_len);

/**
 * @brief Decode Smart Poster nested records
 *
 * Smart Poster records contain nested NDEF messages in their payload.
 * This function decodes those nested records.
 *
 * @param rec Pointer to Smart Poster record
 * @param records Array to store decoded nested records
 * @param capacity Maximum number of records to decode
 * @return Number of nested records decoded, 0 on error
 */
size_t ndef_decode_smartposter(const ndef_record_t *rec, ndef_record_t *records, size_t capacity);

/**
 * @brief Convert error code to human-readable string
 * @param result Error code to convert
 * @return Static string describing the error
 */
const char *ndef_result_to_string(ndef_result_t result);
