#pragma once

#include "pn5180.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief NDEF Type Name Format (TNF) values */
typedef enum
{
    PN5180_NDEF_TNF_EMPTY        = 0x00,
    PN5180_NDEF_TNF_WELL_KNOWN   = 0x01,
    PN5180_NDEF_TNF_MEDIA_TYPE   = 0x02,
    PN5180_NDEF_TNF_ABSOLUTE_URI = 0x03,
    PN5180_NDEF_TNF_EXTERNAL     = 0x04,
    PN5180_NDEF_TNF_UNKNOWN      = 0x05,
    PN5180_NDEF_TNF_UNCHANGED    = 0x06,
    PN5180_NDEF_TNF_RESERVED     = 0x07
} pn5180_ndef_tnf_t;

/** @brief NDEF operation result codes */
typedef enum
{
    PN5180_NDEF_OK                   = 0,  /**< Operation successful */
    PN5180_NDEF_ERR_INVALID_PARAM    = -1, /**< Invalid parameter (NULL pointer, bad size) */
    PN5180_NDEF_ERR_NO_MEMORY        = -2, /**< Memory allocation failed */
    PN5180_NDEF_ERR_READ_FAILED      = -3, /**< Card read operation failed */
    PN5180_NDEF_ERR_WRITE_FAILED     = -4, /**< Card write operation failed */
    PN5180_NDEF_ERR_NO_NDEF          = -5, /**< No NDEF TLV found on card */
    PN5180_NDEF_ERR_PARSE_FAILED     = -6, /**< NDEF message parsing failed */
    PN5180_NDEF_ERR_BUFFER_TOO_SMALL = -7, /**< Reserved: not returned by the driver */
    PN5180_NDEF_ERR_CARD_FULL        = -8, /**< Card capacity exceeded */
    PN5180_NDEF_ERR_UNSUPPORTED      = -9, /**< Card type has no NDEF mapping in this driver */
    PN5180_NDEF_ERR_ACCESS_DENIED    = -10, /**< The NDEF data is protected against the requested access */
} pn5180_ndef_result_t;

/** @name NDEF Record flag bits (header byte)
 * @{
 */
#define PN5180_NDEF_MB       (1u << 7) /**< Message Begin */
#define PN5180_NDEF_ME       (1u << 6) /**< Message End */
#define PN5180_NDEF_CF       (1u << 5) /**< Chunk Flag */
#define PN5180_NDEF_SR       (1u << 4) /**< Short Record (payload length is 1 byte) */
#define PN5180_NDEF_IL       (1u << 3) /**< ID Length field is present */
#define PN5180_NDEF_TNF_MASK (0x07u)   /**< TNF occupies bits [2:0] */
/** @} */

/** @brief NDEF Record structure */
typedef struct
{
    pn5180_ndef_tnf_t     tnf;         /**< Type Name Format */
    uint8_t        type_len;    /**< Length of type field (in bytes) */
    uint8_t        id_len;      /**< Length of id field (in bytes, 0 if none) */
    uint32_t       payload_len; /**< Length of payload (in bytes) */
    const uint8_t *type;        /**< Pointer to type bytes */
    const uint8_t *id;          /**< Pointer to id bytes (optional) */
    const uint8_t *payload;     /**< Pointer to payload bytes */
} pn5180_ndef_record_t;

/** @brief NDEF Message structure */
typedef struct
{
    pn5180_ndef_record_t *records;      /**< Array of records (provided by caller) */
    size_t         record_count; /**< Number of records currently in the message */
    size_t         capacity;     /**< Max number of records writable to 'records' */
} pn5180_ndef_message_t;

/** @name Common Well-known RTD type values (Type field for TNF=Well-known)
 * @{
 */
extern const uint8_t PN5180_NDEF_RTD_TEXT[];        /**< Text RTD "T" */
extern const uint8_t PN5180_NDEF_RTD_URI[];         /**< URI RTD "U" */
extern const uint8_t PN5180_NDEF_RTD_SMARTPOSTER[]; /**< Smart Poster RTD "Sp" */

#define PN5180_NDEF_RTD_TEXT_LEN        1 /**< Length of Text RTD type */
#define PN5180_NDEF_RTD_URI_LEN         1 /**< Length of URI RTD type */
#define PN5180_NDEF_RTD_SMARTPOSTER_LEN 2 /**< Length of Smart Poster RTD type */
/** @} */

/** @brief Common NDEF record types for easy identification */
typedef enum
{
    PN5180_NDEF_RECORD_TYPE_UNKNOWN     = 0, /**< Unknown or unsupported type */
    PN5180_NDEF_RECORD_TYPE_TEXT        = 1, /**< Well-known Text record */
    PN5180_NDEF_RECORD_TYPE_URI         = 2, /**< Well-known URI record */
    PN5180_NDEF_RECORD_TYPE_SMARTPOSTER = 3, /**< Well-known Smart Poster record */
    PN5180_NDEF_RECORD_TYPE_MIME        = 4, /**< MIME type record */
    PN5180_NDEF_RECORD_TYPE_EXTERNAL    = 5, /**< External type record */
    PN5180_NDEF_RECORD_TYPE_EMPTY       = 6, /**< Empty record */
} pn5180_ndef_record_type_t;

/**
 * @brief Initialize NDEF message structure
 * @param msg Pointer to message structure to initialize
 * @param records Array of record structures for storage
 * @param capacity Maximum number of records the array can hold
 */
void pn5180_ndef_message_init(pn5180_ndef_message_t *msg, pn5180_ndef_record_t *records, size_t capacity);

/**
 * @brief Add a record to NDEF message
 * @param msg Pointer to message structure
 * @param rec Pointer to record to add (shallow copy)
 * @return true on success, false if capacity exceeded
 */
bool pn5180_ndef_message_add(pn5180_ndef_message_t *msg, const pn5180_ndef_record_t *rec);

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
void pn5180_ndef_record_init(         //
    pn5180_ndef_record_t *rec,        //
    pn5180_ndef_tnf_t     tnf,        //
    const uint8_t *type,       //
    uint8_t        type_len,   //
    const uint8_t *id,         //
    uint8_t        id_len,     //
    const uint8_t *payload,    //
    uint32_t       payload_len //
);

/**
 * @brief Encode NDEF message to binary format
 *
 * If out is NULL or out_len is 0, returns required buffer size.
 *
 * @param msg Pointer to message to encode
 * @param out Output buffer (can be NULL to query size)
 * @param out_len Size of output buffer
 * A record the parser of this driver would refuse is not encoded: an Empty record
 * (PN5180_NDEF_TNF_EMPTY) with a type, ID or payload, an Unknown record
 * (PN5180_NDEF_TNF_UNKNOWN) with a type, and the TNF values PN5180_NDEF_TNF_UNCHANGED and
 * PN5180_NDEF_TNF_RESERVED.
 *
 * @return Number of bytes written, or the number of bytes required when only the size is asked
 *         for. 0 on failure: msg is NULL, the message has no records, out_len is smaller than
 *         required, a record declares a type, ID or payload length without the matching
 *         pointer, or a record is one of those named above. Nothing is written to out on failure.
 */
size_t pn5180_ndef_encode_message(const pn5180_ndef_message_t *msg, uint8_t *out, size_t out_len);

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
bool pn5180_ndef_make_text_record(        //
    pn5180_ndef_record_t *rec,            //
    const char    *lang_code,      //
    const uint8_t *text,           //
    size_t         text_len,       //
    bool           utf16,          //
    uint8_t       *payload_buf,    //
    size_t         payload_buf_len //
);

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
bool pn5180_ndef_make_uri_record(pn5180_ndef_record_t *rec, const char *uri, bool abbreviate, uint8_t *payload_buf, size_t payload_buf_len);

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
bool pn5180_ndef_decode_next(const uint8_t *in, size_t in_len, size_t *offset, pn5180_ndef_record_t *out_rec, bool *is_begin, bool *is_end);

/**
 * @brief Decode complete NDEF message from buffer
 *
 * Decodes the records into the caller's array; they point into the input buffer. The message
 * structure is checked as in pn5180_ndef_parse_message(): Message Begin on the first record
 * only, Message End on the last one, nothing after it, valid chunk sequences. A message with
 * more records than 'capacity' returns 0. Chunks are returned as separate records; use
 * pn5180_ndef_parse_message() to get them assembled, as for data read from a card.
 *
 * @param in Input buffer containing encoded NDEF data
 * @param in_len Length of input buffer
 * @param records Array to store decoded records
 * @param capacity Size of the records array
 * @return Number of records decoded, 0 on error or if the array is too small
 */
size_t pn5180_ndef_decode_message(const uint8_t *in, size_t in_len, pn5180_ndef_record_t *records, size_t capacity);

/** @brief Forward declaration for protocol interface */
struct _pn5180_proto_t;

/** @brief NDEF Message with allocated memory for card reading */
typedef struct
{
    uint8_t       *raw_data;     /**< Allocated buffer containing complete NDEF message */
    size_t         raw_data_len; /**< Length of raw NDEF data */
    pn5180_ndef_record_t *records;      /**< Array of decoded records (allocated) */
    size_t         record_count; /**< Number of records in message */
} pn5180_ndef_message_parsed_t;

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
typedef bool (*pn5180_ndef_auth_callback_t)(struct _pn5180_proto_t *proto, int blockno, void *user_ctx);

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
typedef int (*pn5180_ndef_sector_id_callback_t)(int blockno, void *user_ctx);

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
 * @return PN5180_NDEF_OK on success, error code on failure
 * @note Caller must free using pn5180_ndef_free_parsed_message()
 */
pn5180_ndef_result_t pn5180_ndef_read_from_selected_card( //
    struct _pn5180_proto_t   *proto,        //
    int                       start_block,  //
    int                       block_size,   //
    int                       max_blocks,   //
    pn5180_ndef_auth_callback_t      auth_cb,      //
    pn5180_ndef_sector_id_callback_t sector_cb,    //
    void                     *auth_ctx,     //
    pn5180_ndef_message_parsed_t   **out_msg       //
);

/**
 * @brief Free memory allocated by pn5180_ndef_read_from_selected_card
 * @param msg Pointer to parsed message to free (can be NULL)
 */
void pn5180_ndef_free_parsed_message(pn5180_ndef_message_parsed_t *msg);

/**
 * @brief Parse an encoded NDEF message into logical records
 *
 * Records carrying the chunk flag (CF) are validated and reassembled: the first chunk supplies
 * TNF, type and ID, the following chunks must use TNF "unchanged", and their payloads are
 * concatenated into one logical record. The returned message owns a copy of the encoded bytes
 * and the assembled payloads.
 *
 * @param raw_data Encoded NDEF message (without TLV or NLEN prefix)
 * @param raw_data_len Number of encoded bytes
 * @param out_msg Receives the parsed message; free with pn5180_ndef_free_parsed_message()
 * @return PN5180_NDEF_OK or an error code
 */
pn5180_ndef_result_t pn5180_ndef_parse_message(const uint8_t *raw_data, size_t raw_data_len, pn5180_ndef_message_parsed_t **out_msg);

/**
 * @brief Read the NDEF message of a selected card, whatever its tag type
 *
 * Picks the NDEF mapping from uid->subtype, so detect_card_type_and_capacity() must have run,
 * and the card must be selected (select_by_uid()):
 * - Ultralight / NTAG (Type 2): capability container in page 3, TLVs from page 4
 * - MIFARE Classic: sectors listed in the MIFARE Application Directory, with the public NDEF keys
 * - ISO14443-4 cards (Type 4): NDEF application, capability container file, NDEF file
 * - ISO15693 (Type 5): capability container in block 0, TLVs after it
 *
 * The checks follow the NXP reader library: a Type 2 or Type 5 capability container must show
 * a supported major version and standard access conditions; a MIFARE Classic NDEF sector must
 * grant read access in its general purpose byte; a Type 4 capability container must be
 * consistent.
 *
 * A failed read is retried once after selecting the card again, because several card families
 * leave the selected state after an error.
 *
 * @param proto Protocol interface the card was found with
 * @param uid Card to read; its subtype, block_size and blocks_count are used
 * @param out_msg Receives the parsed message; free with pn5180_ndef_free_parsed_message()
 * @return PN5180_NDEF_OK, or
 *         PN5180_NDEF_ERR_NO_NDEF if the card is not NDEF formatted or carries no message,
 *         PN5180_NDEF_ERR_UNSUPPORTED for a card type without NDEF mapping, an unknown mapping
 *         version, proprietary access conditions, or a Type 2 tag with lock or reserved bytes
 *         inside the message,
 *         PN5180_NDEF_ERR_ACCESS_DENIED if the tag protects the message against reading,
 *         PN5180_NDEF_ERR_PARSE_FAILED if the tag or the message is inconsistent,
 *         or another error code
 */
pn5180_ndef_result_t pn5180_ndef_read_card_auto(struct _pn5180_proto_t *proto, pn5180_uid_t *uid, pn5180_ndef_message_parsed_t **out_msg);

/**
 * @brief Write an NDEF message to a selected card, whatever its tag type
 *
 * The counterpart of pn5180_ndef_read_card_auto(): the mapping is picked from uid->subtype, and
 * the data area is taken from the capability container of the tag.
 * - Ultralight / NTAG (Type 2): capability container in page 3, TLVs from page 4
 * - ISO15693 (Type 5): capability container in block 0, TLVs after it
 *
 * MIFARE Classic and ISO14443-4 cards are not written.
 *
 * The procedure is the one of the NXP reader library. The tag must be NDEF formatted: a
 * capability container with a supported version and read/write access, and an NDEF TLV in the
 * data area (an empty one on a new tag). The message replaces the content of that NDEF TLV;
 * TLVs in front of it, such as the Lock Control TLV of an NTAG, are kept. The TLV length is set
 * to 0 first and to the real length last, so an interrupted write leaves an empty message. A
 * Terminator TLV follows the message if the data area has room for it.
 *
 * @param proto Protocol interface the card was found with; the card must be selected
 * @param uid Card to write, with subtype, block_size and blocks_count set by
 *            detect_card_type_and_capacity()
 * @param msg Message to write, with at least one record
 * @return PN5180_NDEF_OK, or
 *         PN5180_NDEF_ERR_UNSUPPORTED for a card type this function does not write, an unknown
 *         mapping version, proprietary access conditions, or a Type 2 tag with lock or reserved
 *         bytes inside its data area,
 *         PN5180_NDEF_ERR_NO_NDEF if the tag has no capability container or no NDEF TLV (not
 *         NDEF formatted),
 *         PN5180_NDEF_ERR_ACCESS_DENIED if the tag is read-only,
 *         PN5180_NDEF_ERR_CARD_FULL if the message does not fit the data area,
 *         PN5180_NDEF_ERR_READ_FAILED or PN5180_NDEF_ERR_WRITE_FAILED if the card refused a
 *         command; select the card again after these
 */
pn5180_ndef_result_t pn5180_ndef_write_card_auto(struct _pn5180_proto_t *proto, const pn5180_uid_t *uid, const pn5180_ndef_message_t *msg);

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
bool pn5180_ndef_extract_text(const pn5180_ndef_record_t *rec, const uint8_t **text_out, size_t *text_len_out, char *lang_buf, bool *is_utf16);

/**
 * @brief Extract URI from a Well-known URI record
 *
 * Expands abbreviated URI prefixes and returns complete URI string.
 * Caller provides buffer for the expanded URI.
 *
 * @param rec Pointer to record to extract URI from
 * @param uri_buf Buffer to store expanded URI (can be NULL to query the length)
 * @param uri_buf_len Size of uri_buf, including the terminating NUL
 * @return Length of the complete URI without the terminating NUL, 0 if rec is not a URI record.
 *         A result of uri_buf_len or more means that the string in uri_buf was truncated; it is
 *         NUL-terminated in every case.
 */
size_t pn5180_ndef_extract_uri(const pn5180_ndef_record_t *rec, char *uri_buf, size_t uri_buf_len);

/**
 * @brief Get the type of an NDEF record
 * @param rec Pointer to record to check
 * @return Record type enum value
 */
pn5180_ndef_record_type_t pn5180_ndef_get_record_type(const pn5180_ndef_record_t *rec);

/**
 * @brief Check if record is a Well-known Text record
 * @param rec Pointer to record to check
 * @return true if Text record, false otherwise
 */
bool pn5180_ndef_record_is_text(const pn5180_ndef_record_t *rec);

/**
 * @brief Check if record is a Well-known URI record
 * @param rec Pointer to record to check
 * @return true if URI record, false otherwise
 */
bool pn5180_ndef_record_is_uri(const pn5180_ndef_record_t *rec);

/**
 * @brief Check if record is a Well-known Smart Poster record
 * @param rec Pointer to record to check
 * @return true if Smart Poster record, false otherwise
 */
bool pn5180_ndef_record_is_smartposter(const pn5180_ndef_record_t *rec);

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
bool pn5180_ndef_make_mime_record(pn5180_ndef_record_t *rec, const char *mime_type, const uint8_t *data, size_t data_len, uint8_t *type_buf, size_t type_buf_len);

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
bool pn5180_ndef_make_external_record(pn5180_ndef_record_t *rec, const char *type_name, const uint8_t *data, size_t data_len, uint8_t *type_buf, size_t type_buf_len);

/**
 * @brief Decode Smart Poster nested records
 *
 * Smart Poster records contain nested NDEF messages in their payload.
 * This function decodes those nested records; they point into the payload of rec. The nested
 * message is checked like a message read from a card: a payload without Message End, with a
 * second Message Begin or with data after the last record returns 0, and so does a nested
 * message with chunked records or with more records than 'capacity'.
 *
 * @param rec Pointer to Smart Poster record
 * @param records Array to store decoded nested records
 * @param capacity Size of the records array
 * @return Number of nested records decoded, 0 on error or if the array is too small
 */
size_t pn5180_ndef_decode_smartposter(const pn5180_ndef_record_t *rec, pn5180_ndef_record_t *records, size_t capacity);

/**
 * @brief Convert error code to human-readable string
 * @param result Error code to convert
 * @return Static string describing the error
 */
const char *pn5180_ndef_result_to_string(pn5180_ndef_result_t result);

#ifdef __cplusplus
}
#endif
