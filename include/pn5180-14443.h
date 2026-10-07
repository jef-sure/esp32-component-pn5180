#pragma once
#include "esp_err.h"
#include "pn5180.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize ISO14443A/MIFARE protocol wrapper
 * @param pn5180 Pointer to PN5180 device structure
 * @return Protocol interface for ISO14443A operations
 */
pn5180_proto_t *pn5180_14443_init(pn5180_t *pn5180);

/**
 * @brief Poll for ISO14443A cards and report why nothing was returned
 *
 * Same as the get_all_uids() callback, with a status that tells "no card" apart from a
 * transport failure, a protocol error and an allocation failure.
 *
 * @param proto Protocol interface from pn5180_14443_init()
 * @param status Out: outcome of the poll (may be NULL)
 * @return Heap-allocated UID array for PN5180_POLL_FOUND (caller must free), otherwise NULL
 */
pn5180_uids_array_t *pn5180_14443_get_all_uids_ex(pn5180_proto_t *proto, pn5180_poll_status_t *status);

/**
 * @brief Exchange an APDU with the selected ISO14443-4 (ISO-DEP) card
 *
 * The card must have been selected with select_by_uid(), which activates ISO14443-4 (RATS)
 * for cards that support it. Handles block chaining in both directions, waiting time
 * extensions and retransmission.
 *
 * @param pn5180 Pointer to PN5180 device structure
 * @param apdu Command APDU
 * @param apdu_len Command APDU length in bytes
 * @param rx Buffer for the response APDU (data followed by SW1 SW2)
 * @param rx_len In: size of @p rx. Out: response length
 * @return true if a response was received, false on failure or if ISO14443-4 is not active
 */
bool pn5180_14443_4_transceive(pn5180_t *pn5180, const uint8_t *apdu, size_t apdu_len, uint8_t *rx, size_t *rx_len);

/**
 * @brief Issue ISO 7816-4 SELECT by AID or file identifier
 *
 * More than two bytes select an application by AID (P1=0x04, P2=0x00). Two bytes or fewer
 * select an elementary file by identifier with P2=0x0C (no response data), as NFC Forum
 * Type 4 Tag mapping 2.0 requires; if the card refuses that with an error status word, the
 * select is retried once with P2=0x00 for mapping 1.0 cards.
 *
 * @return true if the card answered 90 00
 */
bool pn5180_14443_4_select_file(pn5180_t *pn5180, const uint8_t *file_id, size_t file_id_len);

/**
 * @brief Issue ISO 7816-4 READ BINARY on the currently selected file
 *
 * @param pn5180 Pointer to PN5180 device structure
 * @param offset File offset to read from; offsets above 0x7FFF are rejected
 * @param le Encoded short Le; 0 requests 256 bytes
 * @param buffer Output buffer
 * @param got In: buffer capacity. Out: number of bytes returned, or the required size when
 *            the response does not fit (the function then returns false)
 * @return false when the card reports an error status, the offset is out of range, or the
 *         response does not fit the buffer
 */
bool pn5180_14443_4_read_binary(pn5180_t *pn5180, uint16_t offset, uint8_t le, uint8_t *buffer, size_t *got);

/** @brief Common ISO 7816-4 response status words */
#define PN5180_APDU_SW_SUCCESS           0x9000u
#define PN5180_APDU_SW_WRONG_LENGTH      0x6700u
#define PN5180_APDU_SW_WRONG_P1P2        0x6A86u
#define PN5180_APDU_SW_INS_NOT_SUPPORTED 0x6D00u
#define PN5180_APDU_SW_CLA_NOT_SUPPORTED 0x6E00u

/** @brief Zero-copy representation of a short ISO 7816-4 command APDU */
typedef struct
{
    uint8_t        cla;
    uint8_t        ins;
    uint8_t        p1;
    uint8_t        p2;
    const uint8_t *data;
    size_t         data_len;
    bool           has_le;
    uint16_t       le; /**< Decoded Le; an encoded short Le of 0 is reported as 256 */
} pn5180_apdu_command_t;

/** @brief Zero-copy representation of an ISO 7816-4 response APDU */
typedef struct
{
    const uint8_t *data;
    size_t         data_len;
    uint8_t        sw1;
    uint8_t        sw2;
} pn5180_apdu_response_t;

/**
 * @brief Parse a short ISO 7816-4 command APDU without allocating memory
 *
 * Supports cases 1, 2S, 3S and 4S. The data member points into @p buffer.
 *
 * @return ESP_OK on success, ESP_ERR_NOT_SUPPORTED for an extended-length APDU,
 *         ESP_ERR_INVALID_ARG for invalid or malformed input
 */
esp_err_t pn5180_apdu_parse_command(const uint8_t *buffer, size_t length, pn5180_apdu_command_t *command);

/**
 * @brief Build a response APDU as [data...][SW1][SW2] in caller-owned memory
 * @return ESP_OK on success, ESP_ERR_NO_MEM when the buffer is too small,
 *         ESP_ERR_INVALID_ARG for invalid arguments
 */
esp_err_t pn5180_apdu_build_response(uint8_t *buffer, size_t buffer_size, const uint8_t *data, size_t data_len, uint8_t sw1, uint8_t sw2,
                                     size_t *response_len);

/**
 * @brief Parse a response APDU without allocating memory
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG when fewer than two bytes are available
 */
esp_err_t pn5180_apdu_parse_response(const uint8_t *buffer, size_t length, pn5180_apdu_response_t *response);

/** @brief Return SW1 and SW2 as one 16-bit status word, or 0 for NULL */
uint16_t pn5180_apdu_get_status(const pn5180_apdu_response_t *response);

#ifdef __cplusplus
}
#endif
