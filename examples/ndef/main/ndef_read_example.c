/**
 * Example: Reading NDEF messages from NFC cards
 *
 * This example demonstrates how to use pn5180_ndef_read_card_auto() to read
 * and parse complete NDEF messages from NFC cards.
 */

#include "esp_log.h"
#include "pn5180-ndef.h"
#include "pn5180.h"
#include <inttypes.h>

static const char *TAG = "PN5180_NDEF_READ";

// The card must be selected and its type detected (proto->select_by_uid(), then
// proto->detect_card_type_and_capacity(), and a second select if that one asks for it).
// The NDEF mapping is chosen from uid->subtype: Type 2 (Ultralight / NTAG), MIFARE Classic with
// the public NDEF keys, Type 4 (ISO14443-4) or Type 5 (ISO15693).
void example_read_ndef_from_card(pn5180_proto_t *proto, pn5180_uid_t *uid)
{
    ESP_LOGI(TAG, "Reading NDEF message from card...");

    pn5180_ndef_message_parsed_t *msg    = NULL;
    pn5180_ndef_result_t          result = pn5180_ndef_read_card_auto(proto, uid, &msg);

    if (result != PN5180_NDEF_OK || !msg) {
        ESP_LOGE(TAG, "Failed to read NDEF message: %s", pn5180_ndef_result_to_string(result));
        return;
    }

    ESP_LOGI(TAG, "Successfully read NDEF message:");
    ESP_LOGI(TAG, "  Raw data length: %zu bytes", msg->raw_data_len);
    ESP_LOGI(TAG, "  Record count: %zu", msg->record_count);

    for (size_t i = 0; i < msg->record_count; i++) {
        pn5180_ndef_record_t *rec = &msg->records[i];

        ESP_LOGI(TAG, "\nRecord %zu:", i + 1);
        ESP_LOGI(TAG, "  TNF: 0x%02X", (unsigned)rec->tnf);
        ESP_LOGI(TAG, "  Type length: %u", (unsigned)rec->type_len);
        ESP_LOGI(TAG, "  Payload length: %" PRIu32, rec->payload_len);

        if (rec->type_len > 0) {
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, rec->type, rec->type_len, ESP_LOG_INFO);
        }

        const uint8_t *text     = NULL;
        size_t         text_len = 0;
        char           lang[64]; // the card sets the length of the code, up to 63 bytes
        bool           is_utf16 = false;
        char           uri[256];
        size_t         uri_len = pn5180_ndef_extract_uri(rec, uri, sizeof(uri));
        if (uri_len > 0) {
            // The URI prefix code is expanded; a result of sizeof(uri) or more means it was truncated.
            ESP_LOGI(TAG, "  URI: %s%s", uri, uri_len >= sizeof(uri) ? "..." : "");
        } else if (pn5180_ndef_extract_text(rec, &text, &text_len, lang, sizeof(lang), &is_utf16)) {
            ESP_LOGI(TAG, "  Language: %s", lang);
            ESP_LOGI(TAG, "  Encoding: %s", is_utf16 ? "UTF-16" : "UTF-8");
            if (!is_utf16) {
                ESP_LOGI(TAG, "  Text: %.*s", (int)text_len, (const char *)text);
            }
        }
    }

    pn5180_ndef_free_parsed_message(msg);
    ESP_LOGI(TAG, "NDEF message freed");
}
