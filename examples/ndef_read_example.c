/**
 * Example: Reading NDEF messages from NFC cards
 *
 * This example demonstrates how to use ndef_read_from_selected_card() to read
 * and parse complete NDEF messages from NFC cards.
 */

#include "esp_log.h"
#include "pn5180-ndef.h"
#include "pn5180.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "NDEF_READ";

void example_read_ndef_from_card(pn5180_proto_t *proto)
{
    int start_block = 4;
    int block_size  = 16;

    ESP_LOGI(TAG, "Reading NDEF message from card...");

    ndef_message_parsed_t *msg    = NULL;
    ndef_result_t          result = ndef_read_from_selected_card(proto, start_block, block_size, 0, &msg);

    if (result != NDEF_OK || !msg) {
        ESP_LOGE(TAG, "Failed to read NDEF message: %s", ndef_result_to_string(result));
        return;
    }

    ESP_LOGI(TAG, "Successfully read NDEF message:");
    ESP_LOGI(TAG, "  Raw data length: %zu bytes", msg->raw_data_len);
    ESP_LOGI(TAG, "  Record count: %zu", msg->record_count);

    for (size_t i = 0; i < msg->record_count; i++) {
        ndef_record_t *rec = &msg->records[i];

        ESP_LOGI(TAG, "\nRecord %zu:", i + 1);
        ESP_LOGI(TAG, "  TNF: 0x%02X", rec->tnf);
        ESP_LOGI(TAG, "  Type length: %u", rec->type_len);
        ESP_LOGI(TAG, "  Payload length: %u", rec->payload_len);

        if (rec->type_len > 0) {
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, rec->type, rec->type_len, ESP_LOG_INFO);
        }

        // Check for Text RTD
        if (rec->tnf == NDEF_TNF_WELL_KNOWN && rec->type_len == 1 && rec->type[0] == 'T') {

            ESP_LOGI(TAG, "  Type: Text RTD");

            if (rec->payload_len > 1) {
                uint8_t status   = rec->payload[0];
                uint8_t lang_len = status & 0x3F;
                bool    is_utf16 = (status & 0x80) != 0;

                if (lang_len + 1 <= rec->payload_len) {
                    char lang[64] = {0};
                    memcpy(lang, rec->payload + 1, lang_len);
                    ESP_LOGI(TAG, "  Language: %s", lang);
                    ESP_LOGI(TAG, "  Encoding: %s", is_utf16 ? "UTF-16" : "UTF-8");

                    size_t text_len = rec->payload_len - lang_len - 1;
                    if (text_len > 0 && !is_utf16) {
                        char *text = malloc(text_len + 1);
                        if (text) {
                            memcpy(text, rec->payload + lang_len + 1, text_len);
                            text[text_len] = '\0';
                            ESP_LOGI(TAG, "  Text: %s", text);
                            free(text);
                        }
                    }
                }
            }
        }
        // Check for URI RTD
        else if (rec->tnf == NDEF_TNF_WELL_KNOWN && rec->type_len == 1 && rec->type[0] == 'U') {

            ESP_LOGI(TAG, "  Type: URI RTD");

            if (rec->payload_len > 0) {
                uint8_t     id_code = rec->payload[0];
                const char *prefix  = "";

                switch (id_code) {
                case 0x00:
                    prefix = "";
                    break;
                case 0x01:
                    prefix = "http://www.";
                    break;
                case 0x02:
                    prefix = "https://www.";
                    break;
                case 0x03:
                    prefix = "http://";
                    break;
                case 0x04:
                    prefix = "https://";
                    break;
                default:
                    prefix = "[unknown prefix]";
                    break;
                }

                size_t uri_len = rec->payload_len - 1;
                if (uri_len > 0) {
                    char *uri = malloc(strlen(prefix) + uri_len + 1);
                    if (uri) {
                        strcpy(uri, prefix);
                        memcpy(uri + strlen(prefix), rec->payload + 1, uri_len);
                        uri[strlen(prefix) + uri_len] = '\0';
                        ESP_LOGI(TAG, "  URI: %s", uri);
                        free(uri);
                    }
                }
            }
        }
    }

    ndef_free_parsed_message(msg);
    ESP_LOGI(TAG, "NDEF message freed");
}

void example_read_ndef_from_type5(pn5180_proto_t *proto)
{
    int start_block = 1;
    int block_size  = 4;

    ESP_LOGI(TAG, "Reading NDEF message from Type 5 tag...");

    ndef_message_parsed_t *msg    = NULL;
    ndef_result_t          result = ndef_read_from_selected_card(proto, start_block, block_size, 0, &msg);

    if (result != NDEF_OK || !msg) {
        ESP_LOGE(TAG, "Failed to read NDEF message from Type 5 tag: %s", ndef_result_to_string(result));
        return;
    }

    ESP_LOGI(TAG, "Type 5 tag - Found %zu record(s)", msg->record_count);

    ndef_free_parsed_message(msg);
}
