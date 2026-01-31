#include "esp_log.h"
#include "pn5180-ndef.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG_NDEF = "ndef_demo";

void run_ndef_demo(void)
{
    ESP_LOGI(TAG_NDEF, "Running NDEF demo: building Text + URI records");

    // Prepare storage for 2 records
    ndef_record_t  records[2];
    ndef_message_t msg;
    ndef_message_init(&msg, records, 2);

    // Payload buffers
    uint8_t text_payload[64];
    uint8_t uri_payload[128];

    // Build Text RTD: lang="en", text="Hello NFC"
    const char *lang = "en";
    const char *text = "Hello NFC";
    if (!ndef_make_text_record(&records[0], lang, (const uint8_t *)text, strlen(text), false, text_payload, sizeof(text_payload))) {
        ESP_LOGE(TAG_NDEF, "Failed to build Text RTD record");
        return;
    }

    // Build URI RTD: uri="https://example.com"
    const char *uri = "https://example.com";
    if (!ndef_make_uri_record(&records[1], uri, true, uri_payload, sizeof(uri_payload))) {
        ESP_LOGE(TAG_NDEF, "Failed to build URI RTD record");
        return;
    }

    // Add records into message
    if (!ndef_message_add(&msg, &records[0]) || !ndef_message_add(&msg, &records[1])) {
        ESP_LOGE(TAG_NDEF, "Failed to add records to message");
        return;
    }

    // Query required length, then encode
    size_t required = ndef_encode_message(&msg, NULL, 0);
    ESP_LOGI(TAG_NDEF, "NDEF required length: %u", (unsigned)required);
    uint8_t *encoded = (uint8_t *)malloc(required);
    if (!encoded) {
        ESP_LOGE(TAG_NDEF, "Failed to allocate %u bytes for NDEF message", (unsigned)required);
        return;
    }
    size_t written = ndef_encode_message(&msg, encoded, required);
    if (written == 0) {
        ESP_LOGE(TAG_NDEF, "Encoding failed");
        free(encoded);
        return;
    }

    // Print encoded bytes
    char  line[256];
    char *p = line;
    for (size_t i = 0; i < written; ++i) {
        int n = snprintf(p, sizeof(line) - (p - line), "%02X ", encoded[i]);
        if (n <= 0) break;
        p += n;
        if ((i % 16) == 15) {
            ESP_LOGI(TAG_NDEF, "%s", line);
            p = line;
        }
    }
    if (p != line) ESP_LOGI(TAG_NDEF, "%s", line);

    // Decode back into records
    ndef_record_t decoded[4];
    size_t        decoded_count = ndef_decode_message(encoded, written, decoded, 4);
    if (decoded_count == 0) {
        ESP_LOGE(TAG_NDEF, "Decoding failed");
        free(encoded);
        return;
    }
    ESP_LOGI(TAG_NDEF, "Decoded %u record(s)", (unsigned)decoded_count);
    for (size_t i = 0; i < decoded_count; ++i) {
        ESP_LOGI(TAG_NDEF, "Record %u: TNF=%u TYPE_LEN=%u ID_LEN=%u PAYLOAD_LEN=%u", (unsigned)i, (unsigned)decoded[i].tnf, (unsigned)decoded[i].type_len,
                 (unsigned)decoded[i].id_len, (unsigned)decoded[i].payload_len);
    }

    free(encoded);
}
