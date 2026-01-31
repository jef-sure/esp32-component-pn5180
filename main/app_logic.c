#include "app_logic.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_chip_info.h"
#include "esp_err.h"
#include "esp_flash.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pn5180-14443.h"
#include "pn5180-15693.h"
#include "pn5180-ndef.h"
#include "pn5180.h"
#include "sdkconfig.h"
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static const char *TAG = "main";

// Static globals for MIFARE Classic transparent authentication
static nfc_uid_t         *g_current_uid      = NULL;
static func_block_read_t *g_original_read    = NULL;
static int                g_last_auth_sector = -1;

enum
{
    PN5180_RST  = GPIO_NUM_12,
    PN5180_SCK  = GPIO_NUM_18,
    PN5180_MOSI = GPIO_NUM_23,
    PN5180_MISO = GPIO_NUM_19,
    PN5180_NSS  = GPIO_NUM_5,
    PN5180_BUSY = GPIO_NUM_21,
    PN5180_FREQ = 7000000,
};

static const uint8_t mifare_keys[][6] = {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    {0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0},
    {0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1},
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
    {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5},
    {0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD},
    {0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
    {0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97},
    {0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F},
    {0xA0, 0x47, 0x8C, 0xC3, 0x90, 0x91},
    {0x53, 0x3C, 0xB6, 0xC7, 0x23, 0xF6},
    {0x8F, 0xD0, 0xA4, 0xF2, 0x56, 0xE9},
};
static const uint8_t key_types[] = {MIFARE_CLASSIC_KEYA, MIFARE_CLASSIC_KEYB};

static const char *get_card_type_name(nfc_type_t subtype)
{
    switch (subtype) {
    case PN5180_MIFARE_CLASSIC_1K:
        return "MIFARE Classic 1K";
    case PN5180_MIFARE_CLASSIC_MINI:
        return "MIFARE Classic Mini";
    case PN5180_MIFARE_CLASSIC_4K:
        return "MIFARE Classic 4K";
    case PN5180_MIFARE_ULTRALIGHT:
        return "MIFARE Ultralight";
    case PN5180_MIFARE_ULTRALIGHT_C:
        return "MIFARE Ultralight C";
    case PN5180_MIFARE_ULTRALIGHT_EV1:
        return "MIFARE Ultralight EV1";
    case PN5180_MIFARE_NTAG213:
        return "NTAG213";
    case PN5180_MIFARE_NTAG215:
        return "NTAG215";
    case PN5180_MIFARE_NTAG216:
        return "NTAG216";
    case PN5180_MIFARE_PLUS_2K:
        return "MIFARE Plus 2K";
    case PN5180_MIFARE_PLUS_4K:
        return "MIFARE Plus 4K";
    case PN5180_MIFARE_DESFIRE:
        return "MIFARE DESFire";
    case PN5180_15693:
        return "ISO15693";
    default:
        return "Unknown";
    }
}

static bool requires_authentication(nfc_type_t subtype)
{
    return (subtype == PN5180_MIFARE_CLASSIC_1K || subtype == PN5180_MIFARE_CLASSIC_MINI || subtype == PN5180_MIFARE_CLASSIC_4K ||
            subtype == PN5180_MIFARE_PLUS_2K || subtype == PN5180_MIFARE_PLUS_4K);
}

static int get_sector_from_block(nfc_type_t subtype, int block)
{
    if (subtype == PN5180_MIFARE_CLASSIC_4K && block >= 128) {
        return 32 + (block - 128) / 16;
    } else {
        return block / 4;
    }
}

static int get_sector_first_block(nfc_type_t subtype, int sector)
{
    if (subtype == PN5180_MIFARE_CLASSIC_4K && sector >= 32) {
        return 128 + (sector - 32) * 16;
    } else {
        return sector * 4;
    }
}

static bool authenticate_sector(pn5180_proto_t *proto, nfc_uid_t *uid, int sector_block)
{
    if (proto->authenticate == NULL) {
        return false;
    }

    // Iterate through known keys to find a match
    for (size_t ki = 0; ki < ARRAY_SIZE(mifare_keys); ki++) {
        for (size_t kt = 0; kt < ARRAY_SIZE(key_types); kt++) {

            // Feed WDT at start of iteration
            vTaskDelay(pdMS_TO_TICKS(10));

            // CRITICAL: Ensure card is in Selected state before every Authentication attempt.
            // MIFARE Classic requires the AUTH command to immediately follow selection (or previous valid command).
            // Any intervening operations (like failed reads or previous failed auths) can break the state.

            // Clean state transition: HALT before Re-Selecting ensures WUPA works reliably
            if (proto->halt) {
                proto->halt(proto);
            }

            if (proto->select_by_uid && !proto->select_by_uid(proto, uid)) {
                // If we can't select, we certainly can't authenticate.
                continue;
            }

            if (proto->authenticate(proto, mifare_keys[ki], key_types[kt], uid, sector_block)) {
                int sector = get_sector_from_block(uid->subtype, sector_block);
                ESP_LOGI(TAG, "Sector %2d authenticated with key %zu (%s)", sector, ki, (key_types[kt] == MIFARE_CLASSIC_KEYA) ? "KeyA" : "KeyB");
                return true;
            }
            // If auth failed, loop continues. We must Re-Select in the next iteration.
        }
    }
    return false;
}

// Wrapper to transparently authenticate sectors during NDEF read
static bool smart_block_read(struct _pn5180_proto_t *proto, int blockno, uint8_t *buffer, size_t buffer_len)
{
    if (g_current_uid && requires_authentication(g_current_uid->subtype)) {
        int sector = get_sector_from_block(g_current_uid->subtype, blockno);
        if (sector != g_last_auth_sector) {
            int sector_block = get_sector_first_block(g_current_uid->subtype, sector);
            if (authenticate_sector(proto, g_current_uid, sector_block)) {
                g_last_auth_sector = sector;
            } else {
                ESP_LOGE(TAG, "SmartRead: Failed to authenticate sector %d", sector);
                return false;
            }
        }
    }
    if (g_original_read) {
        return g_original_read(proto, blockno, buffer, buffer_len);
    }
    return false;
}

static void print_block_data(int block, const uint8_t *data, int size)
{
    printf("    Block %3d: ", block);
    for (int i = 0; i < size; i++) {
        printf("%02X ", data[i]);
    }
    printf(" | ");
    for (int i = 0; i < size; i++) {
        printf("%c", isprint(data[i]) ? data[i] : '.');
    }
    printf("\n");
}

static void read_card_blocks(pn5180_proto_t *proto, nfc_uid_t *uid, int blocks_count, int block_size)
{
    if (blocks_count <= 0 || block_size <= 0 || proto->block_read == NULL) {
        return;
    }

    printf("  Reading all blocks:\n");
    uint8_t  small_block_data[16];
    uint8_t *block_data = block_size < 16 ? small_block_data : malloc(block_size);
    if (block_data == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for block data");
        return;
    }

    bool needs_auth          = requires_authentication(uid->subtype);
    int  current_sector      = -1;
    bool stop_after_fail     = false;
    int  continuous_failures = 0;

    for (int block = 0; block < blocks_count; block++) {
        if (stop_after_fail || continuous_failures >= 5) {
            break;
        }

        if (needs_auth) {
            int sector = get_sector_from_block(uid->subtype, block);

            if (sector != current_sector) {
                int sector_block = get_sector_first_block(uid->subtype, sector);

                if (!authenticate_sector(proto, uid, sector_block)) {
                    ESP_LOGW(TAG, "Block %3d: Authentication failed (keys unknown)", block);
                    stop_after_fail = true;
                    continue;
                }
                current_sector = sector;
            }
        }

        if (proto->block_read(proto, block, block_data, block_size)) {
            print_block_data(block, block_data, block_size);
        } else {
            ESP_LOGW(TAG, "Block %3d: Read failed", block);
            if (proto->block_read(proto, block, block_data, block_size)) {
                ESP_LOGI(TAG, "Block %3d: Read succeeded on retry", block);
                print_block_data(block, block_data, block_size);
            } else {
                ++continuous_failures;
                ESP_LOGW(TAG, "Block %3d: Read failed on retry - skipping block", block);
                if (needs_auth) {
                    current_sector = -1;
                }
                pn5180_delay_ms(5);
            }
        }
    }
    if (block_data != small_block_data) free(block_data);
}

static void process_card(pn5180_proto_t *proto, nfc_uid_t *uid)
{
    printf("UID Length=%d, UID=", uid->uid_length);
    for (int j = 0; j < uid->uid_length; j++) {
        printf("%02X ", uid->uid[j]);
    }
    printf("\n");

    if (!proto->select_by_uid(proto, uid)) {
        ESP_LOGE(TAG, "Failed to select card");
        return;
    }

    int  blocks_count   = 0;
    int  block_size     = 0;
    bool needs_reselect = proto->detect_card_type_and_capacity(proto->pn5180, uid, &blocks_count, &block_size);

    if (needs_reselect) {
        if (!proto->select_by_uid(proto, uid)) {
            ESP_LOGE(TAG, "Failed to reselect card after type detection");
            return;
        }
    }

    printf("  Type: %s\n", get_card_type_name(uid->subtype));
    printf("  Blocks: %d, Block size: %d bytes\n", blocks_count, block_size);

    int start_block = (uid->subtype == PN5180_15693) ? 1 : 4;

    // Set up smart reader context
    g_current_uid      = uid;
    g_original_read    = proto->block_read;
    g_last_auth_sector = -1;
    // Swap reader
    proto->block_read = smart_block_read;

    ndef_message_parsed_t *msg;
    ndef_result_t          result = ndef_read_from_selected_card(proto, start_block, block_size, 256 /* NDEF_DEFAULT_MAX_BLOCKS*/, &msg);

    // Restore reader
    proto->block_read = g_original_read;
    g_original_read   = NULL;
    g_current_uid     = NULL;

    if (result != NDEF_OK) {
        ESP_LOGE(TAG, "Failed to read NDEF message");
        if (uid->subtype != PN5180_MIFARE_DESFIRE) {
            read_card_blocks(proto, uid, blocks_count, block_size);
        }
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
    }
}

static bool read_version(pn5180_t *pn5180, uint8_t addr, const char *name)
{
    uint8_t version[2];
    if (!pn5180_readEEprom(pn5180, addr, version, sizeof(version))) {
        ESP_LOGE(TAG, "Failed to read %s", name);
        return false;
    }

    ESP_LOGI(TAG, "%s: %d.%d", name, version[1], version[0]);

    if (addr == PRODUCT_VERSION && version[1] == 0xff) {
        ESP_LOGE(TAG, "Initialization failed - invalid product version");
        return false;
    }

    return true;
}

static bool init_pn5180_hardware(pn5180_t **pn5180_out)
{
    pn5180_spi_t *spi = pn5180_spi_init(VSPI_HOST, PN5180_SCK, PN5180_MISO, PN5180_MOSI, PN5180_FREQ);
    if (spi == NULL) {
        ESP_LOGE(TAG, "Failed to initialize PN5180 SPI");
        return false;
    }

    pn5180_t *pn5180 = pn5180_init(spi, PN5180_NSS, PN5180_BUSY, PN5180_RST);
    if (pn5180 == NULL) {
        ESP_LOGE(TAG, "Failed to initialize PN5180");
        return false;
    }

    ESP_LOGI(TAG, "PN5180 initialized successfully");

    if (!read_version(pn5180, PRODUCT_VERSION, "Product version") || !read_version(pn5180, FIRMWARE_VERSION, "Firmware version") ||
        !read_version(pn5180, EEPROM_VERSION, "EEPROM version")) {
        pn5180_deinit(pn5180, true);
        return false;
    }

    *pn5180_out = pn5180;
    return true;
}

static void scan_protocol(pn5180_proto_t *proto, const char *label, uint8_t rf_config)
{
    ESP_LOGI(TAG, "Scanning for %s cards...", label);

    proto->pn5180->rf_config = rf_config;

    pn5180_setRF_off(proto->pn5180);
    pn5180_delay_ms(5);
    esp_rom_delay_us(1000);
    if (!proto->setup_rf(proto)) {
        ESP_LOGE(TAG, "Failed to set up RF for %s", label);
        return;
    }

    nfc_uids_array_t *uids = proto->get_all_uids(proto);
    if (uids == NULL) {
        ESP_LOGI(TAG, "No cards found");
        return;
    }

    ESP_LOGI(TAG, "Found %d card(s)", uids->uids_count);
    for (int i = 0; i < uids->uids_count; i++) {
        printf("Card %d UID: ", i + 1);
        for (int j = 0; j < uids->uids[i].uid_length; j++) {
            printf("%02X ", uids->uids[i].uid[j]);
        }
        printf(" | AGC: %u\n", uids->uids[i].agc);
    }
    for (int i = 0; i < uids->uids_count; i++) {
        printf("Card %d: ", i + 1);
        process_card(proto, &uids->uids[i]);
        printf("\n");
    }
    free(uids);
}

static void scan_loop(pn5180_proto_t *proto_14443, pn5180_proto_t *proto_15693)
{
    while (true) {
        ESP_LOGD(TAG, "Free heap before scanning: %lu", esp_get_free_heap_size());

        scan_protocol(proto_14443, "ISO14443A", 0x00);
        scan_protocol(proto_15693, "ISO15693", PN5180_15693_26KASK100);

        pn5180_delay_ms(2000);
        ESP_LOGD(TAG, "Free heap after scanning: %lu", esp_get_free_heap_size());
        assert(heap_caps_check_integrity_all(true));
    }
}

void app_run(void)
{
    pn5180_t *pn5180 = NULL;
    if (!init_pn5180_hardware(&pn5180)) {
        ESP_LOGE(TAG, "Hardware initialization failed");
        return;
    }

    pn5180_proto_t *proto_14443 = pn5180_14443_init(pn5180);
    if (proto_14443 == NULL) {
        ESP_LOGE(TAG, "Failed to initialize ISO14443 protocol");
        pn5180_deinit(pn5180, true);
        return;
    }
    ESP_LOGI(TAG, "ISO14443 protocol initialized successfully");

    pn5180_proto_t *proto_15693 = pn5180_15693_init(pn5180, PN5180_15693_26KASK100);
    if (proto_15693 == NULL) {
        ESP_LOGE(TAG, "Failed to initialize ISO15693 protocol");
        pn5180_deinit(pn5180, true);
        return;
    }
    ESP_LOGI(TAG, "ISO15693 protocol initialized successfully");

    scan_loop(proto_14443, proto_15693);
}
