#include "esp_log.h"
#include "pn5180-14443.h"
#include "pn5180-15693.h"
#include "pn5180.h"
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "main";

enum {
    PN5180_RST  = GPIO_NUM_12,
    PN5180_SCK  = GPIO_NUM_18,
    PN5180_MOSI = GPIO_NUM_23,
    PN5180_MISO = GPIO_NUM_19,
    PN5180_NSS  = GPIO_NUM_5,
    PN5180_BUSY = GPIO_NUM_21,
    PN5180_FREQ = 7000000,
};

static bool read_version(pn5180_t *pn5180, uint8_t addr, const char *name) {
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

static bool init_pn5180_hardware(pn5180_t **pn5180_out) {
  pn5180_spi_t *spi = pn5180_spi_init(VSPI_HOST, PN5180_SCK, PN5180_MISO,
                                      PN5180_MOSI, PN5180_FREQ);
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

  if (!read_version(pn5180, PRODUCT_VERSION, "Product version") ||
      !read_version(pn5180, FIRMWARE_VERSION, "Firmware version") ||
      !read_version(pn5180, EEPROM_VERSION, "EEPROM version")) {
    pn5180_deinit(pn5180, true);
    return false;
  }

  *pn5180_out = pn5180;
  return true;
}

static void scan_protocol(pn5180_proto_t *proto, const char *label,
                          uint8_t rf_config) {
  ESP_LOGI(TAG, "Scanning for %s cards...", label);

  proto->pn5180->rf_config = rf_config;

  pn5180_setRF_off(proto->pn5180);
  pn5180_delay_ms(5);
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
    printf("%s card %d UID: ", label, i + 1);
    for (int j = 0; j < uids->uids[i].uid_length; j++) {
      printf("%02X ", uids->uids[i].uid[j]);
    }
    printf("| AGC: %u\n", uids->uids[i].agc);
  }

  free(uids);
}

void app_main(void) {
  printf("Hello world!\n");
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

  pn5180_proto_t *proto_15693 =
      pn5180_15693_init(pn5180, PN5180_15693_26KASK100);
  if (proto_15693 == NULL) {
    ESP_LOGE(TAG, "Failed to initialize ISO15693 protocol");
    pn5180_deinit(pn5180, true);
    return;
  }
  ESP_LOGI(TAG, "ISO15693 protocol initialized successfully");

  while (true) {
    scan_protocol(proto_14443, "ISO14443A", 0x00);
    scan_protocol(proto_15693, "ISO15693", PN5180_15693_26KASK100);

    pn5180_delay_ms(2000);
  }
}
