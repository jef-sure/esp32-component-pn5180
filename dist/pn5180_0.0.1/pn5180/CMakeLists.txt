idf_component_register(
    SRCS "src/pn5180-14443.c" "src/pn5180-15693.c" "src/pn5180-mifare.c" "src/pn5180-ndef-tlv.c" "src/pn5180.c" "src/pn5180-ndef.c"
    PRIV_REQUIRES driver esp_driver_spi esp_driver_gpio esp_timer
    INCLUDE_DIRS "include"
)
