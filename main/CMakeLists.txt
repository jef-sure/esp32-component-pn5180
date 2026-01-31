idf_component_register(
    SRCS "main.c" "app_logic.c" "ndef_test.c"
    PRIV_REQUIRES spi_flash driver esp_driver_spi esp_driver_gpio esp_timer pn5180
    INCLUDE_DIRS ""
)
