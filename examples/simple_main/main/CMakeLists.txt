idf_component_register(
    SRCS "simple_main.c"
    PRIV_REQUIRES spi_flash driver esp_driver_spi esp_driver_gpio esp_timer
    INCLUDE_DIRS "."
)
