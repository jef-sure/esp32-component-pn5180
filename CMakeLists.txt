# IDF 5.3 split "driver" into esp_driver_*; older versions have only "driver". The public header
# pn5180.h includes driver/gpio.h and driver/spi_master.h, so they are public requirements: since
# IDF 6.0 "driver" no longer passes esp_driver_gpio and esp_driver_spi on to the components that
# require it. "driver" itself stays, as before, for components that took it over from here.
if(IDF_VERSION_MAJOR GREATER 5 OR (IDF_VERSION_MAJOR EQUAL 5 AND IDF_VERSION_MINOR GREATER_EQUAL 3))
    set(pn5180_driver_requires esp_driver_spi esp_driver_gpio)
else()
    set(pn5180_driver_requires "")
endif()

idf_component_register(
    SRCS "src/pn5180-14443.c" "src/pn5180-apdu.c" "src/pn5180-15693.c" "src/pn5180-mifare.c" "src/pn5180-ndef-tlv.c" "src/pn5180.c" "src/pn5180-ndef.c" "src/pn5180-ndef-auto.c"
    REQUIRES driver ${pn5180_driver_requires}
    PRIV_REQUIRES esp_timer
    INCLUDE_DIRS "include"
)
