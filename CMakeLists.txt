# IDF 5.3 split "driver" into esp_driver_*; older versions have only "driver".
if(IDF_VERSION_MAJOR GREATER 5 OR (IDF_VERSION_MAJOR EQUAL 5 AND IDF_VERSION_MINOR GREATER_EQUAL 3))
    set(pn5180_driver_requires esp_driver_spi esp_driver_gpio)
else()
    set(pn5180_driver_requires "")
endif()

idf_component_register(
    SRCS "src/pn5180-14443.c" "src/pn5180-apdu.c" "src/pn5180-15693.c" "src/pn5180-mifare.c" "src/pn5180-ndef-tlv.c" "src/pn5180.c" "src/pn5180-ndef.c" "src/pn5180-ndef-auto.c"
    REQUIRES driver
    PRIV_REQUIRES ${pn5180_driver_requires} esp_timer
    INCLUDE_DIRS "include"
)
