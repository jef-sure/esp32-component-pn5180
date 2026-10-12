# IDF 5.3 split "driver" into esp_driver_*; older versions have only "driver".
if(IDF_VERSION_MAJOR GREATER 5 OR (IDF_VERSION_MAJOR EQUAL 5 AND IDF_VERSION_MINOR GREATER_EQUAL 3))
    set(example_driver_requires esp_driver_spi esp_driver_gpio)
else()
    set(example_driver_requires "")
endif()

# Inside the repository the component has the name of the repository directory. Outside
# of it the component manager adds the requirement from idf_component.yml.
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../../../include/pn5180.h")
    get_filename_component(example_pn5180_requires "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
    get_filename_component(example_pn5180_requires "${example_pn5180_requires}" NAME)
else()
    set(example_pn5180_requires "")
endif()

idf_component_register(
    SRCS "app_logic.c"
    PRIV_REQUIRES spi_flash driver ${example_driver_requires} esp_timer ${example_pn5180_requires}
    INCLUDE_DIRS "."
)
