# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

# Inside the repository the component is the repository itself, whatever its directory
# is called, and the component manager is switched off. An example created with
# "idf.py create-project-from-example" has no repository above it and gets the
# component from the registry, as main/idf_component.yml asks.
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../../include/pn5180.h")
    set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../..")
    set(ENV{IDF_COMPONENT_MANAGER} "0")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(app_logic)
