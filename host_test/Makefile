# Host tests for the PN5180 driver: no hardware and no ESP-IDF build needed.
# The Unity test framework is taken from an ESP-IDF checkout:
#   make test IDF_PATH=~/.espressif/v5.5.4/esp-idf
# or run it from a shell where ESP-IDF is activated. Without ESP-IDF, point
# UNITY_DIR at the src directory of a Unity checkout:
#   make test UNITY_DIR=~/Unity/src
#
# Two programs:
#   pn5180_host_test  the protocol code (ISO14443, ISO15693, MIFARE, NDEF) against simulated
#                     cards; src/pn5180.c, the reader layer, is replaced by fake_pn5180.c.
#   pn5180_chip_test  src/pn5180.c itself, against stand-ins of the ESP-IDF SPI master, GPIO,
#                     esp_timer and semaphores and a model of the PN5180 behind them (chip_sim.c).

ifeq ($(strip $(UNITY_DIR)),)
ifeq ($(strip $(IDF_PATH)),)
$(error IDF_PATH is not set: activate ESP-IDF, pass IDF_PATH=<path to esp-idf> or UNITY_DIR=<path to Unity/src>)
endif
UNITY_DIR := $(IDF_PATH)/components/unity/unity/src
endif
BUILD_DIR ?= build

DRIVER_SRCS := ../src/pn5180-14443.c ../src/pn5180-15693.c ../src/pn5180-mifare.c ../src/pn5180-apdu.c \
               ../src/pn5180-ndef.c ../src/pn5180-ndef-tlv.c ../src/pn5180-ndef-auto.c
TEST_SRCS   := test_main.c fake_pn5180.c sim_cards.c $(UNITY_DIR)/unity.c

CHIP_SRCS      := ../src/pn5180.c
CHIP_TEST_SRCS := test_chip.c chip_sim.c $(UNITY_DIR)/unity.c

CFLAGS += -std=gnu11 -g -O1 -Wall -Wno-unused-function -fsanitize=address,undefined -fno-sanitize-recover=undefined
CFLAGS += -Istubs -I../include -I. -I$(UNITY_DIR)

HEADERS := $(wildcard *.h) $(wildcard stubs/*.h stubs/*/*.h) $(wildcard ../include/*.h)

$(BUILD_DIR)/pn5180_host_test: $(DRIVER_SRCS) $(TEST_SRCS) $(HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DRIVER_SRCS) $(TEST_SRCS) -o $@

$(BUILD_DIR)/pn5180_chip_test: $(CHIP_SRCS) $(CHIP_TEST_SRCS) $(HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CHIP_SRCS) $(CHIP_TEST_SRCS) -o $@

.PHONY: test clean
test: $(BUILD_DIR)/pn5180_host_test $(BUILD_DIR)/pn5180_chip_test
	$(BUILD_DIR)/pn5180_host_test
	$(BUILD_DIR)/pn5180_chip_test

clean:
	rm -rf $(BUILD_DIR)
