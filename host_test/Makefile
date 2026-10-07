# Host tests for the PN5180 protocol code: no hardware and no ESP-IDF build needed.
# The Unity test framework is taken from an ESP-IDF checkout:
#   make IDF_PATH=~/.espressif/v5.5.4/esp-idf
# or run it from a shell where ESP-IDF is activated.

ifeq ($(strip $(IDF_PATH)),)
$(error IDF_PATH is not set: activate ESP-IDF or pass IDF_PATH=<path to esp-idf>)
endif

UNITY_DIR := $(IDF_PATH)/components/unity/unity/src
BUILD_DIR ?= build

# src/pn5180.c is the reader layer and is replaced by fake_pn5180.c.
DRIVER_SRCS := ../src/pn5180-14443.c ../src/pn5180-15693.c ../src/pn5180-mifare.c ../src/pn5180-apdu.c \
               ../src/pn5180-ndef.c ../src/pn5180-ndef-tlv.c ../src/pn5180-ndef-auto.c
TEST_SRCS   := test_main.c fake_pn5180.c sim_cards.c $(UNITY_DIR)/unity.c

CFLAGS += -std=gnu11 -g -O1 -Wall -Wno-unused-function -fsanitize=address,undefined -fno-sanitize-recover=undefined
CFLAGS += -Istubs -I../include -I. -I$(UNITY_DIR)

$(BUILD_DIR)/pn5180_host_test: $(DRIVER_SRCS) $(TEST_SRCS) $(wildcard *.h) $(wildcard ../include/*.h)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DRIVER_SRCS) $(TEST_SRCS) -o $@

.PHONY: test clean
test: $(BUILD_DIR)/pn5180_host_test
	$(BUILD_DIR)/pn5180_host_test

clean:
	rm -rf $(BUILD_DIR)
