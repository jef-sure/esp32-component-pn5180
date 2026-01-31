#include "pn5180-ndef-tlv.h"

#define TLV_NULL       0x00
#define TLV_NDEF       0x03
#define TLV_TERMINATOR 0xFE

static size_t tlv_parse_length(const uint8_t *data, size_t data_len, size_t offset, size_t *value_offset)
{
    if (offset >= data_len) {
        *value_offset = 0;
        return 0;
    }

    if (data[offset] == 0xFF) {
        if (offset + 3 > data_len) {
            *value_offset = 0;
            return 0;
        }
        *value_offset = offset + 3;
        return ((size_t)data[offset + 1] << 8) | data[offset + 2];
    }
    *value_offset = offset + 1;
    return data[offset];
}

bool ndef_tlv_find_ndef(const uint8_t *data, size_t data_len, size_t *search_pos, size_t *ndef_offset, size_t *ndef_length)
{
    size_t i = *search_pos;
    while (i < data_len) {
        uint8_t type = data[i];

        if (type == TLV_NULL) {
            i++;
            continue;
        }
        if (type == TLV_TERMINATOR) {
            *search_pos = i;
            return false;
        }

        if (i + 1 >= data_len) {
            *search_pos = i;
            return false;
        }

        size_t value_offset;
        size_t length = tlv_parse_length(data, data_len, i + 1, &value_offset);

        if (value_offset == 0) {
            *search_pos = i;
            return false;
        }

        if (type == TLV_NDEF) {
            *ndef_offset = value_offset;
            *ndef_length = length;
            *search_pos  = i;
            return true;
        }

        if (value_offset + length > data_len) {
            *search_pos = i;
            return false;
        }

        i = value_offset + length;
    }
    *search_pos = i;
    return false;
}
