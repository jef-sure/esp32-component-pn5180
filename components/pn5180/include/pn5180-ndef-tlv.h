#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Find the NDEF TLV in a byte buffer
 * @param data Input buffer containing TLV data
 * @param data_len Length of input buffer in bytes
 * @param search_pos In/out position for continuing a scan across chunks
 * @param ndef_offset Out: offset to NDEF value field within data
 * @param ndef_length Out: length of NDEF value field
 * @return true if an NDEF TLV was found and offsets are valid
 */
bool ndef_tlv_find_ndef(        //
    const uint8_t *data,        //
    size_t         data_len,    //
    size_t        *search_pos,  //
    size_t        *ndef_offset, //
    size_t        *ndef_length  //
);
