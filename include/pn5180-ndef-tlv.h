#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Find the NDEF TLV in a byte buffer
 * @param data Input buffer containing TLV data
 * @param data_len Length of input buffer in bytes
 * @param search_pos In/out position for continuing a scan across chunks
 * @param ndef_offset Out: offset to NDEF value field within data
 * @param ndef_length Out: length of NDEF value field, as the TLV declares it
 * @return true if the type and length of an NDEF TLV were found. The value may still run past
 *         the end of data (ndef_offset + ndef_length > data_len) when data holds only the first
 *         part of the tag's memory: check that before reading the value, or read more data and
 *         call again. false if there is no complete NDEF TLV header (yet), or a Terminator TLV
 *         came first; *search_pos then points at the TLV where the search stopped.
 */
bool pn5180_ndef_tlv_find_ndef(        //
    const uint8_t *data,        //
    size_t         data_len,    //
    size_t        *search_pos,  //
    size_t        *ndef_offset, //
    size_t        *ndef_length  //
);

#ifdef __cplusplus
}
#endif
