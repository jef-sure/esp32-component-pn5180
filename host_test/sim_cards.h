#pragma once
/**
 * @file sim_cards.h
 * @brief Simulated cards for the host tests
 *
 * Each simulator answers the frames the driver transmits the way the PN5180 would report the
 * card's answer: without CRC bytes, with 4-bit ACK/NAK frames reported as a 1-byte RX error.
 * The behaviour follows the card datasheets (MF0ICU1, MF0ICU2, SL2S2602) and ISO/IEC 14443-3/-4:
 * in particular a card leaves the selected state after a NAK, and ignores REQA/WUPA while selected.
 */
#include "fake_pn5180.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- ISO14443A card ---- */

typedef enum
{
    SIM_A_IDLE,
    SIM_A_READY,
    SIM_A_ACTIVE,
    SIM_A_PROTOCOL, /**< ISO14443-4 activated */
    SIM_A_HALT
} sim_a_state_t;

typedef enum
{
    SIM_A_TYPE2,   /**< Ultralight / NTAG memory card */
    SIM_A_CLASSIC, /**< MIFARE Classic */
    SIM_A_ISO_DEP  /**< ISO14443-4 card with a Type 4 NDEF application */
} sim_a_kind_t;

typedef struct
{
    sim_a_kind_t  kind;
    sim_a_state_t state;
    uint8_t       uid[10];
    int           uid_len; /**< 4 or 7 */
    uint8_t       sak;
    uint8_t       atqa[2];
    int           cascade_done; /**< cascade levels selected so far */

    /* Type 2 */
    uint8_t memory[1024];    /**< pages of 4 bytes */
    int     page_count;      /**< pages that READ decodes */
    bool    has_get_version; /**< answers GET_VERSION (EV1 / NTAG) */
    uint8_t version[8];      /**< GET_VERSION answer */
    bool    is_ultralight_c; /**< answers AUTHENTICATE 1Ah with a challenge */
    bool    compat_write_pending;
    uint8_t compat_write_page;

    /* Classic: 16-byte blocks in memory[], key A per sector */
    uint8_t sector_key_a[40][6];
    int     auth_sector; /**< authenticated sector, -1 if none */
    uint8_t pending_cmd; /**< two-part command waiting for its second frame, 0 if none */
    uint8_t pending_block;
    uint8_t transfer_buffer[16];

    /* ISO14443-4 */
    uint8_t ats_fsci;     /**< frame size the card announces */
    size_t  picc_max_inf; /**< INF bytes per block the card sends */
    uint8_t block_number;
    uint8_t last_tx[300]; /**< last block sent, for retransmission */
    size_t  last_tx_len;
    uint8_t command[600]; /**< command APDU being received (chained) */
    size_t  command_len;
    uint8_t response[600]; /**< response APDU being sent (chained) */
    size_t  response_len;
    size_t  response_offset;
    bool    response_pending_after_wtx;
    int     drop_responses; /**< next N answers are lost on the way to the reader */
    int     drop_commands;  /**< next N commands are not received by the card */
    int     wtx_requests;   /**< next N APDUs are preceded by a waiting time extension request */
    int     deselect_count;
    int     rats_count;
    /* Type 4 application */
    uint8_t cc_file[15];
    uint8_t ndef_file[600];
    size_t  ndef_file_len;
    int     selected_file; /**< 0 none, 1 CC, 2 NDEF */
    bool    app_selected;
    bool    refuse_select_p2_0c; /**< mapping version 1.0 card: wants P2=00 */
    uint8_t last_apdu[600];      /**< last complete command APDU, for inspection */
    size_t  last_apdu_len;
} sim_a_card_t;

void sim_a_init_ntag213(sim_a_card_t *card);
void sim_a_init_ultralight(sim_a_card_t *card, bool ultralight_c);
void sim_a_init_classic_1k(sim_a_card_t *card);
void sim_a_init_iso_dep(sim_a_card_t *card, uint8_t sak, uint8_t ats_fsci);

/** Formats a Classic card as NDEF tag: MAD in sector 0, NDEF keys, message in sectors 1.. */
void sim_a_classic_store_ndef(sim_a_card_t *card, const uint8_t *ndef, size_t ndef_len);
/** Stores an NDEF message in the Type 4 NDEF file. */
void sim_a_iso_dep_store_ndef(sim_a_card_t *card, const uint8_t *ndef, size_t ndef_len);

pn5180_rf_result_t sim_a_card(void *ctx, const uint8_t *tx, size_t tx_len, uint8_t tx_last_bits, uint8_t *rx, size_t rx_size, size_t *rx_len,
                              uint32_t timeout_us, uint32_t *rx_status);
int16_t            sim_a_auth(void *ctx, uint8_t blockno, const uint8_t *key, uint8_t key_type, const uint8_t uid[4]);

/* ---- ISO15693 tag ---- */

typedef struct
{
    uint8_t uid[8];
    uint8_t memory[1024];
    int     block_size;
    int     block_count;
    bool    quiet;
    bool    selected;
    bool    supports_reset_to_ready;
} sim_v_card_t;

void               sim_v_init(sim_v_card_t *card);
pn5180_rf_result_t sim_v_card(void *ctx, const uint8_t *tx, size_t tx_len, uint8_t tx_last_bits, uint8_t *rx, size_t rx_size, size_t *rx_len,
                              uint32_t timeout_us, uint32_t *rx_status);
