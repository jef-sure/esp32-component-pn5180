#include "sim_cards.h"
#include <string.h>

/* ---- Helpers ---- */

static pn5180_rf_result_t answer(uint8_t *rx, size_t rx_size, size_t *rx_len, const uint8_t *data, size_t count)
{
    if (count > rx_size) {
        count = rx_size;
    }
    memcpy(rx, data, count);
    *rx_len = count;
    return PN5180_RF_OK;
}

// A card that leaves the selected state goes back to the waiting state it was woken from.
static void sim_a_leave_selected_state(sim_a_card_t *card, bool to_halt)
{
    card->state                = to_halt ? SIM_A_HALT : SIM_A_IDLE;
    card->cascade_done         = 0;
    card->auth_sector          = -1;
    card->pending_cmd          = 0;
    card->compat_write_pending = false;
}

// 4-bit acknowledge. With RX CRC enabled the PN5180 reports such a frame as a 1-byte RX error.
static pn5180_rf_result_t sim_a_ack(uint8_t *rx, size_t *rx_len)
{
    rx[0]   = 0x0A;
    *rx_len = 1;
    return PN5180_RF_RX_ERROR;
}

// 4-bit negative acknowledge; the card resets to its waiting state afterwards.
static pn5180_rf_result_t sim_a_nak(sim_a_card_t *card, uint8_t *rx, size_t *rx_len)
{
    rx[0]   = 0x00;
    *rx_len = 1;
    sim_a_leave_selected_state(card, false);
    return PN5180_RF_RX_ERROR;
}

static int sim_a_cascade_levels(const sim_a_card_t *card)
{
    return (card->uid_len == 4) ? 1 : ((card->uid_len == 7) ? 2 : 3);
}

// UID part and BCC transmitted at one cascade level
static void sim_a_cascade_bytes(const sim_a_card_t *card, int level, uint8_t out[5])
{
    int offset = (level - 1) * 3;
    if (level < sim_a_cascade_levels(card)) {
        out[0] = 0x88; // cascade tag
        memcpy(&out[1], &card->uid[offset], 3);
    } else {
        memcpy(out, &card->uid[offset], 4);
    }
    out[4] = out[0] ^ out[1] ^ out[2] ^ out[3];
}

/* ---- Type 2 (Ultralight / NTAG) ---- */

static pn5180_rf_result_t sim_a_type2(sim_a_card_t *card, const uint8_t *tx, size_t tx_len, uint8_t *rx, size_t rx_size, size_t *rx_len)
{
    if (card->compat_write_pending) {
        card->compat_write_pending = false;
        if (tx_len != 16) {
            return sim_a_nak(card, rx, rx_len);
        }
        memcpy(&card->memory[card->compat_write_page * 4], tx, 4);
        return sim_a_ack(rx, rx_len);
    }
    if (card->pending_cmd == 0x1A) {
        // An authentication that is not continued is an error.
        card->pending_cmd = 0;
        if (tx[0] != 0xAF) {
            sim_a_leave_selected_state(card, false);
            return PN5180_RF_TIMEOUT;
        }
    }

    switch (tx[0]) {
    case 0x30: { // READ: four pages, wrapping to page 0 after the last one
        if (tx_len != 2 || tx[1] >= card->page_count) {
            return sim_a_nak(card, rx, rx_len);
        }
        uint8_t data[16];
        for (int i = 0; i < 4; i++) {
            int page = (tx[1] + i) % card->page_count;
            memcpy(&data[i * 4], &card->memory[page * 4], 4);
        }
        return answer(rx, rx_size, rx_len, data, sizeof(data));
    }
    case 0xA2: // WRITE
        if (tx_len != 6 || tx[1] < 2 || tx[1] >= card->page_count) {
            return sim_a_nak(card, rx, rx_len);
        }
        memcpy(&card->memory[tx[1] * 4], &tx[2], 4);
        return sim_a_ack(rx, rx_len);
    case 0xA0: // COMPATIBILITY WRITE, first part
        if (tx_len != 2 || tx[1] < 2 || tx[1] >= card->page_count) {
            return sim_a_nak(card, rx, rx_len);
        }
        card->compat_write_pending = true;
        card->compat_write_page    = tx[1];
        return sim_a_ack(rx, rx_len);
    case 0x60: // GET_VERSION
        if (tx_len != 1 || !card->has_get_version) {
            return sim_a_nak(card, rx, rx_len);
        }
        return answer(rx, rx_size, rx_len, card->version, sizeof(card->version));
    case 0x1A: { // AUTHENTICATE (Ultralight C)
        if (tx_len != 2 || !card->is_ultralight_c) {
            return sim_a_nak(card, rx, rx_len);
        }
        const uint8_t challenge[9] = {0xAF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
        card->pending_cmd          = 0x1A;
        return answer(rx, rx_size, rx_len, challenge, sizeof(challenge));
    }
    default:
        return sim_a_nak(card, rx, rx_len);
    }
}

/* ---- MIFARE Classic ---- */

static int sim_a_classic_sector(int block)
{
    return (block < 128) ? (block / 4) : (32 + (block - 128) / 16);
}

static bool sim_a_classic_is_trailer(int block)
{
    return (block < 128) ? ((block % 4) == 3) : ((block % 16) == 15);
}

static bool sim_a_classic_decode_value(const uint8_t *block, uint32_t *value)
{
    uint32_t v0  = (uint32_t)block[0] | ((uint32_t)block[1] << 8) | ((uint32_t)block[2] << 16) | ((uint32_t)block[3] << 24);
    uint32_t inv = (uint32_t)block[4] | ((uint32_t)block[5] << 8) | ((uint32_t)block[6] << 16) | ((uint32_t)block[7] << 24);
    uint32_t v2  = (uint32_t)block[8] | ((uint32_t)block[9] << 8) | ((uint32_t)block[10] << 16) | ((uint32_t)block[11] << 24);
    if (v0 != v2 || v0 != (uint32_t)~inv) {
        return false;
    }
    *value = v0;
    return true;
}

int16_t sim_a_auth(void *ctx, uint8_t blockno, const uint8_t *key, uint8_t key_type, const uint8_t uid[4])
{
    sim_a_card_t *card = ctx;
    (void)uid;
    if (card->kind != SIM_A_CLASSIC || card->state != SIM_A_ACTIVE) {
        return 0x02; // no answer
    }
    int sector = sim_a_classic_sector(blockno);
    if (key_type == 0x60 && memcmp(key, card->sector_key_a[sector], 6) == 0) {
        card->auth_sector = sector;
        card->pending_cmd = 0;
        return 0;
    }
    // Wrong key: the card stops answering until it is selected again.
    sim_a_leave_selected_state(card, false);
    return 0x01;
}

static pn5180_rf_result_t sim_a_classic(sim_a_card_t *card, const uint8_t *tx, size_t tx_len, uint8_t *rx, size_t rx_size, size_t *rx_len)
{
    if (card->pending_cmd == 0xA0) { // data of a WRITE
        card->pending_cmd = 0;
        if (tx_len != 16) {
            return sim_a_nak(card, rx, rx_len);
        }
        if (sim_a_classic_is_trailer(card->pending_block)) {
            memcpy(card->sector_key_a[sim_a_classic_sector(card->pending_block)], tx, 6);
        }
        memcpy(&card->memory[card->pending_block * 16], tx, 16);
        return sim_a_ack(rx, rx_len);
    }
    if (card->pending_cmd == 0xC0 || card->pending_cmd == 0xC1 || card->pending_cmd == 0xC2) { // operand of a value operation
        uint8_t  cmd      = card->pending_cmd;
        uint8_t *source   = &card->memory[card->pending_block * 16];
        uint32_t value    = 0;
        card->pending_cmd = 0;
        if (tx_len != 4 || !sim_a_classic_decode_value(source, &value)) {
            return sim_a_nak(card, rx, rx_len);
        }
        uint32_t delta = (uint32_t)tx[0] | ((uint32_t)tx[1] << 8) | ((uint32_t)tx[2] << 16) | ((uint32_t)tx[3] << 24);
        if (cmd == 0xC1) {
            value += delta;
        } else if (cmd == 0xC0) {
            value -= delta;
        }
        memcpy(card->transfer_buffer, source, 16);
        for (int i = 0; i < 4; i++) {
            card->transfer_buffer[i]     = (uint8_t)(value >> (8 * i));
            card->transfer_buffer[4 + i] = (uint8_t)(~value >> (8 * i));
            card->transfer_buffer[8 + i] = (uint8_t)(value >> (8 * i));
        }
        return PN5180_RF_TIMEOUT; // the operand is not acknowledged
    }

    if (tx_len != 2 || card->auth_sector != sim_a_classic_sector(tx[1])) {
        return sim_a_nak(card, rx, rx_len);
    }
    int block = tx[1];
    switch (tx[0]) {
    case 0x30: { // READ
        uint8_t data[16];
        memcpy(data, &card->memory[block * 16], 16);
        if (sim_a_classic_is_trailer(block)) {
            memset(data, 0, 6); // key A is never readable
        }
        return answer(rx, rx_size, rx_len, data, sizeof(data));
    }
    case 0xA0: // WRITE, first part
    case 0xC0: // DECREMENT
    case 0xC1: // INCREMENT
    case 0xC2: // RESTORE
        card->pending_cmd   = tx[0];
        card->pending_block = (uint8_t)block;
        return sim_a_ack(rx, rx_len);
    case 0xB0: // TRANSFER
        memcpy(&card->memory[block * 16], card->transfer_buffer, 16);
        return sim_a_ack(rx, rx_len);
    default:
        return sim_a_nak(card, rx, rx_len);
    }
}

/* ---- ISO14443-4 with a Type 4 NDEF application ---- */

static void sim_a_set_status(sim_a_card_t *card, size_t data_len, uint16_t sw)
{
    card->response[data_len]     = (uint8_t)(sw >> 8);
    card->response[data_len + 1] = (uint8_t)(sw & 0xFF);
    card->response_len           = data_len + 2;
    card->response_offset        = 0;
}

static void sim_a_process_apdu(sim_a_card_t *card)
{
    static const uint8_t ndef_aid[7] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    const uint8_t       *apdu        = card->command;
    size_t               len         = card->command_len;

    memcpy(card->last_apdu, apdu, len);
    card->last_apdu_len = len;

    if (len < 4) {
        sim_a_set_status(card, 0, 0x6700);
        return;
    }
    uint8_t ins = apdu[1];
    uint8_t p1  = apdu[2];
    uint8_t p2  = apdu[3];

    if (ins == 0xA4) { // SELECT
        size_t lc = (len > 4) ? apdu[4] : 0;
        if (len < 5 + lc) {
            sim_a_set_status(card, 0, 0x6700);
            return;
        }
        const uint8_t *id = &apdu[5];
        if (p1 == 0x04) {
            card->app_selected  = (lc == sizeof(ndef_aid) && memcmp(id, ndef_aid, lc) == 0);
            card->selected_file = 0;
            sim_a_set_status(card, 0, card->app_selected ? 0x9000 : 0x6A82);
            return;
        }
        if (!card->app_selected || lc != 2) {
            sim_a_set_status(card, 0, 0x6A82);
            return;
        }
        if (p2 == 0x0C && card->refuse_select_p2_0c) {
            sim_a_set_status(card, 0, 0x6A86);
            return;
        }
        if (id[0] == 0xE1 && id[1] == 0x03) {
            card->selected_file = 1;
        } else if (id[0] == card->cc_file[9] && id[1] == card->cc_file[10]) {
            card->selected_file = 2;
        } else {
            sim_a_set_status(card, 0, 0x6A82);
            return;
        }
        sim_a_set_status(card, 0, 0x9000);
        return;
    }

    if (ins == 0xB0) { // READ BINARY
        const uint8_t *file     = (card->selected_file == 1) ? card->cc_file : card->ndef_file;
        size_t         file_len = (card->selected_file == 1) ? sizeof(card->cc_file) : card->ndef_file_len;
        size_t         offset   = ((size_t)p1 << 8) | p2;
        size_t         le       = (len > 4 && apdu[4] != 0) ? apdu[4] : 256;
        if (card->selected_file == 0) {
            sim_a_set_status(card, 0, 0x6986);
            return;
        }
        if (offset > file_len) {
            sim_a_set_status(card, 0, 0x6B00);
            return;
        }
        if (le > file_len - offset) {
            le = file_len - offset;
        }
        memcpy(card->response, &file[offset], le);
        sim_a_set_status(card, le, 0x9000);
        return;
    }

    sim_a_set_status(card, 0, 0x6D00);
}

// Puts the next part of the response APDU into an I-block.
static size_t sim_a_response_block(sim_a_card_t *card, uint8_t *out)
{
    size_t count = card->response_len - card->response_offset;
    bool   more  = count > card->picc_max_inf;
    if (more) {
        count = card->picc_max_inf;
    }
    out[0] = (uint8_t)(0x02 | card->block_number | (more ? 0x10 : 0));
    memcpy(&out[1], &card->response[card->response_offset], count);
    card->response_offset += count;
    return 1 + count;
}

static pn5180_rf_result_t sim_a_iso_dep(sim_a_card_t *card, const uint8_t *tx, size_t tx_len, uint8_t *rx, size_t rx_size, size_t *rx_len)
{
    if (card->drop_commands > 0) {
        card->drop_commands--;
        return PN5180_RF_TIMEOUT;
    }

    uint8_t pcb = tx[0];
    uint8_t out[300];
    size_t  out_len = 0;

    if (card->sends_empty_chain && (pcb & 0xC0) != 0xC0) {
        // I-block with the chaining bit and no data, block number as the reader expects it
        if ((pcb & 0xC0) == 0x00) {
            card->block_number = pcb & 0x01;
        } else {
            card->block_number ^= 1;
        }
        const uint8_t empty = (uint8_t)(0x12 | card->block_number);
        return answer(rx, rx_size, rx_len, &empty, 1);
    }

    if ((pcb & 0xC0) == 0x00) { // I-block
        card->block_number ^= 1;
        if (card->command_len + tx_len - 1 > sizeof(card->command)) {
            return PN5180_RF_TIMEOUT;
        }
        memcpy(&card->command[card->command_len], &tx[1], tx_len - 1);
        card->command_len += tx_len - 1;
        if (pcb & 0x10) {
            out[0]  = (uint8_t)(0xA2 | card->block_number); // R(ACK): send the next part
            out_len = 1;
        } else {
            sim_a_process_apdu(card);
            card->command_len = 0;
            if (card->wtx_requests > 0) {
                card->wtx_requests--;
                card->response_pending_after_wtx = true;
                out[0]                           = 0xF2; // S(WTX) request
                out[1]                           = 0x02;
                out_len                          = 2;
            } else {
                out_len = sim_a_response_block(card, out);
            }
        }
    } else if ((pcb & 0xC0) == 0x80) { // R-block
        uint8_t number = pcb & 0x01;
        bool    is_nak = (pcb & 0x10) != 0;
        if (number == card->block_number) {
            // The reader did not get the last block: send it again.
            memcpy(out, card->last_tx, card->last_tx_len);
            out_len = card->last_tx_len;
        } else if (is_nak) {
            out[0]  = (uint8_t)(0xA2 | card->block_number);
            out_len = 1;
        } else {
            // R(ACK) for the previous block of a chained response
            if (card->response_offset >= card->response_len) {
                return PN5180_RF_TIMEOUT;
            }
            card->block_number ^= 1;
            out_len = sim_a_response_block(card, out);
        }
    } else if ((pcb & 0xF7) == 0xF2) { // S(WTX) response
        if (!card->response_pending_after_wtx) {
            return PN5180_RF_TIMEOUT;
        }
        if (card->wtx_requests > 0) {
            card->wtx_requests--; // still not ready: ask again
            out[0]  = 0xF2;
            out[1]  = 0x02;
            out_len = 2;
        } else {
            card->response_pending_after_wtx = false;
            out_len                          = sim_a_response_block(card, out);
        }
    } else if ((pcb & 0xF7) == 0xC2) { // S(DESELECT)
        card->deselect_count++;
        sim_a_leave_selected_state(card, true);
        const uint8_t deselect = 0xC2;
        return answer(rx, rx_size, rx_len, &deselect, 1);
    } else {
        return PN5180_RF_TIMEOUT;
    }

    memcpy(card->last_tx, out, out_len);
    card->last_tx_len = out_len;
    if (card->drop_responses > 0) {
        card->drop_responses--;
        return PN5180_RF_TIMEOUT;
    }
    return answer(rx, rx_size, rx_len, out, out_len);
}

/* ---- ISO14443A card: activation and dispatch ---- */

pn5180_rf_result_t sim_a_card(void *ctx, const uint8_t *tx, size_t tx_len, uint8_t tx_last_bits, uint8_t *rx, size_t rx_size, size_t *rx_len,
                              uint32_t timeout_us, uint32_t *rx_status)
{
    sim_a_card_t *card = ctx;
    (void)timeout_us;
    (void)rx_status;

    if (tx_len == 1 && tx_last_bits == 7) { // REQA / WUPA
        if (tx[0] != 0x26 && tx[0] != 0x52) {
            return PN5180_RF_TIMEOUT;
        }
        if (card->state != SIM_A_IDLE && card->state != SIM_A_HALT) {
            // A selected card treats the request as an error and falls back without answering.
            sim_a_leave_selected_state(card, false);
            return PN5180_RF_TIMEOUT;
        }
        if (card->state == SIM_A_HALT && tx[0] != 0x52) {
            return PN5180_RF_TIMEOUT; // a halted card only wakes on WUPA
        }
        card->state        = SIM_A_READY;
        card->cascade_done = 0;
        return answer(rx, rx_size, rx_len, card->atqa, 2);
    }

    switch (card->state) {
    case SIM_A_IDLE:
    case SIM_A_HALT:
        return PN5180_RF_TIMEOUT;

    case SIM_A_READY: {
        int     level = card->cascade_done + 1;
        uint8_t cl[5];
        sim_a_cascade_bytes(card, level, cl);
        if (tx_len >= 2 && tx[0] == 0x93 + 2 * (level - 1)) {
            if (tx_len == 2 && tx[1] == 0x20) { // anticollision: whole UID part requested
                return answer(rx, rx_size, rx_len, cl, sizeof(cl));
            }
            if (tx_len == 7 && tx[1] == 0x70 && memcmp(&tx[2], cl, 5) == 0) { // SELECT
                uint8_t sak = 0x04;                                           // UID not complete
                card->cascade_done++;
                if (card->cascade_done == sim_a_cascade_levels(card)) {
                    card->state = SIM_A_ACTIVE;
                    sak         = card->sak;
                }
                return answer(rx, rx_size, rx_len, &sak, 1);
            }
        }
        sim_a_leave_selected_state(card, false);
        return PN5180_RF_TIMEOUT;
    }

    case SIM_A_ACTIVE:
        if (tx_len == 2 && tx[0] == 0x50 && tx[1] == 0x00) { // HLTA
            sim_a_leave_selected_state(card, !card->ignores_hlta);
            return PN5180_RF_TIMEOUT;
        }
        if (card->kind == SIM_A_TYPE2) {
            return sim_a_type2(card, tx, tx_len, rx, rx_size, rx_len);
        }
        if (card->kind == SIM_A_CLASSIC) {
            return sim_a_classic(card, tx, tx_len, rx, rx_size, rx_len);
        }
        if (tx_len == 2 && tx[0] == 0xE0) { // RATS
            const uint8_t ats[5] = {0x05, (uint8_t)(0x70 | card->ats_fsci), 0x80, 0x81, 0x02};
            card->state          = SIM_A_PROTOCOL;
            card->block_number   = 1;
            card->command_len    = 0;
            card->response_len   = 0;
            card->rats_count++;
            return answer(rx, rx_size, rx_len, ats, sizeof(ats));
        }
        return sim_a_nak(card, rx, rx_len);

    case SIM_A_PROTOCOL:
        return sim_a_iso_dep(card, tx, tx_len, rx, rx_size, rx_len);
    }
    return PN5180_RF_TIMEOUT;
}

/* ---- Card factories ---- */

void sim_a_init_ntag213(sim_a_card_t *card)
{
    static const uint8_t uid[7]     = {0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6};
    static const uint8_t version[8] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03};
    memset(card, 0, sizeof(*card));
    card->kind    = SIM_A_TYPE2;
    card->uid_len = 7;
    memcpy(card->uid, uid, sizeof(uid));
    card->sak             = 0x00;
    card->atqa[0]         = 0x44;
    card->atqa[1]         = 0x00;
    card->page_count      = 45;
    card->has_get_version = true;
    memcpy(card->version, version, sizeof(version));
    card->auth_sector = -1;
    // Capability container: NDEF magic, version 1.0, 144 bytes of data area, read/write access
    const uint8_t cc[4] = {0xE1, 0x10, 0x12, 0x00};
    memcpy(&card->memory[3 * 4], cc, sizeof(cc));
    // Empty NDEF TLV followed by the terminator
    const uint8_t empty[3] = {0x03, 0x00, 0xFE};
    memcpy(&card->memory[4 * 4], empty, sizeof(empty));
}

void sim_a_init_ultralight(sim_a_card_t *card, bool ultralight_c)
{
    static const uint8_t uid[7] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    memset(card, 0, sizeof(*card));
    card->kind    = SIM_A_TYPE2;
    card->uid_len = 7;
    memcpy(card->uid, uid, sizeof(uid));
    card->sak             = 0x00;
    card->atqa[0]         = 0x44;
    card->atqa[1]         = 0x00;
    card->page_count      = ultralight_c ? 44 : 16;
    card->is_ultralight_c = ultralight_c;
    card->auth_sector     = -1;
}

void sim_a_init_classic_1k(sim_a_card_t *card)
{
    static const uint8_t uid[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    memset(card, 0, sizeof(*card));
    card->kind    = SIM_A_CLASSIC;
    card->uid_len = 4;
    memcpy(card->uid, uid, sizeof(uid));
    card->sak         = 0x08;
    card->atqa[0]     = 0x04;
    card->atqa[1]     = 0x00;
    card->auth_sector = -1;
    for (int sector = 0; sector < 16; sector++) {
        memset(card->sector_key_a[sector], 0xFF, 6); // transport configuration
        const uint8_t access[4] = {0xFF, 0x07, 0x80, 0x69};
        memcpy(&card->memory[(sector * 4 + 3) * 16 + 6], access, sizeof(access));
        memset(&card->memory[(sector * 4 + 3) * 16 + 10], 0xFF, 6);
    }
}

uint8_t sim_mad_crc(const uint8_t *data, size_t len)
{
    uint8_t crc = 0xC7; // preset
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            bool carry = (crc & 0x80) != 0;
            crc        = (uint8_t)(crc << 1);
            if (carry) {
                crc ^= 0x1D; // x^8 + x^4 + x^3 + x^2 + 1
            }
        }
    }
    return crc;
}

void sim_a_classic_store_ndef(sim_a_card_t *card, const uint8_t *ndef, size_t ndef_len)
{
    static const uint8_t key_mad[6]  = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
    static const uint8_t key_ndef[6] = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};

    // TLV stream: NDEF TLV (one-byte length, enough for the tests) and terminator
    uint8_t stream[15 * 48];
    size_t  stream_len = 0;
    memset(stream, 0, sizeof(stream));
    stream[stream_len++] = 0x03;
    stream[stream_len++] = (uint8_t)ndef_len;
    memcpy(&stream[stream_len], ndef, ndef_len);
    stream_len += ndef_len;
    stream[stream_len++] = 0xFE;

    int sectors_used = (int)((stream_len + 47) / 48);

    // MAD1 in blocks 1 and 2: CRC, info byte, then one application identifier per sector 1..15
    uint8_t mad[32];
    memset(mad, 0, sizeof(mad));
    mad[1] = 0x01;
    for (int sector = 1; sector <= sectors_used; sector++) {
        mad[2 + (sector - 1) * 2]     = 0x03;
        mad[2 + (sector - 1) * 2 + 1] = 0xE1;
    }
    mad[0] = sim_mad_crc(&mad[1], sizeof(mad) - 1);
    memcpy(&card->memory[1 * 16], mad, 16);
    memcpy(&card->memory[2 * 16], mad + 16, 16);
    memcpy(card->sector_key_a[0], key_mad, 6);
    card->memory[3 * 16 + 9] = 0xC1; // general purpose byte: MAD present, version 1

    size_t offset = 0;
    for (int sector = 1; sector <= sectors_used; sector++) {
        memcpy(card->sector_key_a[sector], key_ndef, 6);
        card->memory[(sector * 4 + 3) * 16 + 9] = 0x40; // general purpose byte: mapping version 1.0, read and write access
        for (int block = 0; block < 3; block++) {
            memcpy(&card->memory[(sector * 4 + block) * 16], &stream[offset], 16);
            offset += 16;
        }
    }
}

void sim_a_init_iso_dep(sim_a_card_t *card, uint8_t sak, uint8_t ats_fsci)
{
    static const uint8_t uid[7] = {0x04, 0x5A, 0x6B, 0x7C, 0x8D, 0x9E, 0xAF};
    // CCLEN 15, mapping 2.0, MLe 246, MLc 52, NDEF File Control TLV: file E104, 600 bytes, free access
    static const uint8_t cc[15] = {0x00, 0x0F, 0x20, 0x00, 0xF6, 0x00, 0x34, 0x04, 0x06, 0xE1, 0x04, 0x02, 0x58, 0x00, 0x00};
    memset(card, 0, sizeof(*card));
    card->kind    = SIM_A_ISO_DEP;
    card->uid_len = 7;
    memcpy(card->uid, uid, sizeof(uid));
    card->sak          = sak;
    card->atqa[0]      = 0x44;
    card->atqa[1]      = 0x03;
    card->ats_fsci     = ats_fsci;
    card->picc_max_inf = 253;
    card->auth_sector  = -1;
    memcpy(card->cc_file, cc, sizeof(cc));
    card->ndef_file_len = 2; // NLEN = 0: empty
}

void sim_a_iso_dep_store_ndef(sim_a_card_t *card, const uint8_t *ndef, size_t ndef_len)
{
    card->ndef_file[0] = (uint8_t)(ndef_len >> 8);
    card->ndef_file[1] = (uint8_t)(ndef_len & 0xFF);
    memcpy(&card->ndef_file[2], ndef, ndef_len);
    card->ndef_file_len = ndef_len + 2;
}

/* ---- ISO15693 tag ---- */

void sim_v_init(sim_v_card_t *card)
{
    static const uint8_t uid[8] = {0x10, 0x32, 0x54, 0x76, 0x98, 0x01, 0x04, 0xE0}; // as transmitted, LSB first
    memset(card, 0, sizeof(*card));
    memcpy(card->uid, uid, sizeof(uid));
    card->block_size              = 4;
    card->block_count             = 80;
    card->supports_reset_to_ready = true;
}

pn5180_rf_result_t sim_v_card(void *ctx, const uint8_t *tx, size_t tx_len, uint8_t tx_last_bits, uint8_t *rx, size_t rx_size, size_t *rx_len,
                              uint32_t timeout_us, uint32_t *rx_status)
{
    sim_v_card_t *card = ctx;
    (void)tx_last_bits;
    (void)timeout_us;
    (void)rx_status;

    if (tx_len < 2) {
        return PN5180_RF_TIMEOUT;
    }
    uint8_t flags = tx[0];
    uint8_t cmd   = tx[1];

    if (flags & 0x04) { // inventory
        if (cmd != 0x01 || card->quiet || tx_len < 3) {
            return PN5180_RF_TIMEOUT;
        }
        uint8_t mask_len = tx[2];
        for (uint8_t bit = 0; bit < mask_len; bit++) {
            uint8_t mask_bit = (tx[3 + bit / 8] >> (bit % 8)) & 1;
            uint8_t uid_bit  = (card->uid[bit / 8] >> (bit % 8)) & 1;
            if (mask_bit != uid_bit) {
                return PN5180_RF_TIMEOUT;
            }
        }
        uint8_t response[10] = {0x00, 0x00};
        memcpy(&response[2], card->uid, 8);
        return answer(rx, rx_size, rx_len, response, sizeof(response));
    }

    const uint8_t *payload     = &tx[2];
    size_t         payload_len = tx_len - 2;
    bool           addressed   = (flags & 0x20) != 0;
    if (addressed) {
        if (tx_len < 10 || memcmp(&tx[2], card->uid, 8) != 0) {
            return PN5180_RF_TIMEOUT;
        }
        payload     = &tx[10];
        payload_len = tx_len - 10;
    } else if (flags & 0x10) { // select flag
        if (!card->selected) {
            return PN5180_RF_TIMEOUT;
        }
    } else if (card->quiet) {
        return PN5180_RF_TIMEOUT;
    }

    const uint8_t ok               = 0x00;
    const uint8_t not_supported[2] = {0x01, 0x01};
    const uint8_t bad_block[2]     = {0x01, 0x10};

    switch (cmd) {
    case 0x02: // Stay Quiet: only in addressed mode, never answered
        if (addressed) {
            card->quiet    = true;
            card->selected = false;
        }
        return PN5180_RF_TIMEOUT;
    case 0x25: // Select
        if (!addressed) {
            return PN5180_RF_TIMEOUT;
        }
        card->selected = true;
        card->quiet    = false;
        return answer(rx, rx_size, rx_len, &ok, 1);
    case 0x26: // Reset to Ready
        if (!card->supports_reset_to_ready) {
            return answer(rx, rx_size, rx_len, not_supported, sizeof(not_supported));
        }
        card->selected = false;
        card->quiet    = false;
        return answer(rx, rx_size, rx_len, &ok, 1);
    case 0x20: { // Read Single Block
        if (payload_len < 1 || payload[0] >= card->block_count) {
            return answer(rx, rx_size, rx_len, bad_block, sizeof(bad_block));
        }
        uint8_t response[33] = {0x00};
        memcpy(&response[1], &card->memory[payload[0] * card->block_size], (size_t)card->block_size);
        return answer(rx, rx_size, rx_len, response, 1 + (size_t)card->block_size);
    }
    case 0x21: // Write Single Block
        if (payload_len < 1 + (size_t)card->block_size || payload[0] >= card->block_count) {
            return answer(rx, rx_size, rx_len, bad_block, sizeof(bad_block));
        }
        memcpy(&card->memory[payload[0] * card->block_size], &payload[1], (size_t)card->block_size);
        return answer(rx, rx_size, rx_len, &ok, 1);
    case 0x2B: { // Get System Information: DSFID, AFI, memory size and IC reference present
        uint8_t response[15] = {0x00, 0x0F};
        memcpy(&response[2], card->uid, 8);
        response[10] = 0x00;
        response[11] = 0x00;
        response[12] = (uint8_t)(card->block_count - 1);
        response[13] = (uint8_t)(card->block_size - 1);
        response[14] = 0x01;
        return answer(rx, rx_size, rx_len, response, sizeof(response));
    }
    default:
        return answer(rx, rx_size, rx_len, not_supported, sizeof(not_supported));
    }
}
