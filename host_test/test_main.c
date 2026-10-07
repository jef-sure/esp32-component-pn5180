/**
 * @file test_main.c
 * @brief Host tests for the PN5180 protocol code
 *
 * The driver sources are compiled for the host together with a fake of the reader layer
 * (fake_pn5180.c) and simulated cards (sim_cards.c). The tests drive the public protocol API the
 * way an application does: poll, select, detect, read and write.
 */
#include "pn5180-14443.h"
#include "pn5180-15693.h"
#include "pn5180-mifare.h"
#include "pn5180-ndef.h"
#include "sim_cards.h"
#include "unity.h"
#include <stdlib.h>
#include <string.h>

static pn5180_t       *s_pn5180;
static pn5180_proto_t *s_proto_a;
static pn5180_proto_t *s_proto_v;
static sim_a_card_t    s_card_a;
static sim_v_card_t    s_card_v;

void setUp(void)
{
    s_pn5180  = fake_pn5180_create();
    s_proto_a = pn5180_14443_init(s_pn5180);
    s_proto_v = pn5180_15693_init(s_pn5180, PN5180_15693_26KASK100);
}

void tearDown(void)
{
    free(s_proto_a);
    free(s_proto_v);
    fake_pn5180_destroy(s_pn5180);
}

/* ---- Helpers ---- */

// Polls for the simulated ISO14443A card and leaves it selected, with its type detected.
static pn5180_uid_t activate_card_a(void)
{
    fake_set_card(sim_a_card, sim_a_auth, &s_card_a);
    TEST_ASSERT_TRUE(s_proto_a->setup_rf(s_proto_a));

    pn5180_poll_status_t status = PN5180_POLL_NO_TARGET;
    pn5180_uids_array_t *uids   = pn5180_14443_get_all_uids_ex(s_proto_a, &status);
    TEST_ASSERT_EQUAL(PN5180_POLL_FOUND, status);
    TEST_ASSERT_NOT_NULL(uids);
    TEST_ASSERT_EQUAL(1, uids->uids_count);
    pn5180_uid_t uid = uids->uids[0];
    free(uids);

    TEST_ASSERT_TRUE(s_proto_a->select_by_uid(s_proto_a, &uid));
    int  blocks_count   = 0;
    int  block_size     = 0;
    bool needs_reselect = s_proto_a->detect_card_type_and_capacity(s_pn5180, &uid, &blocks_count, &block_size);
    if (needs_reselect) {
        // As documented: just select again, without a halt in between.
        TEST_ASSERT_TRUE(s_proto_a->select_by_uid(s_proto_a, &uid));
    }
    return uid;
}

// Builds a message with one URI record; returns its encoded length.
static size_t make_uri_message(const char *uri, uint8_t *out, size_t out_size)
{
    pn5180_ndef_record_t  record;
    pn5180_ndef_record_t  records[1];
    pn5180_ndef_message_t message;
    uint8_t               payload[400];
    TEST_ASSERT_TRUE(pn5180_ndef_make_uri_record(&record, uri, true, payload, sizeof(payload)));
    pn5180_ndef_message_init(&message, records, 1);
    TEST_ASSERT_TRUE(pn5180_ndef_message_add(&message, &record));
    size_t len = pn5180_ndef_encode_message(&message, out, out_size);
    TEST_ASSERT_TRUE(len > 0);
    return len;
}

static void assert_uri_message(const pn5180_ndef_message_parsed_t *msg, const char *uri)
{
    char buffer[400];
    TEST_ASSERT_NOT_NULL(msg);
    TEST_ASSERT_EQUAL(1, msg->record_count);
    TEST_ASSERT_TRUE(pn5180_ndef_record_is_uri(&msg->records[0]));
    TEST_ASSERT_EQUAL(strlen(uri), pn5180_ndef_extract_uri(&msg->records[0], buffer, sizeof(buffer)));
    TEST_ASSERT_EQUAL_STRING(uri, buffer);
}

/* ---- NDEF codec ---- */

static void test_ndef_encode_parse_roundtrip(void)
{
    pn5180_ndef_record_t  text;
    pn5180_ndef_record_t  uri;
    pn5180_ndef_record_t  records[2];
    pn5180_ndef_message_t message;
    uint8_t               text_payload[32];
    uint8_t               uri_payload[64];
    uint8_t               encoded[128];

    TEST_ASSERT_TRUE(pn5180_ndef_make_text_record(&text, "en", (const uint8_t *)"hello", 5, false, text_payload, sizeof(text_payload)));
    TEST_ASSERT_TRUE(pn5180_ndef_make_uri_record(&uri, "https://www.example.com/x", true, uri_payload, sizeof(uri_payload)));
    pn5180_ndef_message_init(&message, records, 2);
    TEST_ASSERT_TRUE(pn5180_ndef_message_add(&message, &text));
    TEST_ASSERT_TRUE(pn5180_ndef_message_add(&message, &uri));
    size_t len = pn5180_ndef_encode_message(&message, encoded, sizeof(encoded));
    TEST_ASSERT_TRUE(len > 0);

    pn5180_ndef_message_parsed_t *parsed = NULL;
    TEST_ASSERT_EQUAL(PN5180_NDEF_OK, pn5180_ndef_parse_message(encoded, len, &parsed));
    TEST_ASSERT_EQUAL(2, parsed->record_count);

    const uint8_t *text_out = NULL;
    size_t         text_len = 0;
    char           lang[64];
    bool           utf16 = true;
    TEST_ASSERT_TRUE(pn5180_ndef_extract_text(&parsed->records[0], &text_out, &text_len, lang, &utf16));
    TEST_ASSERT_EQUAL(5, text_len);
    TEST_ASSERT_EQUAL_MEMORY("hello", text_out, 5);
    TEST_ASSERT_EQUAL_STRING("en", lang);
    TEST_ASSERT_FALSE(utf16);

    char uri_out[64];
    TEST_ASSERT_TRUE(pn5180_ndef_extract_uri(&parsed->records[1], uri_out, sizeof(uri_out)) > 0);
    TEST_ASSERT_EQUAL_STRING("https://www.example.com/x", uri_out);
    // The longest prefix was used: "https://www." is code 0x02
    TEST_ASSERT_EQUAL_HEX8(0x02, parsed->records[1].payload[0]);
    pn5180_ndef_free_parsed_message(parsed);
}

static void test_ndef_uri_prefix_codes_follow_the_standard(void)
{
    // URI RTD 1.0: 0x13 is "urn:", 0x0D "ftp://", 0x1D "file://", 0x23 "urn:nfc:"
    const struct
    {
        uint8_t     code;
        const char *expected;
    } cases[] = {
        {0x13, "urn:x"    },
        {0x0D, "ftp://x"  },
        {0x1D, "file://x" },
        {0x23, "urn:nfc:x"},
        {0x00, "x"        }
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t              payload[2] = {cases[i].code, 'x'};
        pn5180_ndef_record_t record;
        char                 uri[32];
        pn5180_ndef_record_init(&record, PN5180_NDEF_TNF_WELL_KNOWN, PN5180_NDEF_RTD_URI, 1, NULL, 0, payload, sizeof(payload));
        TEST_ASSERT_TRUE(pn5180_ndef_extract_uri(&record, uri, sizeof(uri)) > 0);
        TEST_ASSERT_EQUAL_STRING(cases[i].expected, uri);
    }

    // Encoding picks the longest matching prefix: "urn:nfc:" (0x23), not "urn:" (0x13)
    pn5180_ndef_record_t record;
    uint8_t              payload[32];
    TEST_ASSERT_TRUE(pn5180_ndef_make_uri_record(&record, "urn:nfc:ext:a", true, payload, sizeof(payload)));
    TEST_ASSERT_EQUAL_HEX8(0x23, payload[0]);
    TEST_ASSERT_EQUAL(1 + strlen("ext:a"), record.payload_len);
}

static void test_ndef_chunks_are_assembled(void)
{
    // A text-type record split into three chunks, followed by an ordinary record
    const uint8_t message[] = {
        0xB1, 0x01, 0x02, 'T', 'a',  'b', // MB, CF, SR, well-known "T", payload "ab"
        0x36, 0x00, 0x02, 'c', 'd',       // CF, SR, unchanged, payload "cd"
        0x16, 0x00, 0x01, 'e',            // SR, unchanged, last chunk, payload "e"
        0x51, 0x01, 0x01, 'U', 0x00,      // ME, SR, well-known "U", payload 00
    };
    pn5180_ndef_message_parsed_t *parsed = NULL;
    TEST_ASSERT_EQUAL(PN5180_NDEF_OK, pn5180_ndef_parse_message(message, sizeof(message), &parsed));
    TEST_ASSERT_EQUAL(2, parsed->record_count);
    TEST_ASSERT_EQUAL(PN5180_NDEF_TNF_WELL_KNOWN, parsed->records[0].tnf);
    TEST_ASSERT_EQUAL(5, parsed->records[0].payload_len);
    TEST_ASSERT_EQUAL_MEMORY("abcde", parsed->records[0].payload, 5);
    TEST_ASSERT_EQUAL(1, parsed->records[1].payload_len);
    pn5180_ndef_free_parsed_message(parsed);
}

static void test_ndef_rejects_malformed_messages(void)
{
    pn5180_ndef_message_parsed_t *parsed = NULL;

    // Continuation chunk without a first chunk
    const uint8_t orphan[] = {0xD6, 0x00, 0x01, 'x'};
    TEST_ASSERT_EQUAL(PN5180_NDEF_ERR_PARSE_FAILED, pn5180_ndef_parse_message(orphan, sizeof(orphan), &parsed));
    TEST_ASSERT_NULL(parsed);

    // Reserved TNF 0x07
    const uint8_t reserved[] = {0xD7, 0x00, 0x00};
    TEST_ASSERT_EQUAL(PN5180_NDEF_ERR_PARSE_FAILED, pn5180_ndef_parse_message(reserved, sizeof(reserved), &parsed));

    // Empty record that carries a payload
    const uint8_t not_empty[] = {0xD0, 0x00, 0x01, 'x'};
    TEST_ASSERT_EQUAL(PN5180_NDEF_ERR_PARSE_FAILED, pn5180_ndef_parse_message(not_empty, sizeof(not_empty), &parsed));

    // Long record that declares a 4 GiB payload: the length check must not wrap around
    const uint8_t huge[] = {0xC1, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 'T', 0x00, 0x00};
    TEST_ASSERT_EQUAL(PN5180_NDEF_ERR_PARSE_FAILED, pn5180_ndef_parse_message(huge, sizeof(huge), &parsed));

    // Message without the Message End flag
    const uint8_t no_end[] = {0x91, 0x01, 0x01, 'U', 0x00};
    TEST_ASSERT_EQUAL(PN5180_NDEF_ERR_PARSE_FAILED, pn5180_ndef_parse_message(no_end, sizeof(no_end), &parsed));
}

/* ---- APDU helpers ---- */

static void test_apdu_parse_and_build(void)
{
    pn5180_apdu_command_t command;
    const uint8_t         case4[] = {0x00, 0xA4, 0x04, 0x00, 0x02, 0xE1, 0x03, 0x00};
    TEST_ASSERT_EQUAL(ESP_OK, pn5180_apdu_parse_command(case4, sizeof(case4), &command));
    TEST_ASSERT_EQUAL_HEX8(0xA4, command.ins);
    TEST_ASSERT_EQUAL(2, command.data_len);
    TEST_ASSERT_TRUE(command.has_le);
    TEST_ASSERT_EQUAL(256, command.le);

    const uint8_t truncated[] = {0x00, 0xA4, 0x04, 0x00, 0x05, 0xE1};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, pn5180_apdu_parse_command(truncated, sizeof(truncated), &command));

    uint8_t       buffer[8];
    size_t        len    = 0;
    const uint8_t data[] = {1, 2, 3};
    TEST_ASSERT_EQUAL(ESP_OK, pn5180_apdu_build_response(buffer, sizeof(buffer), data, sizeof(data), 0x90, 0x00, &len));
    TEST_ASSERT_EQUAL(5, len);
    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, pn5180_apdu_build_response(buffer, 4, data, sizeof(data), 0x90, 0x00, &len));

    pn5180_apdu_response_t response;
    TEST_ASSERT_EQUAL(ESP_OK, pn5180_apdu_parse_response(buffer, 5, &response));
    TEST_ASSERT_EQUAL(3, response.data_len);
    TEST_ASSERT_EQUAL_HEX16(PN5180_APDU_SW_SUCCESS, pn5180_apdu_get_status(&response));
}

/* ---- Polling ---- */

static void test_poll_without_card_reports_no_target(void)
{
    fake_set_card(NULL, NULL, NULL);
    TEST_ASSERT_TRUE(s_proto_a->setup_rf(s_proto_a));
    pn5180_poll_status_t status = PN5180_POLL_FOUND;
    TEST_ASSERT_NULL(pn5180_14443_get_all_uids_ex(s_proto_a, &status));
    TEST_ASSERT_EQUAL(PN5180_POLL_NO_TARGET, status);
    TEST_ASSERT_NULL(s_proto_a->get_all_uids(s_proto_a));

    TEST_ASSERT_NULL(pn5180_14443_get_all_uids_ex(NULL, &status));
    TEST_ASSERT_EQUAL(PN5180_POLL_INVALID_ARGUMENT, status);

    TEST_ASSERT_NULL(pn5180_15693_get_all_uids_ex(s_proto_v, &status));
    TEST_ASSERT_EQUAL(PN5180_POLL_NO_TARGET, status);
}

/* ---- Type 2 tags ---- */

static void test_ntag213_is_found_with_cascaded_uid_and_identified(void)
{
    sim_a_init_ntag213(&s_card_a);
    pn5180_uid_t uid = activate_card_a();

    TEST_ASSERT_EQUAL(7, uid.uid_length);
    TEST_ASSERT_EQUAL_MEMORY(s_card_a.uid, uid.uid, 7);
    TEST_ASSERT_EQUAL_HEX8(0x00, uid.sak);
    TEST_ASSERT_EQUAL_HEX8(0x44, uid.atqa[0]);
    TEST_ASSERT_EQUAL_HEX8(0x00, uid.atqa[1]);
    TEST_ASSERT_EQUAL(PN5180_MIFARE_NTAG213, uid.subtype);
    TEST_ASSERT_EQUAL(45, uid.blocks_count);
    TEST_ASSERT_EQUAL(4, uid.block_size);
    TEST_ASSERT_EQUAL(SIM_A_ACTIVE, s_card_a.state);
}

static void test_type2_ndef_write_then_read(void)
{
    sim_a_init_ntag213(&s_card_a);
    pn5180_uid_t uid = activate_card_a();

    const char           *uri = "https://www.example.com/a/rather/long/path/that/spans/several/pages";
    pn5180_ndef_record_t  record;
    pn5180_ndef_record_t  records[1];
    pn5180_ndef_message_t message;
    uint8_t               payload[128];
    TEST_ASSERT_TRUE(pn5180_ndef_make_uri_record(&record, uri, true, payload, sizeof(payload)));
    pn5180_ndef_message_init(&message, records, 1);
    TEST_ASSERT_TRUE(pn5180_ndef_message_add(&message, &record));

    // Pages are written with WRITE (A2h): a 4-byte block size
    TEST_ASSERT_EQUAL(PN5180_NDEF_OK, pn5180_ndef_write_to_selected_card(s_proto_a, &message, 4, 4, 36));
    TEST_ASSERT_EQUAL_HEX8(0x03, s_card_a.memory[16]); // NDEF TLV at page 4

    pn5180_ndef_message_parsed_t *parsed = NULL;
    TEST_ASSERT_EQUAL(PN5180_NDEF_OK, pn5180_ndef_read_card_auto(s_proto_a, &uid, &parsed));
    assert_uri_message(parsed, uri);
    pn5180_ndef_free_parsed_message(parsed);
}

static void test_type2_read_recovers_after_card_left_selected_state(void)
{
    sim_a_init_ntag213(&s_card_a);
    pn5180_uid_t uid = activate_card_a();

    uint8_t ndef[64];
    size_t  ndef_len    = make_uri_message("tel:+123456789", ndef, sizeof(ndef));
    s_card_a.memory[16] = 0x03;
    s_card_a.memory[17] = (uint8_t)ndef_len;
    memcpy(&s_card_a.memory[18], ndef, ndef_len);
    s_card_a.memory[18 + ndef_len] = 0xFE;

    // A read beyond the last page is answered with NAK, which resets the card to IDLE.
    uint8_t data[16];
    TEST_ASSERT_FALSE(s_proto_a->block_read(s_proto_a, 60, data, sizeof(data)));
    TEST_ASSERT_EQUAL(SIM_A_IDLE, s_card_a.state);

    pn5180_ndef_message_parsed_t *parsed = NULL;
    TEST_ASSERT_EQUAL(PN5180_NDEF_OK, pn5180_ndef_read_card_auto(s_proto_a, &uid, &parsed));
    assert_uri_message(parsed, "tel:+123456789");
    pn5180_ndef_free_parsed_message(parsed);
}

static void test_type2_without_capability_container_has_no_ndef(void)
{
    sim_a_init_ntag213(&s_card_a);
    memset(&s_card_a.memory[12], 0, 4);
    pn5180_uid_t uid = activate_card_a();

    pn5180_ndef_message_parsed_t *parsed = NULL;
    TEST_ASSERT_EQUAL(PN5180_NDEF_ERR_NO_NDEF, pn5180_ndef_read_card_auto(s_proto_a, &uid, &parsed));
    TEST_ASSERT_NULL(parsed);
}

static void test_type2_read_stays_inside_the_data_area(void)
{
    // The NDEF TLV claims more bytes than the data area holds: the reader must stop at the end of
    // the area instead of wrapping around to page 0.
    sim_a_init_ntag213(&s_card_a);
    s_card_a.memory[16] = 0x03;
    s_card_a.memory[17] = 0xF0;
    pn5180_uid_t uid    = activate_card_a();

    pn5180_ndef_message_parsed_t *parsed = NULL;
    int                           frames = fake_frame_count();
    TEST_ASSERT_EQUAL(PN5180_NDEF_ERR_NO_NDEF, pn5180_ndef_read_card_auto(s_proto_a, &uid, &parsed));
    // 144 bytes of data area: one READ for pages 3..6, then pages 7..39 in steps of four
    TEST_ASSERT_EQUAL(1 + 9, fake_frame_count() - frames);
    TEST_ASSERT_EQUAL(SIM_A_ACTIVE, s_card_a.state);
}

static void test_ultralight_c_is_told_apart_from_ultralight(void)
{
    sim_a_init_ultralight(&s_card_a, true);
    pn5180_uid_t uid = activate_card_a();
    TEST_ASSERT_EQUAL(PN5180_MIFARE_ULTRALIGHT_C, uid.subtype);
    TEST_ASSERT_EQUAL(44, uid.blocks_count);
    TEST_ASSERT_EQUAL(SIM_A_ACTIVE, s_card_a.state);

    sim_a_init_ultralight(&s_card_a, false);
    uid = activate_card_a();
    TEST_ASSERT_EQUAL(PN5180_MIFARE_ULTRALIGHT, uid.subtype);
    TEST_ASSERT_EQUAL(16, uid.blocks_count);
    TEST_ASSERT_EQUAL(SIM_A_ACTIVE, s_card_a.state);
}

/* ---- MIFARE Classic ---- */

static void test_classic_ndef_is_read_through_the_mad(void)
{
    sim_a_init_classic_1k(&s_card_a);
    uint8_t     ndef[128];
    const char *uri      = "https://www.example.com/classic/card/with/a/message/over/two/sectors";
    size_t      ndef_len = make_uri_message(uri, ndef, sizeof(ndef));
    sim_a_classic_store_ndef(&s_card_a, ndef, ndef_len);

    pn5180_uid_t uid = activate_card_a();
    TEST_ASSERT_EQUAL(PN5180_MIFARE_CLASSIC_1K, uid.subtype);
    TEST_ASSERT_EQUAL(64, uid.blocks_count);

    pn5180_ndef_message_parsed_t *parsed = NULL;
    TEST_ASSERT_EQUAL(PN5180_NDEF_OK, pn5180_ndef_read_card_auto(s_proto_a, &uid, &parsed));
    assert_uri_message(parsed, uri);
    pn5180_ndef_free_parsed_message(parsed);
}

static void test_classic_without_mad_has_no_ndef(void)
{
    sim_a_init_classic_1k(&s_card_a); // transport configuration: default keys, no MAD
    pn5180_uid_t uid = activate_card_a();

    pn5180_ndef_message_parsed_t *parsed = NULL;
    TEST_ASSERT_EQUAL(PN5180_NDEF_ERR_NO_NDEF, pn5180_ndef_read_card_auto(s_proto_a, &uid, &parsed));
}

static void test_classic_block_write_and_value_operations(void)
{
    static const uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    sim_a_init_classic_1k(&s_card_a);
    pn5180_uid_t uid = activate_card_a();

    TEST_ASSERT_TRUE(s_proto_a->authenticate(s_proto_a, key, PN5180_MIFARE_CLASSIC_KEYA, &uid, 4));

    uint8_t block[16];
    uint8_t readback[16];
    for (int i = 0; i < 16; i++) {
        block[i] = (uint8_t)(0xA0 + i);
    }
    TEST_ASSERT_EQUAL(0, s_proto_a->block_write(s_proto_a, 4, block, sizeof(block)));
    TEST_ASSERT_TRUE(s_proto_a->block_read(s_proto_a, 4, readback, sizeof(readback)));
    TEST_ASSERT_EQUAL_MEMORY(block, readback, 16);

    int32_t value = 0;
    TEST_ASSERT_FALSE(pn5180_mifare_value_read(s_pn5180, 4, &value)); // not a value block
    TEST_ASSERT_TRUE(pn5180_mifare_value_write(s_pn5180, 5, 1000, 5));
    TEST_ASSERT_TRUE(pn5180_mifare_value_read(s_pn5180, 5, &value));
    TEST_ASSERT_EQUAL(1000, value);

    TEST_ASSERT_TRUE(pn5180_mifare_increment(s_pn5180, 5, 25));
    TEST_ASSERT_TRUE(pn5180_mifare_transfer(s_pn5180, 5));
    TEST_ASSERT_TRUE(pn5180_mifare_value_read(s_pn5180, 5, &value));
    TEST_ASSERT_EQUAL(1025, value);

    TEST_ASSERT_TRUE(pn5180_mifare_decrement(s_pn5180, 5, 1030));
    TEST_ASSERT_TRUE(pn5180_mifare_transfer(s_pn5180, 6)); // into another block of the sector
    TEST_ASSERT_TRUE(pn5180_mifare_value_read(s_pn5180, 6, &value));
    TEST_ASSERT_EQUAL(-5, value);
}

/* ---- ISO14443-4 ---- */

static void test_iso_dep_card_is_activated_on_select(void)
{
    sim_a_init_iso_dep(&s_card_a, 0x20, 8);
    pn5180_uid_t uid = activate_card_a();

    TEST_ASSERT_EQUAL(PN5180_MIFARE_DESFIRE, uid.subtype);
    TEST_ASSERT_TRUE(s_pn5180->iso14443_layer4_active);
    TEST_ASSERT_EQUAL(SIM_A_PROTOCOL, s_card_a.state);
    TEST_ASSERT_EQUAL(1, s_card_a.rats_count);
    // Selecting does not touch the card's applications any more.
    TEST_ASSERT_EQUAL(0, s_card_a.last_apdu_len);

    // halt releases the card with S(DESELECT)
    TEST_ASSERT_TRUE(s_proto_a->halt(s_proto_a));
    TEST_ASSERT_EQUAL(1, s_card_a.deselect_count);
    TEST_ASSERT_EQUAL(SIM_A_HALT, s_card_a.state);
    TEST_ASSERT_FALSE(s_pn5180->iso14443_layer4_active);
}

static void test_iso_dep_chaining_in_both_directions(void)
{
    // FSCI 2: the card accepts frames of 32 bytes, so 29 APDU bytes per block
    sim_a_init_iso_dep(&s_card_a, 0x20, 2);
    s_card_a.picc_max_inf = 20;
    uint8_t ndef[400];
    memset(ndef, 0x5A, sizeof(ndef));
    sim_a_iso_dep_store_ndef(&s_card_a, ndef, sizeof(ndef));
    activate_card_a();

    // A 100-byte command has to be chained by the reader; the card sees it whole.
    uint8_t apdu[100];
    memset(apdu, 0x11, sizeof(apdu));
    apdu[0] = 0x00;
    apdu[1] = 0xFF; // unknown instruction
    uint8_t rx[300];
    size_t  rx_len = sizeof(rx);
    TEST_ASSERT_TRUE(pn5180_14443_4_transceive(s_pn5180, apdu, sizeof(apdu), rx, &rx_len));
    TEST_ASSERT_EQUAL(sizeof(apdu), s_card_a.last_apdu_len);
    TEST_ASSERT_EQUAL_MEMORY(apdu, s_card_a.last_apdu, sizeof(apdu));
    TEST_ASSERT_EQUAL(2, rx_len);
    TEST_ASSERT_EQUAL_HEX8(0x6D, rx[0]);

    // A 200-byte response arrives in 20-byte blocks.
    static const uint8_t aid[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    static const uint8_t fid[] = {0xE1, 0x04};
    TEST_ASSERT_TRUE(pn5180_14443_4_select_file(s_pn5180, aid, sizeof(aid)));
    TEST_ASSERT_TRUE(pn5180_14443_4_select_file(s_pn5180, fid, sizeof(fid)));
    uint8_t data[200];
    size_t  got = sizeof(data);
    TEST_ASSERT_TRUE(pn5180_14443_4_read_binary(s_pn5180, 2, 200, data, &got));
    TEST_ASSERT_EQUAL(200, got);
    TEST_ASSERT_EACH_EQUAL_HEX8(0x5A, data, 200);
}

static void test_iso_dep_recovers_from_lost_frames_and_wtx(void)
{
    sim_a_init_iso_dep(&s_card_a, 0x20, 8);
    activate_card_a();
    static const uint8_t aid[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    static const uint8_t cc[]  = {0xE1, 0x03};
    uint8_t              data[15];
    size_t               got;

    // The card's answer is lost: the reader asks again with R(NAK) and gets the same block.
    s_card_a.drop_responses = 1;
    TEST_ASSERT_TRUE(pn5180_14443_4_select_file(s_pn5180, aid, sizeof(aid)));

    // The reader's command is lost: R(NAK) is answered with R(ACK), the command is sent again.
    s_card_a.drop_commands = 1;
    TEST_ASSERT_TRUE(pn5180_14443_4_select_file(s_pn5180, cc, sizeof(cc)));

    // The card asks for more time first.
    s_card_a.wtx_requests = 2;
    got                   = sizeof(data);
    TEST_ASSERT_TRUE(pn5180_14443_4_read_binary(s_pn5180, 0, 15, data, &got));
    TEST_ASSERT_EQUAL(15, got);
    TEST_ASSERT_EQUAL_MEMORY(s_card_a.cc_file, data, 15);

    // Both directions lost several times in a row: the exchange gives up, and the next one works.
    s_card_a.drop_commands = 10;
    got                    = sizeof(data);
    TEST_ASSERT_FALSE(pn5180_14443_4_read_binary(s_pn5180, 0, 15, data, &got));
    s_card_a.drop_commands = 0;
    got                    = sizeof(data);
    TEST_ASSERT_TRUE(pn5180_14443_4_read_binary(s_pn5180, 0, 15, data, &got));
}

static void test_type4_ndef_read(void)
{
    sim_a_init_iso_dep(&s_card_a, 0x20, 8);
    uint8_t ndef[400];
    char    uri[340];
    strcpy(uri, "https://www.example.com/");
    memset(uri + strlen(uri), 'q', 300);
    uri[24 + 300]   = '\0';
    size_t ndef_len = make_uri_message(uri, ndef, sizeof(ndef));
    TEST_ASSERT_TRUE(ndef_len > 255); // long record, read in several READ BINARY commands
    sim_a_iso_dep_store_ndef(&s_card_a, ndef, ndef_len);

    pn5180_uid_t                  uid    = activate_card_a();
    pn5180_ndef_message_parsed_t *parsed = NULL;
    TEST_ASSERT_EQUAL(PN5180_NDEF_OK, pn5180_ndef_read_card_auto(s_proto_a, &uid, &parsed));
    assert_uri_message(parsed, uri);
    pn5180_ndef_free_parsed_message(parsed);

    // An empty NDEF file is "no NDEF", not a failure.
    s_card_a.ndef_file_len = 2;
    s_card_a.ndef_file[0]  = 0;
    s_card_a.ndef_file[1]  = 0;
    TEST_ASSERT_EQUAL(PN5180_NDEF_ERR_NO_NDEF, pn5180_ndef_read_card_auto(s_proto_a, &uid, &parsed));
}

static void test_type4_select_falls_back_for_mapping_version_1(void)
{
    sim_a_init_iso_dep(&s_card_a, 0x20, 8);
    s_card_a.refuse_select_p2_0c = true;
    uint8_t ndef[64];
    size_t  ndef_len = make_uri_message("mailto:a@example.com", ndef, sizeof(ndef));
    sim_a_iso_dep_store_ndef(&s_card_a, ndef, ndef_len);

    pn5180_uid_t                  uid    = activate_card_a();
    pn5180_ndef_message_parsed_t *parsed = NULL;
    TEST_ASSERT_EQUAL(PN5180_NDEF_OK, pn5180_ndef_read_card_auto(s_proto_a, &uid, &parsed));
    assert_uri_message(parsed, "mailto:a@example.com");
    pn5180_ndef_free_parsed_message(parsed);
}

static void test_classic_emulation_card_stays_on_layer_3_unless_asked(void)
{
    // SAK 0x28: ISO14443-4 card that also emulates MIFARE Classic 1K
    sim_a_init_iso_dep(&s_card_a, 0x28, 8);
    pn5180_uid_t uid = activate_card_a();
    TEST_ASSERT_EQUAL(PN5180_MIFARE_CLASSIC_1K, uid.subtype);
    TEST_ASSERT_EQUAL(0, s_card_a.rats_count);
    TEST_ASSERT_FALSE(s_pn5180->iso14443_layer4_active);
    TEST_ASSERT_EQUAL(SIM_A_ACTIVE, s_card_a.state);

    // Asking for the ISO14443-4 side: set the subtype and select again.
    s_proto_a->halt(s_proto_a);
    uid.subtype = PN5180_MIFARE_DESFIRE;
    TEST_ASSERT_TRUE(s_proto_a->select_by_uid(s_proto_a, &uid));
    TEST_ASSERT_EQUAL(1, s_card_a.rats_count);
    TEST_ASSERT_TRUE(s_pn5180->iso14443_layer4_active);
}

/* ---- ISO15693 ---- */

static void test_iso15693_poll_select_detect_and_ndef(void)
{
    sim_v_init(&s_card_v);
    // Type 5 capability container and message
    uint8_t       ndef[64];
    size_t        ndef_len = make_uri_message("https://example.org/t5", ndef, sizeof(ndef));
    const uint8_t cc[4]    = {0xE1, 0x40, 0x28, 0x01}; // 40 * 8 = 320 bytes of data area
    memcpy(s_card_v.memory, cc, sizeof(cc));
    s_card_v.memory[4] = 0x03;
    s_card_v.memory[5] = (uint8_t)ndef_len;
    memcpy(&s_card_v.memory[6], ndef, ndef_len);
    s_card_v.memory[6 + ndef_len] = 0xFE;

    fake_set_card(sim_v_card, NULL, &s_card_v);
    TEST_ASSERT_TRUE(s_proto_v->setup_rf(s_proto_v));

    pn5180_poll_status_t status = PN5180_POLL_NO_TARGET;
    pn5180_uids_array_t *uids   = pn5180_15693_get_all_uids_ex(s_proto_v, &status);
    TEST_ASSERT_EQUAL(PN5180_POLL_FOUND, status);
    TEST_ASSERT_NOT_NULL(uids);
    TEST_ASSERT_EQUAL(1, uids->uids_count);
    pn5180_uid_t uid = uids->uids[0];
    free(uids);
    TEST_ASSERT_EQUAL(8, uid.uid_length);
    TEST_ASSERT_EQUAL_MEMORY(s_card_v.uid, uid.uid, 8);
    TEST_ASSERT_TRUE(s_card_v.quiet); // inventory silences each tag it has found

    TEST_ASSERT_TRUE(s_proto_v->select_by_uid(s_proto_v, &uid));
    int blocks_count = 0;
    int block_size   = 0;
    s_proto_v->detect_card_type_and_capacity(s_pn5180, &uid, &blocks_count, &block_size);
    TEST_ASSERT_EQUAL(PN5180_15693, uid.subtype);
    TEST_ASSERT_EQUAL(80, blocks_count);
    TEST_ASSERT_EQUAL(4, block_size);

    pn5180_ndef_message_parsed_t *parsed = NULL;
    TEST_ASSERT_EQUAL(PN5180_NDEF_OK, pn5180_ndef_read_card_auto(s_proto_v, &uid, &parsed));
    assert_uri_message(parsed, "https://example.org/t5");
    pn5180_ndef_free_parsed_message(parsed);

    // halt: Reset to Ready in Select mode puts the tag back into the Ready state
    TEST_ASSERT_TRUE(s_proto_v->halt(s_proto_v));
    TEST_ASSERT_FALSE(s_card_v.selected);
    TEST_ASSERT_FALSE(s_card_v.quiet);
}

static void test_iso15693_block_write_and_read(void)
{
    sim_v_init(&s_card_v);
    fake_set_card(sim_v_card, NULL, &s_card_v);
    TEST_ASSERT_TRUE(s_proto_v->setup_rf(s_proto_v));
    pn5180_uids_array_t *uids = s_proto_v->get_all_uids(s_proto_v);
    TEST_ASSERT_NOT_NULL(uids);
    pn5180_uid_t uid = uids->uids[0];
    free(uids);
    TEST_ASSERT_TRUE(s_proto_v->select_by_uid(s_proto_v, &uid));

    const uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t       readback[4];
    TEST_ASSERT_EQUAL(0, s_proto_v->block_write(s_proto_v, 7, data, sizeof(data)));
    TEST_ASSERT_TRUE(s_proto_v->block_read(s_proto_v, 7, readback, sizeof(readback)));
    TEST_ASSERT_EQUAL_MEMORY(data, readback, 4);
    TEST_ASSERT_FALSE(s_proto_v->block_read(s_proto_v, 200, readback, sizeof(readback))); // error flag

    // A tag without Reset to Ready answers halt with an error.
    s_card_v.supports_reset_to_ready = false;
    TEST_ASSERT_FALSE(s_proto_v->halt(s_proto_v));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ndef_encode_parse_roundtrip);
    RUN_TEST(test_ndef_uri_prefix_codes_follow_the_standard);
    RUN_TEST(test_ndef_chunks_are_assembled);
    RUN_TEST(test_ndef_rejects_malformed_messages);
    RUN_TEST(test_apdu_parse_and_build);
    RUN_TEST(test_poll_without_card_reports_no_target);
    RUN_TEST(test_ntag213_is_found_with_cascaded_uid_and_identified);
    RUN_TEST(test_type2_ndef_write_then_read);
    RUN_TEST(test_type2_read_recovers_after_card_left_selected_state);
    RUN_TEST(test_type2_without_capability_container_has_no_ndef);
    RUN_TEST(test_type2_read_stays_inside_the_data_area);
    RUN_TEST(test_ultralight_c_is_told_apart_from_ultralight);
    RUN_TEST(test_classic_ndef_is_read_through_the_mad);
    RUN_TEST(test_classic_without_mad_has_no_ndef);
    RUN_TEST(test_classic_block_write_and_value_operations);
    RUN_TEST(test_iso_dep_card_is_activated_on_select);
    RUN_TEST(test_iso_dep_chaining_in_both_directions);
    RUN_TEST(test_iso_dep_recovers_from_lost_frames_and_wtx);
    RUN_TEST(test_type4_ndef_read);
    RUN_TEST(test_type4_select_falls_back_for_mapping_version_1);
    RUN_TEST(test_classic_emulation_card_stays_on_layer_3_unless_asked);
    RUN_TEST(test_iso15693_poll_select_detect_and_ndef);
    RUN_TEST(test_iso15693_block_write_and_read);
    return UNITY_END();
}
