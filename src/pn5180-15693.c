#include "pn5180-15693.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pn5180-internal.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "pn5180-15693";

static bool pn5180_iso15693_stay_quiet(pn5180_t *pn5180, uint8_t *uid);

static bool pn5180_iso15693_check_response(const char *operation, const uint8_t *buffer, uint16_t num_bytes)
{
    if (buffer == NULL || num_bytes == 0) {
        ESP_LOGE(TAG, "%s: empty response", operation);
        return false;
    }
    if ((buffer[0] & 0x01) != 0) {
        ESP_LOGW(TAG, "%s: ISO15693 error flags=0x%02X code=0x%02X", operation, buffer[0], (num_bytes > 1) ? buffer[1] : 0x00);
        return false;
    }
    return true;
}

/*
| **26 kbit/s**    | 0x0D | 0x8D | ISO 15693 (ASK100)             |
| **26 kbit/s**    | 0x0E | 0x8E | ISO 15693 (ASK10)              |
*/

#define ISO15693_CMD_INVENTORY        0x01
#define ISO15693_CMD_STAY_QUIET       0x02
#define ISO15693_CMD_SELECT           0x25
#define ISO15693_CMD_RESET_TO_READY   0x26
#define ISO15693_CMD_READ_SINGLE      0x20
#define ISO15693_CMD_WRITE_SINGLE     0x21
#define ISO15693_CMD_READ_SINGLE_EXT  0x30 // Extended Read Single Block: two-byte block number
#define ISO15693_CMD_WRITE_SINGLE_EXT 0x31 // Extended Write Single Block
#define ISO15693_CMD_GET_SYSTEM_INFO  0x2B
#define ISO15693_FLAG_INVENTORY       0x04
#define ISO15693_FLAG_DATA_RATE_HIGH  0x02
#define ISO15693_FLAG_SLOT_ONE        0x20
#define ISO15693_FLAG_SELECTED        0x10
#define ISO15693_FLAG_ADDRESS         0x20
#define ARRAY_SIZE(arr)               (sizeof(arr) / sizeof((arr)[0]))

// PN5180 RF config constants (from datasheet)
#ifndef PN5180_15693_26KASK100
#define PN5180_15693_26KASK100 0x0D
#endif
#ifndef PN5180_15693_26KASK10
#define PN5180_15693_26KASK10 0x0E
#endif

static bool pn5180_15693_setup_rf(pn5180_t *pn5180, uint8_t rf_config)
{
    pn5180_write_register_and_mask(pn5180, PN5180_SYSTEM_CONFIG, PN5180_SYSTEM_CONFIG_CLEAR_CRYPTO_MASK);
    pn5180_set_transceiver_idle(pn5180);
    if (pn5180->is_rf_on) {
        pn5180_set_rf_off(pn5180);
        // Tags drop their Quiet and Selected state only after the field was off long enough.
        pn5180_delay_us(PN5180_RF_OFF_TIME_US);
    }
    bool ret = pn5180_load_rf_config(pn5180, rf_config);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to load RF config for 15693");
        return false;
    }
    ret = pn5180_set_rf_on(pn5180);
    if (!ret) {
        ESP_LOGE(TAG, "Failed to turn RF on for 15693");
        return false;
    }
    return true;
}

// Sends a request and receives the response frame. Returns true only for an error-free reception.
static bool pn5180_iso15693_exchange(pn5180_t *pn5180, const uint8_t *cmd, size_t cmd_len, uint8_t *rx, size_t rx_size, uint16_t *num_bytes,
                                     uint32_t timeout_us)
{
    size_t             rx_len = 0;
    pn5180_rf_result_t result = pn5180_rf_transceive(pn5180, cmd, cmd_len, 0, rx, rx_size, &rx_len, timeout_us, NULL);
    *num_bytes                = (uint16_t)rx_len;
    return result == PN5180_RF_OK;
}

static bool _pn5180_15693_setup_rf(pn5180_proto_t *proto)
{
    return pn5180_15693_setup_rf(proto->pn5180, proto->rf_config);
}

static void pn5180_iso15693_fill_uid(pn5180_uid_t *entry, const uint8_t *uid, uint8_t uid_len, uint16_t agc)
{
    memset(entry, 0, sizeof(*entry));
    entry->uid_length = uid_len;
    entry->sak        = 0;
    entry->agc        = agc;
    entry->subtype    = PN5180_15693;
    memcpy(entry->uid, uid, uid_len);
}

static size_t pn5180_iso15693_build_cmd(uint8_t *cmd, size_t cmd_size, uint8_t flags, uint8_t command, const uint8_t *uid)
{
    if (cmd_size < 2) {
        return 0;
    }
    cmd[0] = flags;
    cmd[1] = command;
    if (uid == NULL) {
        return 2;
    }
    if (cmd_size < 10) {
        return 0;
    }
    memcpy(&cmd[2], uid, 8);
    return 10;
}

static bool pn5180_iso15693_collect_uid(pn5180_uids_array_t **uids, const uint8_t *uid, uint8_t uid_len, uint16_t agc)
{
    if (uids == NULL) {
        PN5180_LOGD(TAG, "collect_uid: uids container is NULL");
        return false;
    }

    if (uid == NULL || uid_len == 0 || uid_len > sizeof(((pn5180_uid_t *)0)->uid)) {
        PN5180_LOGD(TAG, "collect_uid: invalid uid");
        return false;
    }

    if (*uids != NULL) {
        for (int i = 0; i < (*uids)->uids_count; i++) {
            if ((*uids)->uids[i].uid_length == uid_len && memcmp((*uids)->uids[i].uid, uid, uid_len) == 0) {
                (*uids)->uids[i].agc = agc;
                PN5180_LOGD(TAG, "collect_uid: duplicate UID");
                return false;
            }
        }
    }

    if (*uids == NULL) {
        *uids = calloc(1, sizeof(pn5180_uids_array_t));
        if (*uids == NULL) {
            ESP_LOGE(TAG, "Memory allocation failed for ISO15693 UIDs");
            return false;
        }
        PN5180_LOGD(TAG, "collect_uid: first UID stored");
        (*uids)->uids_count = 1;
        pn5180_iso15693_fill_uid(&(*uids)->uids[0], uid, uid_len, agc);
        return true;
    }

    pn5180_uids_array_t *new_uids = realloc(*uids, sizeof(pn5180_uids_array_t) + ((*uids)->uids_count * sizeof(pn5180_uid_t)));
    if (new_uids == NULL) {
        ESP_LOGE(TAG, "Memory allocation failed for ISO15693 UIDs");
        return false;
    }
    *uids                 = new_uids;
    pn5180_uid_t *new_uid = &(*uids)->uids[(*uids)->uids_count];
    pn5180_iso15693_fill_uid(new_uid, uid, uid_len, agc);
    (*uids)->uids_count++;
    return true;
}

/**
 * @brief Build an inventory request (flags, command, mask) into send_buf, which must hold 12 bytes
 * @param single_slot If true, requests 1 slot. If false, requests 16 slots.
 * @param mask_len Length of mask in bits (0-60)
 * @param mask_val Mask value (up to 64 bits, but only mask_len used)
 */
static size_t pn5180_iso15693_build_inventory_cmd(pn5180_t *pn5180, uint8_t *send_buf, bool single_slot, uint8_t mask_len, uint64_t mask_val)
{
    size_t idx = 0;

    // Enable full CRC for proper error detection
    pn5180_enable_crc(pn5180);

    send_buf[idx] = ISO15693_FLAG_INVENTORY;
    if (single_slot) {
        send_buf[idx] |= ISO15693_FLAG_SLOT_ONE;
    }
    if (pn5180->iso15693_use_high_rate) {
        send_buf[idx] |= ISO15693_FLAG_DATA_RATE_HIGH;
    }
    idx++;

    send_buf[idx++] = ISO15693_CMD_INVENTORY;
    send_buf[idx++] = mask_len; // mask length

    if (mask_len > 0) {
        // Mask value bytes - LSB first
        int bytes = (mask_len + 7) / 8;
        for (int i = 0; i < bytes; i++) {
            send_buf[idx++] = (mask_val >> (i * 8)) & 0xFF;
        }
    }

    PN5180_LOGD(TAG, "inventory: (%s) mask_len=%u val=%" PRIx64, single_slot ? "single-slot" : "16-slot", (unsigned)mask_len, mask_val);
    return idx;
}

/**
 * @brief Try single-slot inventory to read one tag at a time.
 * Uses a Stack-based Depth-First Search (DFS) to resolve collisions.
 */
static bool pn5180_15693_inventory_single_slot(pn5180_t *pn5180, pn5180_uids_array_t **uids, bool *fatal)
{
    const int max_total_scans = 64; // Safety limit
    int       scan_count      = 0;
    int       total_found     = 0;

    // Stack for DFS anticollision
    typedef struct
    {
        uint8_t  len;
        uint64_t val;
        int      retries;
    } mask_t;

    mask_t stack[20]; // masks of up to 16 bits: at most 17 entries wait at a time
    int    stack_ptr = 0;

    // Push initial global search
    stack[stack_ptr].len     = 0;
    stack[stack_ptr].val     = 0;
    stack[stack_ptr].retries = 0;
    stack_ptr++;

    while (stack_ptr > 0 && scan_count < max_total_scans) {
        // Pop the current mask
        stack_ptr--;
        mask_t current = stack[stack_ptr];

        scan_count++;

        // Send single-slot inventory with current mask
        uint8_t inv_cmd[12];
        size_t  inv_len = pn5180_iso15693_build_inventory_cmd(pn5180, inv_cmd, true, current.len, current.val);

        uint8_t            rx_buf[16];
        size_t             rx_len    = 0;
        uint32_t           rx_status = 0;
        pn5180_rf_result_t result    = pn5180_rf_transceive(pn5180, inv_cmd, inv_len, 0, rx_buf, sizeof(rx_buf), &rx_len, PN5180_TIMEOUT_15693_US, &rx_status);
        if (result == PN5180_RF_FATAL) {
            // The reader itself failed: this is not "no tag".
            *fatal = true;
            break;
        }
        if (result == PN5180_RF_TIMEOUT) {
            // Timeout - no tags match this mask
            continue;
        }

        uint16_t num_bytes    = (rx_status >> PN5180_RX_BYTES_RECEIVED_START) & PN5180_RX_BYTES_RECEIVED_MASK;
        bool     collision    = (result == PN5180_RF_COLLISION);
        bool     protocol_err = (rx_status & PN5180_RX_PROTOCOL_ERROR) != 0;

        PN5180_LOGD(TAG, "scan %d: rx_status=0x%08" PRIx32 " len=%u val=0x%" PRIx64 " collision=%d bytes=%u", scan_count, rx_status, (unsigned)current.len,
                    current.val, collision, (unsigned)num_bytes);

        if (collision) {
            // Check for "Noise" vs "Real Collision"
            // If we have 0 bytes and collision, it's likely noise (especially if ProtocolError is set)
            // We should retry the same mask to see if we get a clear signal or a clear collision
            bool looks_like_noise = (num_bytes == 0) || protocol_err;

            // Retrying doesn't seem to help much with the PN5180 "Ghost Collision" issue.
            // If we are deep enough in the tree (e.g. len > 0) and we still see 0 bytes collision,
            // it is very likely we are chasing a ghost.
            // However, for len=0 (global), we MUST split if we see collision, otherwise we find nothing.

            if (looks_like_noise && current.retries < 3) {
                PN5180_LOGD(TAG, "scan %d: noisy collision, retrying (retry %d)", scan_count, current.retries);
                current.retries++;
                stack[stack_ptr++] = current; // Push back exact same state

                // Add a small jitter to desynchronize potentially colliding cards
                int jitter = (esp_random() % 10) + 5;
                pn5180_delay_ms(jitter);
                continue;
            }

            // Critical Fix: If we retried and it's STILL 0-byte collision, assume it's noise and IGNORE it?
            // ABANDON BRANCH if we have 0 bytes after retries, UNLESS we are at root (len=0).
            // If len=0 and 0 bytes, we might have multiple cards shouting over each other perfectly.
            if (looks_like_noise && current.len > 0) {
                PN5180_LOGD(TAG, "scan %d: abandoning noisy branch (len=%d)", scan_count, current.len);
                continue;
            }

            // Safety mechanism for root noise:
            // If we are at len=0, and we exhausted retries with "looks like noise" (0 bytes) status,
            // we should probably split, BUT if the split branches also show noise immediately,
            // we will catch them in the next iteration's "abandoning noisy branch" check.
            // So we proceed to split here for len=0 even if noisy.

            // If retries exhausted OR it looks like a clean collision, SPLIT
            if (current.len < 16) {
                if ((size_t)stack_ptr + 2 <= ARRAY_SIZE(stack)) {
                    // Push '1' branch
                    stack[stack_ptr].len     = current.len + 1;
                    stack[stack_ptr].val     = current.val | (1ULL << current.len);
                    stack[stack_ptr].retries = 0;
                    stack_ptr++;

                    // Push '0' branch
                    stack[stack_ptr].len     = current.len + 1;
                    stack[stack_ptr].val     = current.val; // Bit is 0
                    stack[stack_ptr].retries = 0;
                    stack_ptr++;
                } else {
                    ESP_LOGW(TAG, "DFS stack overflow!");
                }
            } else {
                ESP_LOGW(TAG, "Max collision depth reached at len=%d", current.len);
            }
            continue;
        }

        // No collision, check data
        // A frame flagged with an RX error is still taken if it is complete, as before.
        if (rx_len >= 10) {
            {
                // rx_buf[1]=DSFID, [2..9]=UID
                // Check flags in rx_buf[0]? Usually 0x00.

                // PN5180_LOGD(TAG, "scan %d: data received", scan_count);
                if (1) { // Accept any valid frame structure
                    uint8_t *uid_ptr = &rx_buf[2];
                    ESP_LOGI(TAG, "Tag Found! UID: %02x%02x%02x%02x%02x%02x%02x%02x", uid_ptr[0], uid_ptr[1], uid_ptr[2], uid_ptr[3], uid_ptr[4], uid_ptr[5],
                             uid_ptr[6], uid_ptr[7]);

                    uint32_t agc_reg = 0;
                    pn5180_read_register(pn5180, PN5180_RF_STATUS, &agc_reg);
                    uint16_t current_agc = (uint16_t)(agc_reg & PN5180_RF_STATUS_AGC_MASK);
                    ESP_LOGI(TAG, "AGC Value: %u", (unsigned)current_agc);

                    bool is_new = pn5180_iso15693_collect_uid(uids, uid_ptr, 8, current_agc);
                    if (is_new) {
                        total_found++;
                    }
                    // Quiet this tag so we don't see it again in parent recursions
                    pn5180_iso15693_stay_quiet(pn5180, uid_ptr);
                }
            }
        }
    }

    PN5180_LOGD(TAG, "inventory: total found %d tags", total_found);
    return total_found > 0;
}

/**
 * @brief Sends ISO15693 Stay Quiet command to a specific tag
 */
static bool pn5180_iso15693_stay_quiet(pn5180_t *pn5180, uint8_t *uid)
{
    PN5180_LOGD(TAG, "stay_quiet: sending");
    uint8_t quiet_cmd[10];
    size_t  cmd_len =
        pn5180_iso15693_build_cmd(quiet_cmd, sizeof(quiet_cmd), ISO15693_FLAG_ADDRESS | ISO15693_FLAG_DATA_RATE_HIGH, ISO15693_CMD_STAY_QUIET, uid);
    if (cmd_len == 0) {
        PN5180_LOGD(TAG, "stay_quiet: build failed");
        return false;
    }
    // Stay Quiet has no response: the frame is done once the transmission has ended.
    return pn5180_rf_transceive(pn5180, quiet_cmd, cmd_len, 0, NULL, 0, NULL, 0, NULL) == PN5180_RF_OK;
}

static bool pn5180_iso15693_select_by_uid( //
    pn5180_t     *pn5180,                  //
    pn5180_uid_t *uid                      //
)
{
    if (pn5180 == NULL || uid == NULL) {
        PN5180_LOGD(TAG, "select_by_uid: invalid args");
        return false;
    }
    if (uid->uid_length != 8) {
        PN5180_LOGD(TAG, "select_by_uid: invalid uid length %d", uid->uid_length);
        return false;
    }

    uint8_t select_cmd[10];
    size_t  cmd_len =
        pn5180_iso15693_build_cmd(select_cmd, sizeof(select_cmd), ISO15693_FLAG_ADDRESS | ISO15693_FLAG_DATA_RATE_HIGH, ISO15693_CMD_SELECT, uid->uid);
    if (cmd_len == 0) {
        PN5180_LOGD(TAG, "select_by_uid: build failed");
        return false;
    }

    uint16_t num_bytes = 0;
    uint8_t  rx_buf[8];
    if (!pn5180_iso15693_exchange(pn5180, select_cmd, cmd_len, rx_buf, sizeof(rx_buf), &num_bytes, PN5180_TIMEOUT_15693_US)) {
        PN5180_LOGD(TAG, "select_by_uid: no valid response");
        return false;
    }
    if (!pn5180_iso15693_check_response("select_by_uid", rx_buf, num_bytes)) {
        return false;
    }

    PN5180_LOGD(TAG, "select_by_uid: selected");
    return true;
}

static bool _pn5180_15693_select_by_uid(pn5180_proto_t *proto, pn5180_uid_t *uid)
{
    return pn5180_iso15693_select_by_uid(proto->pn5180, uid);
}

// ISO15693 halt: Reset to Ready in Select mode, which returns the selected tag to the Ready state.
// Stay Quiet cannot be used here: it is only valid in Addressed mode and the UID is not known at this point.
static bool pn5180_iso15693_halt(pn5180_t *pn5180)
{
    if (pn5180 == NULL) {
        PN5180_LOGD(TAG, "halt: invalid pn5180");
        return false;
    }
    uint8_t halt_cmd[2];
    halt_cmd[0] = ISO15693_FLAG_SELECTED | ISO15693_FLAG_DATA_RATE_HIGH;
    halt_cmd[1] = ISO15693_CMD_RESET_TO_READY;

    PN5180_LOGD(TAG, "halt: sending Reset to Ready (selected)");
    uint16_t num_bytes = 0;
    uint8_t  rx_buf[8];
    if (!pn5180_iso15693_exchange(pn5180, halt_cmd, sizeof(halt_cmd), rx_buf, sizeof(rx_buf), &num_bytes, PN5180_TIMEOUT_15693_US)) {
        PN5180_LOGD(TAG, "halt: no valid response");
        return false;
    }
    return pn5180_iso15693_check_response("halt", rx_buf, num_bytes);
}

static bool _pn5180_15693_halt(pn5180_proto_t *proto)
{
    return pn5180_iso15693_halt(proto->pn5180);
}

static bool pn5180_iso15693_get_system_info(pn5180_t *pn5180, uint8_t *buf, size_t buf_len, size_t *out_len)
{
    if (pn5180 == NULL || buf == NULL || buf_len == 0 || out_len == NULL) {
        PN5180_LOGD(TAG, "sysinfo: invalid args");
        return false;
    }

    uint8_t cmd[2];
    size_t  cmd_len = pn5180_iso15693_build_cmd(cmd, sizeof(cmd), ISO15693_FLAG_SELECTED | ISO15693_FLAG_DATA_RATE_HIGH, ISO15693_CMD_GET_SYSTEM_INFO, NULL);
    if (cmd_len == 0) {
        PN5180_LOGD(TAG, "sysinfo: build failed");
        return false;
    }

    uint16_t num_bytes = 0;
    if (!pn5180_iso15693_exchange(pn5180, cmd, cmd_len, buf, buf_len, &num_bytes, PN5180_TIMEOUT_15693_US)) {
        PN5180_LOGD(TAG, "sysinfo: no valid response");
        return false;
    }
    if (!pn5180_iso15693_check_response("sysinfo", buf, num_bytes)) {
        return false;
    }
    if (num_bytes == 0) {
        PN5180_LOGD(TAG, "sysinfo: no data");
        return false;
    }

    *out_len = (num_bytes > buf_len) ? buf_len : num_bytes;
    return true;
}

static bool pn5180_iso15693_block_read(pn5180_t *pn5180, int blockno, uint8_t *buffer, size_t buffer_len)
{
    if (pn5180 == NULL || buffer == NULL || buffer_len == 0) {
        PN5180_LOGD(TAG, "block_read: invalid args");
        return false;
    }

    pn5180_enable_crc(pn5180);

    uint8_t cmd[4];
    size_t  cmd_len = 0;

    cmd[0] = ISO15693_FLAG_SELECTED | ISO15693_FLAG_DATA_RATE_HIGH;
    if (blockno <= 0xFF) {
        cmd[1]  = ISO15693_CMD_READ_SINGLE;
        cmd[2]  = (uint8_t)blockno;
        cmd_len = 3;
    } else {
        cmd[1]  = ISO15693_CMD_READ_SINGLE_EXT;
        cmd[2]  = (uint8_t)(blockno & 0xFF);
        cmd[3]  = (uint8_t)((blockno >> 8) & 0xFF);
        cmd_len = 4;
    }

    uint8_t  temp[64];
    uint16_t num_bytes = 0;
    if (!pn5180_iso15693_exchange(pn5180, cmd, cmd_len, temp, sizeof(temp), &num_bytes, PN5180_TIMEOUT_15693_US)) {
        PN5180_LOGD(TAG, "block_read: no valid response block=%d", blockno);
        return false;
    }
    if (num_bytes < 2) {
        PN5180_LOGD(TAG, "block_read: rx too short (%u)", (unsigned)num_bytes);
        return false;
    }
    if (!pn5180_iso15693_check_response("block_read", temp, num_bytes)) {
        return false;
    }

    size_t data_len = num_bytes - 1;
    if (data_len < buffer_len) {
        // The tag's blocks are shorter than the caller assumes: the rest of the buffer would stay unset.
        ESP_LOGE(TAG, "block_read: block %d has %u bytes, %u expected", blockno, (unsigned)data_len, (unsigned)buffer_len);
        return false;
    }
    memcpy(buffer, &temp[1], buffer_len);
    return true;
}

static int pn5180_iso15693_block_write(pn5180_t *pn5180, int blockno, const uint8_t *buffer, size_t buffer_len)
{
    if (pn5180 == NULL || buffer == NULL) {
        PN5180_LOGD(TAG, "block_write: invalid args");
        return -1;
    }

    pn5180_enable_crc(pn5180);

    if (buffer_len == 0 || buffer_len > 32) {
        PN5180_LOGD(TAG, "block_write: unsupported block size %zu", buffer_len);
        return -2;
    }

    uint8_t cmd[1 + 1 + 2 + 32];
    size_t  cmd_len = 0;

    cmd[0] = ISO15693_FLAG_SELECTED | ISO15693_FLAG_DATA_RATE_HIGH;
    if (blockno <= 0xFF) {
        cmd[1]  = ISO15693_CMD_WRITE_SINGLE;
        cmd[2]  = (uint8_t)blockno;
        cmd_len = 3;
    } else {
        cmd[1]  = ISO15693_CMD_WRITE_SINGLE_EXT;
        cmd[2]  = (uint8_t)(blockno & 0xFF);
        cmd[3]  = (uint8_t)((blockno >> 8) & 0xFF);
        cmd_len = 4;
    }

    memcpy(&cmd[cmd_len], buffer, buffer_len);
    cmd_len += buffer_len;

    uint8_t  temp[32];
    uint16_t num_bytes = 0;
    if (!pn5180_iso15693_exchange(pn5180, cmd, cmd_len, temp, sizeof(temp), &num_bytes, PN5180_TIMEOUT_15693_WRITE_US)) {
        PN5180_LOGD(TAG, "block_write: no valid response block=%d", blockno);
        return -4;
    }
    if (num_bytes == 0) {
        PN5180_LOGD(TAG, "block_write: no response");
        return -8;
    }
    if (!pn5180_iso15693_check_response("block_write", temp, num_bytes)) {
        return -9;
    }

    return 0;
}

static bool _pn5180_15693_block_read(pn5180_proto_t *proto, int blockno, uint8_t *buffer, size_t buffer_len)
{
    return pn5180_iso15693_block_read(proto->pn5180, blockno, buffer, buffer_len);
}

static int _pn5180_15693_block_write(pn5180_proto_t *proto, int blockno, const uint8_t *buffer, size_t buffer_len)
{
    return pn5180_iso15693_block_write(proto->pn5180, blockno, buffer, buffer_len);
}

static bool _pn5180_15693_detect_card_type_and_capacity( //
    pn5180_t     *pn5180,                                //
    pn5180_uid_t *uid,                                   //
    int          *blocks_count,                          //
    int          *block_size                             //
)
{
    if (pn5180 == NULL || uid == NULL || blocks_count == NULL || block_size == NULL) {
        PN5180_LOGD(TAG, "detect: invalid args");
        return false;
    }

    uid->subtype  = PN5180_15693;
    *block_size   = 4;
    *blocks_count = 0;

    uint8_t sysinfo[32];
    size_t  sysinfo_len = 0;
    if (pn5180_iso15693_get_system_info(pn5180, sysinfo, sizeof(sysinfo), &sysinfo_len)) {
        if (sysinfo_len >= 10) { // Flags(1) + InfoFlags(1) + UID(8) = 10 bytes min
            uint8_t info_flags = sysinfo[1];
            size_t  idx        = 2 + 8; // Skip Flags, InfoFlags, and UID (8 bytes)

            if (info_flags & 0x01) idx++; // DSFID
            if (info_flags & 0x02) idx++; // AFI
            if ((info_flags & 0x04) && (idx + 1 < sysinfo_len)) {
                uint8_t blocks = sysinfo[idx++];
                uint8_t bsize  = sysinfo[idx++];
                // ISO15693 encodes (blocks - 1) and (block_size - 1) in System Info.
                // The block size byte also carries flags in the upper bits; size is in bits [4:0].
                *blocks_count = (int)blocks + 1;
                *block_size   = (int)(bsize & 0x1F) + 1;
            }
        }
    }

    uid->block_size   = *block_size;
    uid->blocks_count = *blocks_count;
    PN5180_LOGD(TAG, "detect: block_size=%d blocks_count=%d", *block_size, *blocks_count);
    return false;
}

static pn5180_uids_array_t *pn5180_15693_get_all_uids(pn5180_t *pn5180, bool *fatal)
{
    *fatal = false;
    if (pn5180 == NULL) {
        PN5180_LOGD(TAG, "get_all_uids: pn5180 is NULL");
        return NULL;
    }

    pn5180_uids_array_t *uids = NULL;

    // Prioritize ASK 10% (0x0E) which provides better power stability prevents
    // tags from resetting their "Stay Quiet" state during modulation.
    // Try ASK 100% (0x0D) as fallback.
    const uint8_t rf_fallbacks[] = {PN5180_15693_26KASK10, PN5180_15693_26KASK100};

    PN5180_LOGD(TAG, "get_all_uids: start");

    for (size_t rf_idx = 0; rf_idx < ARRAY_SIZE(rf_fallbacks); rf_idx++) {
        if (!pn5180_15693_setup_rf(pn5180, rf_fallbacks[rf_idx])) {
            continue;
        }

        // Try high data rate first
        pn5180->iso15693_use_high_rate = true;
        pn5180_15693_inventory_single_slot(pn5180, &uids, fatal);

        if (uids == NULL || uids->uids_count == 0) {
            if (uids != NULL) {
                free(uids);
                uids = NULL;
            }
            // Retry with low data rate
            pn5180->iso15693_use_high_rate = false;
            PN5180_LOGD(TAG, "get_all_uids: retry with low data rate");
            pn5180_15693_inventory_single_slot(pn5180, &uids, fatal);
        }

        // ASK 100 % is only the fallback: tags found with the first configuration end the search.
        // A second pass would also leave the other RF configuration loaded and mix the signal
        // strength values of two passes.
        if ((uids != NULL && uids->uids_count > 0) || *fatal) {
            break;
        }
    }

    if (uids != NULL && uids->uids_count == 0) {
        free(uids);
        uids = NULL;
    }

    if (uids != NULL && uids->uids_count > 1) {
        // Simple Bubble Sort for small array (theoretical max ~14 tags)
        for (int i = 0; i < uids->uids_count - 1; i++) {
            for (int j = 0; j < uids->uids_count - i - 1; j++) {
                if (uids->uids[j].agc > uids->uids[j + 1].agc) {
                    pn5180_uid_t temp = uids->uids[j];
                    uids->uids[j]     = uids->uids[j + 1];
                    uids->uids[j + 1] = temp;
                }
            }
        }
    }

    PN5180_LOGD(TAG, "get_all_uids: done count=%d", uids ? uids->uids_count : 0);
    return uids;
}

static pn5180_uids_array_t *_pn5180_15693_get_all_uids(pn5180_proto_t *proto)
{
    bool fatal;
    return pn5180_15693_get_all_uids(proto->pn5180, &fatal);
}

pn5180_uids_array_t *pn5180_15693_get_all_uids_ex(pn5180_proto_t *proto, pn5180_poll_status_t *status)
{
    pn5180_poll_status_t local_status = PN5180_POLL_INVALID_ARGUMENT;
    pn5180_uids_array_t *uids         = NULL;
    if (proto != NULL && proto->pn5180 != NULL) {
        bool fatal = false;
        uids       = pn5180_15693_get_all_uids(proto->pn5180, &fatal);
        if (uids != NULL) {
            local_status = PN5180_POLL_FOUND;
        } else {
            // The inventory tries two RF configurations; if the field is still off, none could be set up.
            local_status = (proto->pn5180->is_rf_on && !fatal) ? PN5180_POLL_NO_TARGET : PN5180_POLL_TRANSPORT_ERROR;
        }
    }
    if (status != NULL) {
        *status = local_status;
    }
    return uids;
}

pn5180_proto_t *pn5180_15693_init(pn5180_t *pn5180, pn5180_15693_rf_config_t rf_config)
{
    PN5180_LOGD(TAG, "init: rf_config=0x%02x", rf_config);
    pn5180_proto_t *proto = calloc(1, sizeof(pn5180_proto_t));
    if (proto == NULL) {
        return NULL;
    }
    proto->rf_config                     = (uint8_t)rf_config;
    proto->pn5180                        = pn5180;
    proto->setup_rf                      = _pn5180_15693_setup_rf;
    proto->get_all_uids                  = _pn5180_15693_get_all_uids;
    proto->select_by_uid                 = _pn5180_15693_select_by_uid;
    proto->halt                          = _pn5180_15693_halt;
    proto->block_read                    = _pn5180_15693_block_read;
    proto->block_write                   = _pn5180_15693_block_write;
    proto->authenticate                  = NULL;
    proto->detect_card_type_and_capacity = _pn5180_15693_detect_card_type_and_capacity;
    return proto;
}
