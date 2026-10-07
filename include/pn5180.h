#pragma once

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PN5180_MIFARE_CLASSIC_KEYA 0x60 // Mifare Classic key A
#define PN5180_MIFARE_CLASSIC_KEYB 0x61 // Mifare Classic key B

// PN5180 IRQ_STATUS
#define PN5180_RX_IRQ_STAT              (1 << 0)  // End of RF receiption IRQ
#define PN5180_TX_IRQ_STAT              (1 << 1)  // End of RF transmission IRQ
#define PN5180_IDLE_IRQ_STAT            (1 << 2)  // IDLE IRQ
#define PN5180_MODE_DETECTED_IRQ_STAT   (1 << 3)  // Mode detected IRQ
#define PN5180_CARD_ACTIVATED_IRQ_STAT  (1 << 4)  // Card activated IRQ
#define PN5180_STATE_CHANGE_IRQ_STAT    (1 << 5)  // State Change in the transceive state machine IRQ
#define PN5180_RFOFF_DET_IRQ_STAT       (1 << 6)  // RF Field OFF detection IRQ
#define PN5180_RFON_DET_IRQ_STAT        (1 << 7)  // RF Field ON detection IRQ
#define PN5180_TX_RFOFF_IRQ_STAT        (1 << 8)  // RF Field OFF in PCD IRQ
#define PN5180_TX_RFON_IRQ_STAT         (1 << 9)  // RF Field ON in PCD IRQ
#define PN5180_RF_ACTIVE_ERROR_IRQ_STAT (1 << 10) // RF Active error IRQ
#define PN5180_TIMER0_IRQ_STAT          (1 << 11) // Timer 0 IRQ
#define PN5180_TIMER1_IRQ_STAT          (1 << 12) // Timer 1 IRQ
#define PN5180_TIMER2_IRQ_STAT          (1 << 13) // RX Timeout IRQ
#define PN5180_RX_SOF_DET_IRQ_STAT      (1 << 14) // RF SOF Detection IRQ
#define PN5180_RX_SC_DET_IRQ_STAT       (1 << 15) // RF SCD Detection IRQ
#define PN5180_TEMPSENS_ERROR_IRQ_STAT  (1 << 16) // Temperature Sensor Error IRQ
#define PN5180_GENERAL_ERROR_IRQ_STAT   (1 << 17) // General error IRQ
#define PN5180_HV_ERROR_IRQ_STAT        (1 << 18) // High Voltage error IRQ
#define PN5180_LPCD_IRQ_STAT            (1 << 19) // LPCD Detection IRQ

// PN5180 RX_STATUS
#define PN5180_RX_COLL_POS_START            19 // Bits [25:19] - bit position of the first detected collision in a received frame
#define PN5180_RX_COLL_POS_MASK             0x7F
#define PN5180_RX_COLLISION_DETECTED        (1 << 18) // Bit 18 - Collision detected flag
#define PN5180_RX_PROTOCOL_ERROR            (1 << 17) // Bit 17 - Protocol error flag
#define PN5180_RX_DATA_INTEGRITY_ERROR      (1 << 16) // Bit 16 - Data integrity error flag
#define PN5180_RX_NUM_LAST_BITS_START       13        // Bits [15:13] - Number of valid bits in the last received byte
#define PN5180_RX_NUM_LAST_BITS_MASK        0x07
#define PN5180_RX_NUM_FRAMES_RECEIVED_START 9 // Bits [12:9] - Number of frames received
#define PN5180_RX_NUM_FRAMES_RECEIVED_MASK  0x0F
#define PN5180_RX_BYTES_RECEIVED_START      0 // Bits [8:0] - Number of bytes received
#define PN5180_RX_BYTES_RECEIVED_MASK       0x1FF

// PN5180 EEPROM Addresses
#define PN5180_DIE_IDENTIFIER   (0x00)
#define PN5180_PRODUCT_VERSION  (0x10)
#define PN5180_FIRMWARE_VERSION (0x12)
#define PN5180_EEPROM_VERSION   (0x14)
#define PN5180_IDLE_IRQ_AFTER_BOOT (0x16) // Non-zero: IDLE IRQ is raised when the boot has finished
#define PN5180_IRQ_PIN_CONFIG   (0x1A)
#define PN5180_IRQ_PIN_CONFIG_ACTIVE_HIGH        0x01u // Bit 0 - IRQ pin is active high
#define PN5180_IRQ_PIN_CONFIG_AUTO_CLEAR_ON_READ 0x02u // Bit 1 - IRQ pin is cleared by reading IRQ_STATUS
#define PN5180_EEPROM_MIN_ADDR      0x16u
#define PN5180_EEPROM_MAX_ADDR      0xFDu
#define PN5180_MIN_FIRMWARE_VERSION 0x0304u
#define PN5180_FIRMWARE_VERSION_3_A 0x030Au // First firmware with the LPCD reference modes of datasheet rev. 4.0
#define PN5180_MAX_WAKEUP_COUNTER_MS 2690u

// PN5180 EEPROM Addresses - LPCD (Low Power Card Detection)
#define PN5180_DPC_XI (0x5C) // DPC AGC Trim Value

// PN5180 Registers
#define PN5180_SYSTEM_CONFIG      (0x00)
#define PN5180_IRQ_ENABLE         (0x01)
#define PN5180_IRQ_STATUS         (0x02)
#define PN5180_IRQ_CLEAR          (0x03)
#define PN5180_TRANSCEIVE_CONTROL (0x04)
#define PN5180_TIMER1_RELOAD      (0x0c)
#define PN5180_TIMER1_CONFIG      (0x0f)
// TIMER1_CONFIG register bit masks
#define PN5180_TIMER1_CONFIG_ENABLE             (1u << 0)  // Bit 0 - Timer enabled
#define PN5180_TIMER1_CONFIG_MODE_SEL           (1u << 2)  // Bit 2 - Use the prescaler clock
#define PN5180_TIMER1_CONFIG_PRESCALE_53KHZ     (7u << 3)  // Bits 5:3 - 53 kHz prescaler clock
#define PN5180_TIMER1_CONFIG_START_ON_TX_ENDED  (1u << 11) // Bit 11 - Start when a transmission ends
#define PN5180_TIMER1_CONFIG_STOP_ON_RX_STARTED (1u << 20) // Bit 20 - Stop when a reception begins
#define PN5180_TIMER_RELOAD_MAX                 0x000FFFFFu
#define PN5180_RX_WAIT_CONFIG     (0x11)
#define PN5180_CRC_RX_CONFIG      (0x12)
#define PN5180_RX_STATUS          (0x13)
#define PN5180_TX_WAIT_CONFIG     (0x17)
#define PN5180_TX_CONFIG          (0x18)
#define PN5180_CRC_TX_CONFIG      (0x19)
#define PN5180_SIGPRO_RM_CONFIG   (0x1C)
#define PN5180_RF_STATUS          (0x1d)
#define PN5180_SYSTEM_STATUS      (0x24)
#define PN5180_TEMP_CONTROL       (0x25)
#define PN5180_AGC_REF_CONFIG     (0x26)
#define PN5180_RF_STATUS_AGC_MASK            0x000003FFu
#define PN5180_RF_STATUS_TX_RF_STATUS_MASK   0x00020000u  // Bit 17 - TX RF drivers on (RF field created)
#define PN5180_RF_STATUS_RF_DET_STATUS_MASK  0x00010000u  // Bit 16 - External RF field detected

// SYSTEM_CONFIG register bit masks
#define PN5180_SYSTEM_CONFIG_MFC_CRYPTO_ON      (1 << 6)   // Bit 6 - MIFARE Crypto1 enabled
#define PN5180_SYSTEM_CONFIG_TX_MODE_MASK       0x00000007 // Bits 0-2 - Transceiver mode
#define PN5180_SYSTEM_CONFIG_TX_MODE_IDLE       0x00000000
#define PN5180_SYSTEM_CONFIG_TX_MODE_TRANSCEIVE 0x00000003
#define PN5180_SYSTEM_CONFIG_CLEAR_CRYPTO_MASK  0xFFFFFFBF // ~(1<<6) - Clear MFC_CRYPTO_ON bit
#define PN5180_SYSTEM_CONFIG_CLEAR_TX_MODE_MASK 0xFFFFFFF8 // ~0x07 - Clear transceiver state bits

// CRC_RX_CONFIG register bit masks (register 0x12)
#define PN5180_CRC_RX_CONFIG_RX_BIT_ALIGN_POS               6u
#define PN5180_CRC_RX_CONFIG_RX_BIT_ALIGN_MASK              0x000001C0u  // Bits [8:6] - RX bit alignment
#define PN5180_CRC_RX_CONFIG_VALUES_AFTER_COLLISION_MASK     0x00000200u  // Bit 9 - Keep bit values after collision

/** @brief SPI configuration and handle for PN5180 */
typedef struct _pn5180_spi_t
{
    gpio_num_t          sck;
    gpio_num_t          miso;
    gpio_num_t          mosi;
    int                 clock_speed_hz;
    spi_device_handle_t spi_handle;
    spi_host_device_t   host_id;
    bool                owns_bus; /**< The bus was initialized by pn5180_spi_init() and may be freed by pn5180_deinit() */
} pn5180_spi_t;

#define PN5180_MAX_BUF_SIZE 512 // Maximum buffer size for PN5180 commands

/** @brief PN5180 device context */
typedef struct _pn5180_t
{
    uint8_t      *send_buf;
    uint8_t      *recv_buf;
    int64_t       timeout_ms;
    pn5180_spi_t *spi;
    gpio_num_t    nss;
    gpio_num_t    busy;
    gpio_num_t    rst;
    gpio_num_t    irq;              /**< IRQ pin, GPIO_NUM_NC unless pn5180_irq_attach() was called */
    void         *irq_sem;          /**< Binary semaphore given from the IRQ pin interrupt */
    bool          irq_active_high;  /**< IRQ pin polarity, read from EEPROM IRQ_PIN_CONFIG */
    void         *poll_timer;       /**< High-resolution timer that paces IRQ_STATUS polling without an IRQ pin */
    void         *poll_sem;         /**< Binary semaphore given when poll_timer expires */
    uint8_t       tx_config;        /**< RF configuration last loaded with pn5180_load_rf_config() */
    bool          rf_config_loaded; /**< tx_config is valid */
    bool          is_rf_on;
    uint16_t      firmware_version; /**< Firmware version read from EEPROM at init, major in the high byte */
    bool          hw_rx_timeout;    /**< Use Timer1 as the receive timeout in pn5180_rf_transceive() */
    bool          rfca_disabled;    /**< Switch the field on without RF collision avoidance */
    uint32_t      rf_guard_time_us; /**< Delay after the field has been switched on */

    // ISO14443-4 State
    uint8_t iso14443_current_card_type; // Maps to pn5180_card_type_t, but using uint8_t to avoid circular dependency if valid
    uint8_t iso14443_block_number;      // PCB toggle
    uint16_t iso14443_frame_size;       // Max ISO14443-4 frame size excluding CRC bytes
    int64_t  iso14443_fwt_ms;           // Frame waiting time derived from ATS
    bool    iso14443_layer4_active;

    // ISO15693 State
    bool iso15693_use_high_rate;
} pn5180_t;

/**
 * @brief NFC card type/subtype enumeration
 *
 * Identifies the specific card type detected during anticollision.
 * Used to determine authentication requirements and memory layout.
 */
typedef enum _pn5180_nfc_subtype_t
{
    PN5180_MIFARE_UNKNOWN = 0,    /**< Unknown or unidentified card */
    PN5180_MIFARE_CLASSIC_1K,     /**< MIFARE Classic 1K (16 sectors, 64 blocks) */
    PN5180_MIFARE_CLASSIC_MINI,   /**< MIFARE Classic Mini (5 sectors, 20 blocks) */
    PN5180_MIFARE_CLASSIC_4K,     /**< MIFARE Classic 4K (40 sectors, 256 blocks) */
    PN5180_MIFARE_ULTRALIGHT,     /**< MIFARE Ultralight (64 bytes, no auth) */
    PN5180_MIFARE_ULTRALIGHT_C,   /**< MIFARE Ultralight C (192 bytes, 3DES auth) */
    PN5180_MIFARE_ULTRALIGHT_EV1, /**< MIFARE Ultralight EV1 (48/128 pages) */
    PN5180_MIFARE_NTAG213,        /**< NTAG213 (144 bytes user memory) */
    PN5180_MIFARE_NTAG215,        /**< NTAG215 (504 bytes user memory) */
    PN5180_MIFARE_NTAG216,        /**< NTAG216 (888 bytes user memory) */
    PN5180_MIFARE_PLUS_2K,        /**< MIFARE Plus 2K (security level dependent) */
    PN5180_MIFARE_PLUS_4K,        /**< MIFARE Plus 4K (security level dependent) */
    PN5180_MIFARE_DESFIRE,        /**< MIFARE DESFire (ISO 14443-4, file-based) */
    PN5180_15693,                 /**< ISO 15693 vicinity card */
    PN5180_MIFARE_NTAG210,        /**< NTAG210 (48 bytes user memory) */
    PN5180_MIFARE_NTAG212         /**< NTAG212 (128 bytes user memory) */
} __attribute__((__packed__)) pn5180_card_type_t;

/** @brief Outcome of a card poll, see pn5180_14443_get_all_uids_ex() and pn5180_15693_get_all_uids_ex() */
typedef enum
{
    PN5180_POLL_FOUND = 0,        /**< At least one card was found; the UID array is returned */
    PN5180_POLL_NO_TARGET,        /**< No card answered */
    PN5180_POLL_TRANSPORT_ERROR,  /**< The PN5180 could not be driven (SPI failure, RF field did not come up) */
    PN5180_POLL_PROTOCOL_ERROR,   /**< A card answered but anticollision or selection failed */
    PN5180_POLL_NO_MEMORY,        /**< Memory allocation for the UID array failed */
    PN5180_POLL_INVALID_ARGUMENT  /**< NULL protocol or device pointer */
} pn5180_poll_status_t;

/**
 * @brief UID metadata and block geometry for a detected card
 *
 * Contains all information gathered during card detection and type identification.
 */
typedef struct
{
    int8_t     uid_length;   /**< UID length in bytes (4, 7, or 10 for ISO14443; 8 for ISO15693) */
    uint8_t    sak;          /**< Select Acknowledge byte (ISO14443A only, indicates card capabilities) */
    uint16_t   agc;          /**< AGC value from RF_STATUS (lower = stronger signal = closer card) */
    int        block_size;   /**< Block size in bytes (16 for Classic, 4 for Ultralight, varies for 15693) */
    int        blocks_count; /**< Total number of blocks on card */
    pn5180_card_type_t subtype;      /**< Detected card type/subtype */
    uint8_t    uid[10];      /**< Card UID bytes (length indicated by uid_length) */
    uint8_t    atqa[2];      /**< ATQA as received, first byte first (ISO14443A only; 44 00 for Ultralight) */
} pn5180_uid_t;

/**
 * @brief Dynamic array of detected card UIDs
 *
 * Heap-allocated structure returned by get_all_uids().
 * Uses flexible array member pattern - actual size is sizeof(pn5180_uids_array_t) + (uids_count-1)*sizeof(pn5180_uid_t).
 * Caller must free() after use.
 */
typedef struct
{
    int       uids_count; /**< Number of cards detected */
    pn5180_uid_t uids[1];    /**< Flexible array of UID entries */
} pn5180_uids_array_t;

struct _pn5180_proto_t;

/**
 * @brief Callback: Enumerate all cards in RF field
 * @param pn5180_proto Protocol interface
 * @return Heap-allocated array of UIDs (caller must free), or NULL if none found
 */
typedef pn5180_uids_array_t *pn5180_func_get_all_uids_t(struct _pn5180_proto_t *pn5180_proto);

/**
 * @brief Callback: Configure RF field for protocol
 * @param pn5180_proto Protocol interface
 * @return true on success, false on failure
 */
typedef bool pn5180_func_setup_rf_t(struct _pn5180_proto_t *pn5180_proto);

/**
 * @brief Callback: Select a specific card by UID
 * @param pn5180_proto Protocol interface
 * @param uid Pointer to UID structure of card to select
 * @return true if card selected successfully, false on failure
 */
typedef bool pn5180_func_select_by_uid_t(        //
    struct _pn5180_proto_t *pn5180_proto, //
    pn5180_uid_t              *uid           //
);

/**
 * @brief Callback: Authenticate for block access (MIFARE Classic)
 * @param pn5180_proto Protocol interface
 * @param key 6-byte authentication key
 * @param key_type Key type: MIFARE_CLASSIC_KEYA (0x60) or MIFARE_CLASSIC_KEYB (0x61)
 * @param uid Card UID for authentication
 * @param blockno Block number to authenticate for (determines sector)
 * @return true if authentication successful, false on failure
 * @note For Ultralight/DESFire, returns true without performing Crypto1 auth
 */
typedef bool pn5180_func_authenticate_t(         //
    struct _pn5180_proto_t *pn5180_proto, //
    const uint8_t          *key,          //
    uint8_t                 key_type,      //
    const pn5180_uid_t        *uid,          //
    int                     blockno       //
);
/**
 * @brief Callback: Detect card type and memory geometry
 * @param pn5180 PN5180 device handle
 * @param uid UID structure to update with subtype and geometry
 * @param blocks_count Output: total number of blocks on card
 * @param block_size Output: size of each block in bytes
 * @return true if card must be re-selected after detection, false otherwise
 * @note May perform additional commands (GET_VERSION, etc.) that invalidate selection
 */
typedef bool pn5180_func_detect_card_type_t( //
    pn5180_t  *pn5180,                 //
    pn5180_uid_t *uid,                    //
    int       *blocks_count,           //
    int       *block_size              //
);

/**
 * @brief Callback: Read a block from the selected card
 * @param pn5180_proto Protocol interface
 * @param blockno Block number to read
 * @param buffer Destination buffer for block data
 * @param buffer_len Size of destination buffer
 * @return true on success, false on failure
 */
typedef bool pn5180_func_block_read_t(struct _pn5180_proto_t *pn5180_proto, int blockno, uint8_t *buffer, size_t buffer_len);

/**
 * @brief Callback: Write a block to the selected card
 * @param pn5180_proto Protocol interface
 * @param blockno Block number to write
 * @param buffer Source buffer containing block data
 * @param buffer_len Size of source buffer
 * @return 0 on success, negative error code on failure
 */
typedef int pn5180_func_block_write_t(struct _pn5180_proto_t *pn5180_proto, int blockno, const uint8_t *buffer, size_t buffer_len);

/**
 * @brief Callback: Halt or deselect the currently selected card
 * @param pn5180_proto Protocol interface
 * @return true on success, false on failure
 * @note ISO14443A: after HALT, card must receive WUPA (not REQA) to wake up
 * @note ISO15693: sends Reset to Ready in Select mode; the tag returns to the Ready state.
 *       The command is optional in ISO15693, so this fails on tags that do not implement it.
 */
typedef bool pn5180_func_halt_t(struct _pn5180_proto_t *pn5180_proto);

/**
 * @brief Protocol interface for card operations
 *
 * Abstract interface providing protocol-agnostic card operations.
 * Implementations exist for ISO14443A (pn5180-14443.h) and ISO15693 (pn5180-15693.h).
 * All callbacks operate on an already-initialized PN5180 device.
 */
typedef struct _pn5180_proto_t
{
    pn5180_t                       *pn5180;                        /**< Underlying PN5180 device handle */
    pn5180_func_setup_rf_t         *setup_rf;                      /**< Configure RF field for this protocol */
    pn5180_func_get_all_uids_t     *get_all_uids;                  /**< Enumerate all cards in field */
    pn5180_func_select_by_uid_t    *select_by_uid;                 /**< Select specific card by UID */
    pn5180_func_block_read_t       *block_read;                    /**< Read block from selected card */
    pn5180_func_block_write_t      *block_write;                   /**< Write block to selected card */
    pn5180_func_authenticate_t     *authenticate;                  /**< Authenticate sector (MIFARE Classic) */
    pn5180_func_detect_card_type_t *detect_card_type_and_capacity; /**< Detect card type and geometry */
    pn5180_func_halt_t             *halt;                          /**< Halt/deselect current card */
    uint8_t                         rf_config;                     /**< RF configuration loaded by setup_rf() */
} pn5180_proto_t;

/**
 * @brief PN5180 transceiver state machine states
 *
 * Reflects the internal state of the PN5180 RF transceiver.
 * Read via pn5180_get_transceive_state().
 */
typedef enum
{
    PN5180_TS_IDLE         = 0, /**< Transceiver idle, ready for command */
    PN5180_TS_WAIT_TRANSMIT = 1, /**< Waiting to start transmission */
    PN5180_TS_TRANSMITTING = 2, /**< RF transmission in progress */
    PN5180_TS_WAIT_RECEIVE  = 3, /**< Transmission complete, waiting for response */
    PN5180_TS_WAIT_FOR_DATA  = 4, /**< Waiting for data from card */
    PN5180_TS_RECEIVING    = 5, /**< Receiving data from card */
    PN5180_TS_LOOPBACK     = 6, /**< Loopback mode active */
    PN5180_TS_RESERVED     = 7  /**< Reserved state; also returned when the state cannot be read */
} pn5180_transceive_state_t;

/**
 * @brief Initialize SPI interface for PN5180
 * @param host_id SPI host device ID
 * @param sck SPI clock GPIO pin
 * @param miso SPI MISO GPIO pin
 * @param mosi SPI MOSI GPIO pin
 * @param clock_speed_hz SPI clock speed in Hz
 * @return Pointer to initialized SPI structure, or NULL on failure
 */
pn5180_spi_t *pn5180_spi_init(spi_host_device_t host_id, gpio_num_t sck, gpio_num_t miso, gpio_num_t mosi, int clock_speed_hz);

/**
 * @brief Attach the PN5180 to an SPI bus that the application has already initialized
 *
 * Only adds the PN5180 as a device on the bus. The bus is shared with other devices and is
 * never freed by pn5180_deinit(), whatever its free_spi_bus argument says.
 *
 * @param host_id SPI host device ID of the initialized bus
 * @param clock_speed_hz SPI clock speed in Hz
 * @return Pointer to initialized SPI structure, or NULL on failure
 */
pn5180_spi_t *pn5180_spi_attach(spi_host_device_t host_id, int clock_speed_hz);

/**
 * @brief Remove the PN5180 SPI device and free the SPI structure
 *
 * For an SPI structure that is not, or no longer, used by a pn5180_t, for example after
 * pn5180_init() has failed. pn5180_deinit() does this itself for the structure it was given.
 *
 * @param spi SPI structure returned by pn5180_spi_init() or pn5180_spi_attach()
 * @param free_spi_bus If true, also free the bus when it was initialized by pn5180_spi_init()
 */
void pn5180_spi_deinit(pn5180_spi_t *spi, bool free_spi_bus);

/**
 * @brief Initialize PN5180 device
 * @param spi Pointer to initialized SPI structure
 * @param nss NSS (chip select) GPIO pin
 * @param busy BUSY GPIO pin for monitoring device state
 * @param rst RESET GPIO pin
 * @return Pointer to initialized PN5180 structure, or NULL on failure.
 *         On failure @p spi is left untouched and can be passed to pn5180_init() again
 *         or released with pn5180_spi_deinit().
 */
pn5180_t *pn5180_init(pn5180_spi_t *spi, gpio_num_t nss, gpio_num_t busy, gpio_num_t rst);

/**
 * @brief Use the PN5180 IRQ pin instead of polling IRQ_STATUS over SPI
 *
 * Optional. The pin polarity is read from EEPROM (IRQ_PIN_CONFIG). Without an IRQ pin the
 * driver polls IRQ_STATUS; with it, waits block on the interrupt and do not load the CPU.
 * The IRQ pin is required for pn5180_lpcd_wait().
 *
 * @param pn5180 Pointer to PN5180 device structure
 * @param irq GPIO connected to the PN5180 IRQ pin
 * @return true on success, false on failure (the driver keeps polling)
 */
bool pn5180_irq_attach(pn5180_t *pn5180, gpio_num_t irq);

/** @brief Result of an RF exchange, see pn5180_rf_transceive() */
typedef enum
{
    PN5180_RF_OK = 0,    /**< Response received without errors */
    PN5180_RF_TIMEOUT,   /**< No response within the timeout (no card, or the card did not answer) */
    PN5180_RF_COLLISION, /**< Response received with a bit collision; data (cut to the buffer size) and RX_STATUS are returned */
    PN5180_RF_RX_ERROR,  /**< Protocol, parity or CRC error; data is returned unless a general error was raised */
    PN5180_RF_OVERFLOW,  /**< Response is longer than the receive buffer; no data is returned */
    PN5180_RF_FATAL      /**< The PN5180 could not be driven (SPI failure, transmission did not finish) */
} pn5180_rf_result_t;

/**
 * @brief Transmit a frame and receive the response
 *
 * The receive timeout runs on PN5180 Timer1: it starts when the transmission ends and stops
 * when a reception begins, so it measures the card's response delay and does not depend on
 * host timing. CRC and parity handling follow the current CRC_TX_CONFIG / CRC_RX_CONFIG.
 *
 * @param pn5180 Pointer to PN5180 device structure
 * @param tx Frame to transmit
 * @param tx_len Frame length in bytes (1-260)
 * @param tx_last_bits Number of valid bits in the last byte (0 = all 8 bits)
 * @param rx Receive buffer; NULL to discard the response data
 * @param rx_size Size of the receive buffer in bytes
 * @param rx_len Out: number of bytes stored in @p rx (may be NULL)
 * @param timeout_us Time to wait for the start of the response in microseconds. 0 means that no
 *                   response is expected: the call returns when the transmission has ended.
 *                   The hardware timer covers up to about 19.7 s.
 * @param rx_status Out: RX_STATUS register of the reception, for collision position and
 *                  last-bits information (may be NULL)
 * @return Result of the exchange
 */
pn5180_rf_result_t pn5180_rf_transceive( //
    pn5180_t      *pn5180,               //
    const uint8_t *tx,                   //
    size_t         tx_len,               //
    uint8_t        tx_last_bits,         //
    uint8_t       *rx,                   //
    size_t         rx_size,              //
    size_t        *rx_len,               //
    uint32_t       timeout_us,           //
    uint32_t      *rx_status             //
);

/**
 * @brief Select between the Timer1 receive timeout and a host-side timeout
 *
 * Enabled by default. When disabled, pn5180_rf_transceive() does not use Timer1 and waits for
 * the response with a host timer instead, which is less precise and slower to report a
 * missing card.
 */
void pn5180_set_hw_rx_timeout(pn5180_t *pn5180, bool enable);

/**
 * @brief Set the delay inserted after the RF field has been switched on
 *
 * Cards need the unmodulated field for some time before the first command. The default is
 * 5100 us, which covers ISO14443A; ISO15693 needs 1000 us.
 */
void pn5180_set_rf_guard_time_us(pn5180_t *pn5180, uint32_t guard_time_us);

/**
 * @brief Enable or disable RF collision avoidance when the field is switched on
 *
 * Enabled by default: the PN5180 does not switch its field on while another RF field is
 * present. Disable it to force the field on regardless.
 */
void pn5180_set_rfca(pn5180_t *pn5180, bool enable);

/**
 * @brief Reset the PN5180 and restore the RF configuration and field state it had before
 *
 * For recovering a reader that stopped responding. Card state is lost: cards have to be
 * selected again.
 *
 * @return true on success, false on failure
 */
bool pn5180_recover(pn5180_t *pn5180);

/**
 * @brief Deinitialize and free PN5180 device resources
 * @param pn5180 Pointer to PN5180 device structure
 * @param free_spi_bus If true, also free the SPI bus resources
 */
void pn5180_deinit(pn5180_t *pn5180, bool free_spi_bus);

/**
 * @brief Write a 32-bit value to PN5180 register
 * @param pn5180 Pointer to PN5180 device structure
 * @param reg Register address
 * @param value 32-bit value to write
 * @return true on success, false on failure
 */
bool pn5180_write_register(pn5180_t *pn5180, uint8_t reg, uint32_t value);

/**
 * @brief Write to PN5180 register using OR mask (set bits)
 * @param pn5180 Pointer to PN5180 device structure
 * @param addr Register address
 * @param mask OR mask to apply (sets bits)
 * @return true on success, false on failure
 */
bool pn5180_write_register_or_mask(pn5180_t *pn5180, uint8_t addr, uint32_t mask);

/**
 * @brief Write to PN5180 register using AND mask (clear bits)
 * @param pn5180 Pointer to PN5180 device structure
 * @param addr Register address
 * @param mask AND mask to apply (clears bits when mask bit is 0)
 * @return true on success, false on failure
 */
bool pn5180_write_register_and_mask(pn5180_t *pn5180, uint8_t addr, uint32_t mask);

/**
 * @brief Read a 32-bit value from PN5180 register
 * @param pn5180 Pointer to PN5180 device structure
 * @param reg Register address
 * @param value Pointer to store the read value
 * @return true on success, false on failure
 */
bool pn5180_read_register(pn5180_t *pn5180, uint8_t reg, uint32_t *value);

/**
 * @brief Read data from PN5180 EEPROM
 * @param pn5180 Pointer to PN5180 device structure
 * @param addr EEPROM start address (0-254)
 * @param buffer Buffer to store read data
 * @param len Number of bytes to read
 * @return true on success, false on failure
 */
bool pn5180_read_eeprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len);

/**
 * @brief Write data to PN5180 EEPROM
 * @param pn5180 Pointer to PN5180 device structure
 * @param addr EEPROM start address
 * @param buffer Data to write
 * @param len Number of bytes to write
 * @return true on success, false on failure
 */
bool pn5180_write_eeprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len);

/**
 * @brief Send data via RF to card
 * @param pn5180 Pointer to PN5180 device structure
 * @param data Data buffer to send
 * @param len Number of bytes to send (max 260)
 * @param valid_bits Number of valid bits in last byte (0-7, 0 means all 8 bits valid)
 * @return true on success, false on failure
 */
bool pn5180_send_data(pn5180_t *pn5180, const uint8_t *data, int len, uint8_t valid_bits);

/**
 * @brief Read received RF data from reception buffer
 * @param pn5180 Pointer to PN5180 device structure
 * @param len Number of bytes to read (0-508)
 * @param buffer Buffer to store received data
 * @return true on success, false on failure
 */
bool pn5180_read_data(pn5180_t *pn5180, int len, uint8_t *buffer);

/**
 * @brief Prepare PN5180 for Low Power Card Detection (LPCD) mode
 * @param pn5180 Pointer to PN5180 device structure
 * @return true on success, false on failure
 */
bool pn5180_lpcd_prepare(pn5180_t *pn5180);

/**
 * @brief Switch PN5180 to Low Power Card Detection (LPCD) mode
 * @param pn5180 Pointer to PN5180 device structure
 * @param wakeup_counter_ms Wakeup interval in milliseconds
 * @return true on success, false on failure
 */
bool pn5180_lpcd_enter(pn5180_t *pn5180, uint16_t wakeup_counter_ms);

/**
 * @brief Wait until the PN5180 leaves LPCD mode
 *
 * Call after pn5180_lpcd_enter(). Needs the IRQ pin (pn5180_irq_attach()): any SPI access
 * ends LPCD mode, so IRQ_STATUS cannot be polled while waiting.
 *
 * On wake-up the PN5180 has lost its register settings; this function reloads the RF
 * configuration that was active before. The RF field is off and has to be switched on again
 * with setup_rf() or pn5180_set_rf_on().
 *
 * @param pn5180 Pointer to PN5180 device structure
 * @param timeout_ms Maximum time to wait in milliseconds, or -1 to wait forever
 * @param irq_status Out: IRQ_STATUS read at wake-up (may be NULL)
 * @return true if the PN5180 woke up because a card or metal object was detected (LPCD IRQ).
 *         false on timeout (the PN5180 is still in LPCD mode), on another wake-up reason,
 *         or if no IRQ pin is attached.
 */
bool pn5180_lpcd_wait(pn5180_t *pn5180, int timeout_ms, uint32_t *irq_status);

/**
 * @brief Authenticate MIFARE Classic card sector
 * @param pn5180 Pointer to PN5180 device structure
 * @param blockno Block number to authenticate
 * @param key 6-byte authentication key
 * @param key_type Key type (MIFARE_CLASSIC_KEYA or MIFARE_CLASSIC_KEYB)
 * @param uid 4-byte card UID
 * @return 0x00 on success, error code otherwise
 */
int16_t pn5180_mifare_authenticate(pn5180_t *pn5180, uint8_t blockno, const uint8_t *key, uint8_t key_type, const uint8_t uid[4]);

/**
 * @brief Load RF configuration for transmitter and receiver
 * @param pn5180 Pointer to PN5180 device structure
 * @param tx_conf Transmitter configuration (0x00-0x1C, 0xFF=no change)
 * @return true on success, false on failure
 */
bool pn5180_load_rf_config(pn5180_t *pn5180, uint8_t tx_conf);

/**
 * @brief Turn on RF field
 * @param pn5180 Pointer to PN5180 device structure
 * @return true on success, false on failure
 */
bool pn5180_set_rf_on(pn5180_t *pn5180);

/**
 * @brief Turn off RF field
 * @param pn5180 Pointer to PN5180 device structure
 * @return true on success, false on failure
 */
bool pn5180_set_rf_off(pn5180_t *pn5180);

/**
 * @brief Send raw command to PN5180 and receive response
 * @param pn5180 Pointer to PN5180 device structure
 * @param send_buffer Command data to send
 * @param send_buffer_len Length of send buffer
 * @param recv_buffer Buffer for response data (can be NULL)
 * @param recv_buffer_len Expected response length
 * @return true on success, false on failure
 */
bool pn5180_send_command(pn5180_t *pn5180, uint8_t *send_buffer, size_t send_buffer_len, uint8_t *recv_buffer, size_t recv_buffer_len);

/**
 * @brief Get number of bytes received in last RF reception
 * @param pn5180 Pointer to PN5180 device structure
 * @return Number of bytes received
 */
uint32_t pn5180_rx_bytes_received(pn5180_t *pn5180);

/**
 * @brief Hardware reset PN5180 device
 * @param pn5180 Pointer to PN5180 device structure
 * @return true on success, false on failure
 */
bool pn5180_reset(pn5180_t *pn5180);

/**
 * @brief Read current IRQ status register
 * @param pn5180 Pointer to PN5180 device structure
 * @return 32-bit IRQ status value
 */
uint32_t pn5180_get_irq_status(pn5180_t *pn5180);

/**
 * @brief Clear specified IRQ flags
 * @param pn5180 Pointer to PN5180 device structure
 * @param irq_mask Mask of IRQ flags to clear
 * @return true on success, false on failure
 */
bool pn5180_clear_irq_status(pn5180_t *pn5180, uint32_t irq_mask);

/**
 * @brief Get current transceiver state
 * @param pn5180 Pointer to PN5180 device structure
 * @return Current transceiver state
 */
pn5180_transceive_state_t pn5180_get_transceive_state(pn5180_t *pn5180);

/**
 * @brief Delay execution for specified milliseconds
 *
 * Precise to well below a FreeRTOS tick: whole ticks are slept, the remainder is a busy wait.
 *
 * @param ms Milliseconds to delay
 */
void pn5180_delay_ms(int ms);

/**
 * @brief Delay execution for specified microseconds
 *
 * Whole FreeRTOS ticks are slept, the remainder is a busy wait.
 *
 * @param us Microseconds to delay
 */
void pn5180_delay_us(uint32_t us);

/**
 * @brief Time the RF field has to stay off for cards to return to their idle state, in microseconds
 *
 * Use it between pn5180_set_rf_off() and the next setup_rf(): halted cards answer a new poll only
 * after the field was off this long. 5 ms is not enough.
 */
#define PN5180_RF_OFF_TIME_US 5100u

/**
 * @brief Wait for specific IRQ flag(s) with timeout
 * @param pn5180 Pointer to PN5180 device structure
 * @param irq_mask IRQ flags to wait for
 * @param operation Description of operation (for logging)
 * @param irq_status Pointer to store final IRQ status
 * @return true if IRQ occurred, false on timeout or error
 */
bool pn5180_wait_for_irq(pn5180_t *pn5180, uint32_t irq_mask, const char *operation, uint32_t *irq_status);

/**
 * @brief Enable RX CRC checking
 * @param pn5180 Pointer to PN5180 device structure
 */
static void inline pn5180_enable_rx_crc(pn5180_t *pn5180)
{
    pn5180_write_register_or_mask(pn5180, PN5180_CRC_RX_CONFIG, 0x01);
}

/**
 * @brief Enable TX CRC generation
 * @param pn5180 Pointer to PN5180 device structure
 */
static void inline pn5180_enable_tx_crc(pn5180_t *pn5180)
{
    pn5180_write_register_or_mask(pn5180, PN5180_CRC_TX_CONFIG, 0x01);
}

/**
 * @brief Enable both RX and TX CRC
 * @param pn5180 Pointer to PN5180 device structure
 */
static void inline pn5180_enable_crc(pn5180_t *pn5180)
{
    pn5180_enable_rx_crc(pn5180);
    pn5180_enable_tx_crc(pn5180);
}

/**
 * @brief Disable RX CRC checking
 * @param pn5180 Pointer to PN5180 device structure
 */
static void inline pn5180_disable_rx_crc(pn5180_t *pn5180)
{
    pn5180_write_register_and_mask(pn5180, PN5180_CRC_RX_CONFIG, 0xFFFFFFFE);
}

/**
 * @brief Disable TX CRC generation
 * @param pn5180 Pointer to PN5180 device structure
 */
static void inline pn5180_disable_tx_crc(pn5180_t *pn5180)
{
    pn5180_write_register_and_mask(pn5180, PN5180_CRC_TX_CONFIG, 0xFFFFFFFE);
}

/**
 * @brief Disable both RX and TX CRC
 * @param pn5180 Pointer to PN5180 device structure
 */
static void inline pn5180_disable_crc(pn5180_t *pn5180)
{
    pn5180_disable_rx_crc(pn5180);
    pn5180_disable_tx_crc(pn5180);
}

/**
 * @brief Clear all IRQ flags
 * @param pn5180 Pointer to PN5180 device structure
 * @return true on success, false on failure
 */
static bool inline pn5180_clear_all_irqs(pn5180_t *pn5180)
{
    return pn5180_clear_irq_status(pn5180, 0xFFFFFFFF);
}

/**
 * @brief Set transceiver to idle state
 * @param pn5180 Pointer to PN5180 device structure
 * @return true on success, false on failure
 */
static bool inline pn5180_set_transceiver_idle(pn5180_t *pn5180)
{
    bool ret = pn5180_write_register_and_mask(pn5180, PN5180_SYSTEM_CONFIG, 0xFFFFFFF8); // Idle/StopCom Command
    if (ret) {
        pn5180_clear_all_irqs(pn5180);
    }
    return ret;
}

#ifdef __cplusplus
}
#endif
