#pragma once

#include "driver/gpio.h"
#include "driver/spi_master.h"

#define MIFARE_CLASSIC_KEYA 0x60 // Mifare Classic key A
#define MIFARE_CLASSIC_KEYB 0x61 // Mifare Classic key B

// PN5180 IRQ_STATUS
#define RX_IRQ_STAT              (1 << 0)  // End of RF receiption IRQ
#define TX_IRQ_STAT              (1 << 1)  // End of RF transmission IRQ
#define IDLE_IRQ_STAT            (1 << 2)  // IDLE IRQ
#define MODE_DETECTED_IRQ_STAT   (1 << 3)  // Mode detected IRQ
#define CARD_ACTIVATED_IRQ_STAT  (1 << 4)  // Card activated IRQ
#define STATE_CHANGE_IRQ_STAT    (1 << 5)  // State Change in the transceive state machine IRQ
#define RFOFF_DET_IRQ_STAT       (1 << 6)  // RF Field OFF detection IRQ
#define RFON_DET_IRQ_STAT        (1 << 7)  // RF Field ON detection IRQ
#define TX_RFOFF_IRQ_STAT        (1 << 8)  // RF Field OFF in PCD IRQ
#define TX_RFON_IRQ_STAT         (1 << 9)  // RF Field ON in PCD IRQ
#define RF_ACTIVE_ERROR_IRQ_STAT (1 << 10) // RF Active error IRQ
#define TIMER0_IRQ_STAT          (1 << 11) // Timer 0 IRQ
#define TIMER1_IRQ_STAT          (1 << 12) // Timer 1 IRQ
#define TIMER2_IRQ_STAT          (1 << 13) // RX Timeout IRQ
#define RX_SOF_DET_IRQ_STAT      (1 << 14) // RF SOF Detection IRQ
#define RX_SC_DET_IRQ_STAT       (1 << 15) // RF SCD Detection IRQ
#define TEMPSENS_ERROR_IRQ_STAT  (1 << 16) // Temperature Sensor Error IRQ
#define GENERAL_ERROR_IRQ_STAT   (1 << 17) // General error IRQ
#define HV_ERROR_IRQ_STAT        (1 << 18) // High Voltage error IRQ
#define LPCD_IRQ_STAT            (1 << 19) // LPCD Detection IRQ

// PN5180 RX_STATUS
#define RX_COLL_POS_START            19 // Bits [25:19] - bit position of the first detected collision in a received frame
#define RX_COLL_POS_MASK             0x7F
#define RX_COLLISION_DETECTED        (1 << 18) // Bit 18 - Collision detected flag
#define RX_PROTOCOL_ERROR            (1 << 17) // Bit 17 - Protocol error flag
#define RX_DATA_INTEGRITY_ERROR      (1 << 16) // Bit 16 - Data integrity error flag
#define RX_NUM_LAST_BITS_START       13        // Bits [15:13] - Number of valid bits in the last received byte
#define RX_NUM_LAST_BITS_MASK        0x07
#define RX_NUM_FRAMES_RECEIVED_START 9 // Bits [12:9] - Number of frames received
#define RX_NUM_FRAMES_RECEIVED_MASK  0x0F
#define RX_BYTES_RECEIVED_START      0 // Bits [8:0] - Number of bytes received
#define RX_BYTES_RECEIVED_MASK       0x1FF

// PN5180 EEPROM Addresses
#define DIE_IDENTIFIER   (0x00)
#define PRODUCT_VERSION  (0x10)
#define FIRMWARE_VERSION (0x12)
#define EEPROM_VERSION   (0x14)
#define IRQ_PIN_CONFIG   (0x1A)

// PN5180 EEPROM Addresses - LPCD (Low Power Card Detection)
#define DPC_XI (0x5C) // DPC AGC Trim Value

// PN5180 Registers
#define SYSTEM_CONFIG      (0x00)
#define IRQ_ENABLE         (0x01)
#define IRQ_STATUS         (0x02)
#define IRQ_CLEAR          (0x03)
#define TRANSCEIVE_CONTROL (0x04)
#define TIMER1_RELOAD      (0x0c)
#define TIMER1_CONFIG      (0x0f)
#define RX_WAIT_CONFIG     (0x11)
#define CRC_RX_CONFIG      (0x12)
#define RX_STATUS          (0x13)
#define TX_WAIT_CONFIG     (0x17)
#define TX_CONFIG          (0x18)
#define CRC_TX_CONFIG      (0x19)
#define SIGPRO_RM_CONFIG   (0x1C)
#define RF_STATUS          (0x1d)
#define SYSTEM_STATUS      (0x24)
#define TEMP_CONTROL       (0x25)
#define AGC_REF_CONFIG     (0x26)
#define RF_STATUS_AGC_MASK 0x000003FFu

// SYSTEM_CONFIG register bit masks
#define SYSTEM_CONFIG_MFC_CRYPTO_ON      (1 << 6)   // Bit 6 - MIFARE Crypto1 enabled
#define SYSTEM_CONFIG_TX_MODE_MASK       0x00000003 // Bits 0-2 - Transceiver mode
#define SYSTEM_CONFIG_TX_MODE_IDLE       0x00000000
#define SYSTEM_CONFIG_TX_MODE_TRANSCEIVE 0x00000003
#define SYSTEM_CONFIG_CLEAR_CRYPTO_MASK  0xFFFFFFBF // ~(1<<6) - Clear MFC_CRYPTO_ON bit
#define SYSTEM_CONFIG_CLEAR_TX_MODE_MASK 0xFFFFFFF8 // ~0x07 - Clear transceiver state bits
#define TIMER1_RELOAD                    (0x0c)
#define TIMER1_CONFIG                    (0x0f)
#define RX_WAIT_CONFIG                   (0x11)
#define CRC_RX_CONFIG                    (0x12)
#define RX_STATUS                        (0x13)
#define TX_WAIT_CONFIG                   (0x17)
#define TX_CONFIG                        (0x18)
#define CRC_TX_CONFIG                    (0x19)
#define RF_STATUS                        (0x1d)
#define SYSTEM_STATUS                    (0x24)
#define TEMP_CONTROL                     (0x25)
#define AGC_REF_CONFIG                   (0x26)

/** @brief SPI configuration and handle for PN5180 */
typedef struct _pn5180_spi_t
{
    gpio_num_t          sck;
    gpio_num_t          miso;
    gpio_num_t          mosi;
    int                 clock_speed_hz;
    spi_device_handle_t spi_handle;
    spi_host_device_t   host_id;
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
    uint8_t       rf_config;
    uint8_t       tx_config;
    bool          is_rf_on;

    // ISO14443-4 State
    uint8_t iso14443_current_card_type; // Maps to nfc_type_t, but using uint8_t to avoid circular dependency if valid
    uint8_t iso14443_block_number;      // PCB toggle
    bool    iso14443_layer4_active;
    bool    iso14443_ndef_checked;  // Cache for NDEF Application presence check
    bool    iso14443_ndef_detected; // Result of NDEF Application presence check

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
    PN5180_15693                  /**< ISO 15693 vicinity card */
} __attribute__((__packed__)) nfc_type_t;

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
    nfc_type_t subtype;      /**< Detected card type/subtype */
    uint8_t    uid[10];      /**< Card UID bytes (length indicated by uid_length) */
} nfc_uid_t;

/**
 * @brief Dynamic array of detected card UIDs
 *
 * Heap-allocated structure returned by get_all_uids().
 * Uses flexible array member pattern - actual size is sizeof(nfc_uids_array_t) + (uids_count-1)*sizeof(nfc_uid_t).
 * Caller must free() after use.
 */
typedef struct
{
    int       uids_count; /**< Number of cards detected */
    nfc_uid_t uids[1];    /**< Flexible array of UID entries */
} nfc_uids_array_t;

struct _pn5180_proto_t;

/**
 * @brief Callback: Enumerate all cards in RF field
 * @param pn5180_proto Protocol interface
 * @return Heap-allocated array of UIDs (caller must free), or NULL if none found
 */
typedef nfc_uids_array_t *funct_get_all_uids_t(struct _pn5180_proto_t *pn5180_proto);

/**
 * @brief Callback: Configure RF field for protocol
 * @param pn5180_proto Protocol interface
 * @return true on success, false on failure
 */
typedef bool func_setup_rf_t(struct _pn5180_proto_t *pn5180_proto);

/**
 * @brief Callback: Select a specific card by UID
 * @param pn5180_proto Protocol interface
 * @param uid Pointer to UID structure of card to select
 * @return true if card selected successfully, false on failure
 */
typedef bool func_select_by_uid_t(        //
    struct _pn5180_proto_t *pn5180_proto, //
    nfc_uid_t              *uid           //
);

/**
 * @brief Callback: Authenticate for block access (MIFARE Classic)
 * @param pn5180_proto Protocol interface
 * @param key 6-byte authentication key
 * @param keyType Key type: MIFARE_CLASSIC_KEYA (0x60) or MIFARE_CLASSIC_KEYB (0x61)
 * @param uid Card UID for authentication
 * @param blockno Block number to authenticate for (determines sector)
 * @return true if authentication successful, false on failure
 * @note For Ultralight/DESFire, returns true without performing Crypto1 auth
 */
typedef bool func_authenticate_t(         //
    struct _pn5180_proto_t *pn5180_proto, //
    const uint8_t          *key,          //
    uint8_t                 keyType,      //
    const nfc_uid_t        *uid,          //
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
typedef bool funct_detect_card_type_t( //
    pn5180_t  *pn5180,                 //
    nfc_uid_t *uid,                    //
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
typedef bool func_block_read_t(struct _pn5180_proto_t *pn5180_proto, int blockno, uint8_t *buffer, size_t buffer_len);

/**
 * @brief Callback: Write a block to the selected card
 * @param pn5180_proto Protocol interface
 * @param blockno Block number to write
 * @param buffer Source buffer containing block data
 * @param buffer_len Size of source buffer
 * @return 0 on success, negative error code on failure
 */
typedef int func_block_write_t(struct _pn5180_proto_t *pn5180_proto, int blockno, const uint8_t *buffer, size_t buffer_len);

/**
 * @brief Callback: Halt or deselect the currently selected card
 * @param pn5180_proto Protocol interface
 * @return true on success, false on failure
 * @note After HALT, card must receive WUPA (not REQA) to wake up
 */
typedef bool func_halt_t(struct _pn5180_proto_t *pn5180_proto);

/**
 * @brief Protocol interface for card operations
 *
 * Abstract interface providing protocol-agnostic card operations.
 * Implementations exist for ISO14443A (pn5180-14443.h) and ISO15693 (pn5180-15693.h).
 * All callbacks operate on an already-initialized PN5180 device.
 */
typedef struct _pn5180_proto_t
{
    pn5180_t                 *pn5180;                        /**< Underlying PN5180 device handle */
    func_setup_rf_t          *setup_rf;                      /**< Configure RF field for this protocol */
    funct_get_all_uids_t     *get_all_uids;                  /**< Enumerate all cards in field */
    func_select_by_uid_t     *select_by_uid;                 /**< Select specific card by UID */
    func_block_read_t        *block_read;                    /**< Read block from selected card */
    func_block_write_t       *block_write;                   /**< Write block to selected card */
    func_authenticate_t      *authenticate;                  /**< Authenticate sector (MIFARE Classic) */
    funct_detect_card_type_t *detect_card_type_and_capacity; /**< Detect card type and geometry */
    func_halt_t              *halt;                          /**< Halt/deselect current card */
} pn5180_proto_t;

/**
 * @brief PN5180 transceiver state machine states
 *
 * Reflects the internal state of the PN5180 RF transceiver.
 * Read via pn5180_getTransceiveState().
 */
typedef enum
{
    PN5180_TS_Idle         = 0, /**< Transceiver idle, ready for command */
    PN5180_TS_WaitTransmit = 1, /**< Waiting to start transmission */
    PN5180_TS_Transmitting = 2, /**< RF transmission in progress */
    PN5180_TS_WaitReceive  = 3, /**< Transmission complete, waiting for response */
    PN5180_TS_WaitForData  = 4, /**< Waiting for data from card */
    PN5180_TS_Receiving    = 5, /**< Receiving data from card */
    PN5180_TS_LoopBack     = 6, /**< Loopback mode active */
    PN5180_TS_RESERVED     = 7  /**< Reserved state */
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
 * @brief Initialize PN5180 device
 * @param spi Pointer to initialized SPI structure
 * @param nss NSS (chip select) GPIO pin
 * @param busy BUSY GPIO pin for monitoring device state
 * @param rst RESET GPIO pin
 * @return Pointer to initialized PN5180 structure, or NULL on failure
 */
pn5180_t *pn5180_init(pn5180_spi_t *spi, gpio_num_t nss, gpio_num_t busy, gpio_num_t rst);

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
bool pn5180_writeRegister(pn5180_t *pn5180, uint8_t reg, uint32_t value);

/**
 * @brief Write to PN5180 register using OR mask (set bits)
 * @param pn5180 Pointer to PN5180 device structure
 * @param addr Register address
 * @param mask OR mask to apply (sets bits)
 * @return true on success, false on failure
 */
bool pn5180_writeRegisterWithOrMask(pn5180_t *pn5180, uint8_t addr, uint32_t mask);

/**
 * @brief Write to PN5180 register using AND mask (clear bits)
 * @param pn5180 Pointer to PN5180 device structure
 * @param addr Register address
 * @param mask AND mask to apply (clears bits when mask bit is 0)
 * @return true on success, false on failure
 */
bool pn5180_writeRegisterWithAndMask(pn5180_t *pn5180, uint8_t addr, uint32_t mask);

/**
 * @brief Read a 32-bit value from PN5180 register
 * @param pn5180 Pointer to PN5180 device structure
 * @param reg Register address
 * @param value Pointer to store the read value
 * @return true on success, false on failure
 */
bool pn5180_readRegister(pn5180_t *pn5180, uint8_t reg, uint32_t *value);

/**
 * @brief Read data from PN5180 EEPROM
 * @param pn5180 Pointer to PN5180 device structure
 * @param addr EEPROM start address (0-254)
 * @param buffer Buffer to store read data
 * @param len Number of bytes to read
 * @return true on success, false on failure
 */
bool pn5180_readEEprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len);

/**
 * @brief Write data to PN5180 EEPROM
 * @param pn5180 Pointer to PN5180 device structure
 * @param addr EEPROM start address
 * @param buffer Data to write
 * @param len Number of bytes to write
 * @return true on success, false on failure
 */
bool pn5180_writeEEprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len);

/**
 * @brief Send data via RF to card
 * @param pn5180 Pointer to PN5180 device structure
 * @param data Data buffer to send
 * @param len Number of bytes to send (max 260)
 * @param validBits Number of valid bits in last byte (0-7, 0 means all 8 bits valid)
 * @return true on success, false on failure
 */
bool pn5180_sendData(pn5180_t *pn5180, const uint8_t *data, int len, uint8_t validBits);

/**
 * @brief Read received RF data from reception buffer
 * @param pn5180 Pointer to PN5180 device structure
 * @param len Number of bytes to read (0-508)
 * @param buffer Buffer to store received data
 * @return true on success, false on failure
 */
bool pn5180_readData(pn5180_t *pn5180, int len, uint8_t *buffer);

/**
 * @brief Prepare PN5180 for Low Power Card Detection (LPCD) mode
 * @param pn5180 Pointer to PN5180 device structure
 * @return true on success, false on failure
 */
bool pn5180_prepareLPCD(pn5180_t *pn5180);

/**
 * @brief Switch PN5180 to Low Power Card Detection (LPCD) mode
 * @param pn5180 Pointer to PN5180 device structure
 * @param wakeupCounterInMs Wakeup interval in milliseconds
 * @return true on success, false on failure
 */
bool pn5180_switchToLPCD(pn5180_t *pn5180, uint16_t wakeupCounterInMs);

/**
 * @brief Authenticate MIFARE Classic card sector
 * @param pn5180 Pointer to PN5180 device structure
 * @param blockno Block number to authenticate
 * @param key 6-byte authentication key
 * @param keyType Key type (MIFARE_CLASSIC_KEYA or MIFARE_CLASSIC_KEYB)
 * @param uid 4-byte card UID
 * @return 0x00 on success, error code otherwise
 */
int16_t pn5180_mifareAuthenticate(pn5180_t *pn5180, uint8_t blockno, const uint8_t *key, uint8_t keyType, const uint8_t uid[4]);

/**
 * @brief Load RF configuration for transmitter and receiver
 * @param pn5180 Pointer to PN5180 device structure
 * @param txConf Transmitter configuration (0x00-0x1C, 0xFF=no change)
 * @return true on success, false on failure
 */
bool pn5180_loadRFConfig(pn5180_t *pn5180, uint8_t txConf);

/**
 * @brief Turn on RF field
 * @param pn5180 Pointer to PN5180 device structure
 * @return true on success, false on failure
 */
bool pn5180_setRF_on(pn5180_t *pn5180);

/**
 * @brief Turn off RF field
 * @param pn5180 Pointer to PN5180 device structure
 * @return true on success, false on failure
 */
bool pn5180_setRF_off(pn5180_t *pn5180);

/**
 * @brief Send raw command to PN5180 and receive response
 * @param pn5180 Pointer to PN5180 device structure
 * @param sendBuffer Command data to send
 * @param sendBufferLen Length of send buffer
 * @param recvBuffer Buffer for response data (can be NULL)
 * @param recvBufferLen Expected response length
 * @return true on success, false on failure
 */
bool pn5180_sendCommand(pn5180_t *pn5180, uint8_t *sendBuffer, size_t sendBufferLen, uint8_t *recvBuffer, size_t recvBufferLen);

/**
 * @brief Get number of bytes received in last RF reception
 * @param pn5180 Pointer to PN5180 device structure
 * @return Number of bytes received
 */
uint32_t pn5180_rxBytesReceived(pn5180_t *pn5180);

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
uint32_t pn5180_getIRQStatus(pn5180_t *pn5180);

/**
 * @brief Clear specified IRQ flags
 * @param pn5180 Pointer to PN5180 device structure
 * @param irqMask Mask of IRQ flags to clear
 * @return true on success, false on failure
 */
bool pn5180_clearIRQStatus(pn5180_t *pn5180, uint32_t irqMask);

/**
 * @brief Get current transceiver state
 * @param pn5180 Pointer to PN5180 device structure
 * @return Current transceiver state
 */
pn5180_transceive_state_t pn5180_getTransceiveState(pn5180_t *pn5180);

/**
 * @brief Delay execution for specified milliseconds
 * @param ms Milliseconds to delay
 */
void pn5180_delay_ms(int ms);

/**
 * @brief Wait for specific IRQ flag(s) with timeout
 * @param pn5180 Pointer to PN5180 device structure
 * @param irq_mask IRQ flags to wait for
 * @param operation Description of operation (for logging)
 * @param irqStatus Pointer to store final IRQ status
 * @return true if IRQ occurred, false on timeout or error
 */
bool pn5180_wait_for_irq(pn5180_t *pn5180, uint32_t irq_mask, const char *operation, uint32_t *irqStatus);

/**
 * @brief Enable RX CRC checking
 * @param pn5180 Pointer to PN5180 device structure
 */
static void inline pn5180_enable_rx_crc(pn5180_t *pn5180)
{
    pn5180_writeRegisterWithOrMask(pn5180, CRC_RX_CONFIG, 0x01);
}

/**
 * @brief Enable TX CRC generation
 * @param pn5180 Pointer to PN5180 device structure
 */
static void inline pn5180_enable_tx_crc(pn5180_t *pn5180)
{
    pn5180_writeRegisterWithOrMask(pn5180, CRC_TX_CONFIG, 0x01);
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
    pn5180_writeRegisterWithAndMask(pn5180, CRC_RX_CONFIG, 0xFFFFFFFE);
}

/**
 * @brief Disable TX CRC generation
 * @param pn5180 Pointer to PN5180 device structure
 */
static void inline pn5180_disable_tx_crc(pn5180_t *pn5180)
{
    pn5180_writeRegisterWithAndMask(pn5180, CRC_TX_CONFIG, 0xFFFFFFFE);
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
static bool inline pn5180_clearAllIRQs(pn5180_t *pn5180)
{
    return pn5180_clearIRQStatus(pn5180, 0xFFFFFFFF);
}

/**
 * @brief Set transceiver to idle state
 * @param pn5180 Pointer to PN5180 device structure
 * @return true on success, false on failure
 */
static bool inline pn5180_set_transceiver_idle(pn5180_t *pn5180)
{
    bool ret = pn5180_writeRegisterWithAndMask(pn5180, SYSTEM_CONFIG, 0xFFFFFFF8); // Idle/StopCom Command
    if (ret) {
        pn5180_clearAllIRQs(pn5180);
    }
    return ret;
}
