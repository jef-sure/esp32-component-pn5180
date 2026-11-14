# Справочник API

*[In English](../en/api.md)*

Все публичные типы, функции и константы, по заголовочным файлам. Как они связаны друг с другом, описано на странице
[Как работает драйвер](how-it-works.md); страницы об [опросе](polling.md), [ISO14443A](iso14443a.md),
[ISO14443-4](iso14443-4.md), [ISO15693](iso15693.md) и [NDEF](ndef.md) показывают их в работе.

| Заголовок | Что в нём |
| --------- | --------- |
| `pn5180.h` | объекты SPI и устройства, интерфейс протокола, поле, радиообмен, аутентификация MIFARE, LPCD, регистры и EEPROM |
| `pn5180-14443.h` | протокол ISO14443A, обмен APDU по ISO14443-4, утилиты APDU |
| `pn5180-15693.h` | протокол ISO15693 |
| `pn5180-mifare.h` | низкоуровневые операции MIFARE с блоками, страницами и блоками значения |
| `pn5180-ndef.h` | записи и сообщения NDEF, чтение и запись меток |
| `pn5180-ndef-tlv.h` | поиск NDEF TLV в необработанных байтах |

`pn5180-internal.h` нужен исходникам драйвера и в API не входит.

Все публичные имена начинаются с `pn5180_` или `PN5180_`. В каждом заголовке есть `extern "C"` для C++.

## pn5180.h: типы

### pn5180_spi_t

```c
typedef struct _pn5180_spi_t {
    gpio_num_t          sck, miso, mosi;
    int                 clock_speed_hz;
    spi_device_handle_t spi_handle;
    spi_host_device_t   host_id;
    bool                owns_bus;    /* the bus was initialized by pn5180_spi_init() */
} pn5180_spi_t;
```

Хост SPI и PN5180 как устройство на нём. Создаётся функцией `pn5180_spi_init()` или `pn5180_spi_attach()`.

### pn5180_t

Устройство: пины, два буфера SPI по 512 байт, состояние ВЧ-части, настройки времени и состояние выбранной карты
ISO14443. Структура публичная, потому что драйвер разделён на несколько файлов; для программы это дескриптор, и его
поля она не меняет. Поля, которые программа может читать:

| Поле | Описание |
| ---- | -------- |
| `firmware_version` | читается из EEPROM при инициализации, старшая часть версии в старшем байте (`0x0304` — это 3.4) |
| `iso14443_last_auth_status` | результат последней аутентификации MIFARE Classic, см. [`pn5180_mifare_authenticate()`](#pn5180_mifare_authenticate) |
| `timeout_ms` | предел ожиданий самого PN5180 (BUSY, состояние приёмопередатчика, поле, IRQ), 500 мс; это не тайм-аут карты |
| `is_rf_on` | включено поле или выключено, как считает драйвер |
| `irq` | пин IRQ, `GPIO_NUM_NC` без `pn5180_irq_attach()` |

### pn5180_proto_t

```c
typedef struct _pn5180_proto_t {
    pn5180_t                       *pn5180;
    pn5180_func_setup_rf_t         *setup_rf;
    pn5180_func_get_all_uids_t     *get_all_uids;
    pn5180_func_select_by_uid_t    *select_by_uid;
    pn5180_func_block_read_t       *block_read;
    pn5180_func_block_write_t      *block_write;
    pn5180_func_authenticate_t     *authenticate;    /* NULL for ISO15693 */
    pn5180_func_detect_card_type_t *detect_card_type_and_capacity;
    pn5180_func_halt_t             *halt;
    uint8_t                         rf_config;       /* RF configuration loaded by setup_rf() */
    int                             max_cards;       /* most cards one poll enumerates (ISO14443A) */
} pn5180_proto_t;
```

Интерфейс протокола; создаётся функцией `pn5180_14443_init()` или `pn5180_15693_init()`, освобождается `free()`.
Колбэки:

#### setup_rf

```c
bool setup_rf(pn5180_proto_t *proto);
```

Загружает конфигурацию RF протокола и включает поле. Если эта конфигурация уже загружена и поле включено, проверяет,
что поле действительно есть, и не выключает его, так что карты, остановленные или заглушённые прошлым опросом, такими
и остаются. Если загружена другая конфигурация, сначала выключает поле на `PN5180_RF_OFF_TIME_US`. `false`, если
конфигурацию не удалось загрузить или поле не появилось (в том числе из-за защиты от столкновения полей).

#### get_all_uids

```c
pn5180_uids_array_t *get_all_uids(pn5180_proto_t *proto);
```

Опрашивает все карты в поле. Возвращает массив в куче, который освобождается `free()`, или `NULL`, если ничего не
найдено или опрос не удался; что именно произошло, сообщают `pn5180_14443_get_all_uids_ex()` и
`pn5180_15693_get_all_uids_ex()`. Ни одна карта не остаётся выбранной. См. [Поиск карт](polling.md).

#### select_by_uid

```c
bool select_by_uid(pn5180_proto_t *proto, pn5180_uid_t *uid);
```

Выбирает одну карту. ISO14443A: закрывает оставшуюся открытой сессию ISO14443-4, посылает WUPA и SELECT каждого
уровня каскада, обновляет `sak` и `atqa` и активирует ISO14443-4 (RATS) у карты с битом SAK `20`, кроме случая, когда
карта эмулирует ещё и MIFARE Classic, а `subtype` не `PN5180_MIFARE_DESFIRE`. ISO15693: адресный Select; в UID должно
быть 8 байт.

#### detect_card_type_and_capacity

```c
bool detect_card_type_and_capacity(pn5180_t *pn5180, pn5180_uid_t *uid, int *blocks_count, int *block_size);
```

Принимает `pn5180_t`, а не объект протокола. Заполняет `uid->subtype`, `uid->blocks_count`, `uid->block_size` и оба
выходных параметра. Возвращает `true`, если после неё карту нужно выбрать заново (семейство Ultralight), иначе
`false`. Типы карт перечислены на страницах [Карты ISO14443A](iso14443a.md#типы-карт) и
[Метки ISO15693](iso15693.md#выбор-определение-остановка).

#### authenticate

```c
bool authenticate(pn5180_proto_t *proto, const uint8_t *key, uint8_t key_type, const pn5180_uid_t *uid, int blockno);
```

Только ISO14443A (у ISO15693 — `NULL`). MIFARE Classic / Plus: аутентификация Crypto1 сектора блока `blockno` (от 0
до 255) 6-байтным ключом `key`, `key_type` — `PN5180_MIFARE_CLASSIC_KEYA` или `PN5180_MIFARE_CLASSIC_KEYB`; у UID из 7
или 10 байт в аутентификации участвуют последние 4 байта. Карты Ultralight, NTAG и ISO14443-4: `true`, ничего не
посылается. После `false` карта уже не в выбранном состоянии; `pn5180->iso14443_last_auth_status` отличает отвергнутый
ключ (`PN5180_MIFARE_AUTH_REFUSED`) от карты, которая не ответила (`PN5180_MIFARE_AUTH_NO_ANSWER`), и от случая, когда
ничего не посылалось (`PN5180_MIFARE_AUTH_NONE`).

#### block_read

```c
bool block_read(pn5180_proto_t *proto, int blockno, uint8_t *buffer, size_t buffer_len);
```

- MIFARE Classic, Ultralight, NTAG: READ блока или первой страницы `blockno` (от 0 до 255); карта отвечает 16 байтами,
  из них копируются первые `buffer_len`.
- Карты ISO14443-4: READ BINARY `buffer_len` байт (от 1 до 255) по смещению `blockno` (от 0 до 7FFFh) в выбранном
  файле; `false`, если вернулось меньше байт.
- ISO15693: Read Single Block, выше блока 255 (до 65535) — расширенная команда; метка должна отдать не меньше
  `buffer_len` байт.

#### block_write

```c
int block_write(pn5180_proto_t *proto, int blockno, const uint8_t *buffer, size_t buffer_len);
```

Возвращает 0 при успехе, отрицательное значение при ошибке. При `buffer_len`, равном 16, записывается блок MIFARE
Classic, при 4 — страница Ultralight / NTAG, при размере блока (от 1 до 32) — блок ISO15693. Для карты ISO14443-4 в её
сессии недоступна (-1).

#### halt

```c
bool halt(pn5180_proto_t *proto);
```

Завершает сессию: HLTA для карт ISO14443-3, S(DESELECT) для карты ISO14443-4, Reset to Ready выбранной метке ISO15693
(в ISO15693 эта команда необязательна: на метке без неё — `false`).

### pn5180_uid_t

```c
typedef struct {
    int8_t             uid_length;   /* 4, 7 or 10 for ISO14443A, 8 for ISO15693 */
    uint8_t            sak;          /* ISO14443A */
    uint16_t           agc;          /* receiver AGC when the card answered: lower is closer */
    int                block_size;   /* bytes per block */
    int                blocks_count; /* blocks on the card */
    pn5180_card_type_t subtype;
    uint8_t            uid[10];
    uint8_t            atqa[2];      /* ISO14443A, first byte first */
} pn5180_uid_t;
```

Одна карта, как её нашёл опрос. `subtype`, `block_size` и `blocks_count` заполняет `detect_card_type_and_capacity()`.

### pn5180_uids_array_t

```c
typedef struct {
    int          uids_count;
    pn5180_uid_t uids[1];   /* uids_count entries */
} pn5180_uids_array_t;
```

Результат опроса, в куче; освобождается `free()`.

### pn5180_card_type_t

| Значение | Карта |
| -------- | ----- |
| `PN5180_MIFARE_UNKNOWN` | не опознана или ещё не определялась |
| `PN5180_MIFARE_CLASSIC_1K`, `PN5180_MIFARE_CLASSIC_MINI`, `PN5180_MIFARE_CLASSIC_4K` | MIFARE Classic |
| `PN5180_MIFARE_PLUS_2K`, `PN5180_MIFARE_PLUS_4K` | MIFARE Plus на уровне безопасности 2 |
| `PN5180_MIFARE_ULTRALIGHT`, `PN5180_MIFARE_ULTRALIGHT_C`, `PN5180_MIFARE_ULTRALIGHT_EV1` | MIFARE Ultralight |
| `PN5180_MIFARE_NTAG210`, `PN5180_MIFARE_NTAG212`, `PN5180_MIFARE_NTAG213`, `PN5180_MIFARE_NTAG215`, `PN5180_MIFARE_NTAG216` | NTAG |
| `PN5180_MIFARE_DESFIRE` | любая карта ISO14443-4 |
| `PN5180_15693` | метка ISO15693 |

Упакованное перечисление: один байт.

### pn5180_poll_status_t

| Значение | Описание |
| -------- | -------- |
| `PN5180_POLL_FOUND` | найдена хотя бы одна карта; массив возвращается |
| `PN5180_POLL_NO_TARGET` | ни одна карта не ответила |
| `PN5180_POLL_TRANSPORT_ERROR` | не удалось управлять PN5180: сбой SPI, поле не появилось |
| `PN5180_POLL_PROTOCOL_ERROR` | только ISO14443A: карта ответила, но антиколлизия или выбор не удались |
| `PN5180_POLL_NO_MEMORY` | не удалось выделить память под массив |
| `PN5180_POLL_INVALID_ARGUMENT` | объект протокола или устройство — `NULL` |

### pn5180_rf_result_t

| Значение | Описание |
| -------- | -------- |
| `PN5180_RF_OK` | ответ без ошибок |
| `PN5180_RF_TIMEOUT` | ответа не было за время тайм-аута |
| `PN5180_RF_COLLISION` | ответ с коллизией битов; данные (обрезанные по размеру буфера) и RX_STATUS возвращаются |
| `PN5180_RF_RX_ERROR` | ошибка протокола, чётности или CRC; данные возвращаются, если только PN5180 не выставил общую ошибку |
| `PN5180_RF_OVERFLOW` | ответ длиннее буфера; данные не возвращаются |
| `PN5180_RF_FATAL` | не удалось управлять PN5180: сбой SPI, передача не завершилась |

### pn5180_transceive_state_t

Состояние приёмопередатчика PN5180, его возвращает `pn5180_get_transceive_state()`: `PN5180_TS_IDLE`,
`PN5180_TS_WAIT_TRANSMIT`, `PN5180_TS_TRANSMITTING`, `PN5180_TS_WAIT_RECEIVE`, `PN5180_TS_WAIT_FOR_DATA`,
`PN5180_TS_RECEIVING`, `PN5180_TS_LOOPBACK` и `PN5180_TS_RESERVED`, которое возвращается и тогда, когда состояние не
удалось прочитать.

## pn5180.h: устройство

### pn5180_spi_init

```c
pn5180_spi_t *pn5180_spi_init(spi_host_device_t host_id, gpio_num_t sck, gpio_num_t miso, gpio_num_t mosi,
                              int clock_speed_hz);
```

Инициализирует шину SPI хоста `host_id` с каналом DMA и добавляет на неё PN5180. Частота выше
`PN5180_SPI_MAX_CLOCK_HZ` (7 МГц) снижается до неё. `NULL` при ошибке; пин, который не является GPIO чипа (в том
числе `GPIO_NUM_NC`), SCK или MOSI на GPIO, работающем только на вход, или пин MISO, который отвергает `gpio_config()`,
дают `NULL` ещё до обращения к хосту SPI.

### pn5180_spi_attach

```c
pn5180_spi_t *pn5180_spi_attach(spi_host_device_t host_id, int clock_speed_hz);
```

Добавляет PN5180 на шину, которую инициализировала программа; работает и сразу после `spi_bus_initialize()`, когда на
хосте ещё нет других устройств. Шина должна пропускать `PN5180_MAX_BUF_SIZE` (512) байт за транзакцию, а для этого
нужен канал DMA. `NULL`, если хост не инициализирован, пропускает меньше или устройство не удаётся добавить; тогда на
хосте не остаётся устройства PN5180. Драйвер никогда не освобождает эту шину.

### pn5180_spi_deinit

```c
void pn5180_spi_deinit(pn5180_spi_t *spi, bool free_spi_bus);
```

Удаляет устройство PN5180 и освобождает структуру; это для структуры SPI, которой не пользуется ни один `pn5180_t`,
например после неудачного `pn5180_init()`. С `free_spi_bus` освобождает и шину, если её инициализировала
`pn5180_spi_init()`.

### pn5180_init

```c
pn5180_t *pn5180_init(pn5180_spi_t *spi, gpio_num_t nss, gpio_num_t busy, gpio_num_t rst);
```

Настраивает пины, сбрасывает PN5180, ждёт его загрузки, читает версию прошивки (нужна 3.4 или новее) и выделяет
память под устройство с двумя буферами, пригодными для DMA. `NULL` при ошибке, `spi` при этом не тронут: функцию можно
вызвать снова или освободить `spi` через `pn5180_spi_deinit()`. Пин, который не является GPIO чипа, NSS или RST на
GPIO, работающем только на вход, или пин, который отвергает `gpio_config()`, дают `NULL` ещё до обращения к PN5180.

### pn5180_irq_attach

```c
bool pn5180_irq_attach(pn5180_t *pn5180, gpio_num_t irq);
```

Переводит драйвер на пин IRQ вместо опроса статуса IRQ по SPI; полярность читается из EEPROM. Вызывается один раз после
`pn5180_init()`. `false` при ошибке, и тогда драйвер по-прежнему опрашивает статус; `false` сразу для устройства
`NULL` или пина, который не является GPIO чипа. Нужна для `pn5180_lpcd_wait()`.

### pn5180_deinit

```c
void pn5180_deinit(pn5180_t *pn5180, bool free_spi_bus);
```

Освобождает устройство вместе с его устройством SPI; с `free_spi_bus` — и шину, если её инициализировала
`pn5180_spi_init()`. Шину, к которой PN5180 был подключён, драйвер не освобождает никогда. Объекты протоколов нужно
освободить раньше.

### pn5180_reset

```c
bool pn5180_reset(pn5180_t *pn5180);
```

Аппаратный сброс через RST. Конфигурация RF и поле пропадают, карты нужно выбирать заново, сессия ISO14443-4
помечается закрытой. `pn5180_recover()` сбрасывает и восстанавливает.

### pn5180_recover

```c
bool pn5180_recover(pn5180_t *pn5180);
```

Сбрасывает PN5180 и восстанавливает конфигурацию RF и состояние поля, какими они были. Для считывателя, который
перестал отвечать, например когда опрос вернул `PN5180_POLL_TRANSPORT_ERROR`. Карты нужно выбирать заново.

## pn5180.h: поле

### pn5180_load_rf_config

```c
bool pn5180_load_rf_config(pn5180_t *pn5180, uint8_t tx_conf);
```

Загружает конфигурацию RF PN5180 для передатчика и приёмника: от 00h до 1Ch, FFh — без изменений. 00h — ISO14443A
106 кбит/с, 0Dh и 0Eh — ISO15693 ASK 100 % и ASK 10 %. `setup_rf()` делает это для своего протокола.

### pn5180_set_rf_on, pn5180_set_rf_off

```c
bool pn5180_set_rf_on(pn5180_t *pn5180);
bool pn5180_set_rf_off(pn5180_t *pn5180);
```

Включают и выключают поле. `pn5180_set_rf_on()` проверяет само поле, а не только флаг драйвера, выжидает защитное
время после включения и возвращает `false`, если защита от столкновения полей не даёт его включить.
`pn5180_set_rf_off()` завершает сессии всех карт; сессия ISO14443-4 помечается закрытой.

### pn5180_set_rf_guard_time_us

```c
void pn5180_set_rf_guard_time_us(pn5180_t *pn5180, uint32_t guard_time_us);
```

Пауза после включения поля перед первой командой: по умолчанию 5100 мкс, этого хватает для ISO14443A; для ISO15693
нужно 1000 мкс.

### pn5180_set_rfca

```c
void pn5180_set_rfca(pn5180_t *pn5180, bool enable);
```

Защита от столкновения полей (RFCA), по умолчанию включена: поле не включается, пока есть другое поле. С `false` поле
включается в любом случае.

### pn5180_set_hw_rx_timeout

```c
void pn5180_set_hw_rx_timeout(pn5180_t *pn5180, bool enable);
```

По умолчанию включено: ожидание ответа карты отсчитывает Timer1 в PN5180. Если выключено — тайм-аут на стороне хоста,
менее точный и позже сообщающий, что карты нет.

### PN5180_RF_OFF_TIME_US

```c
#define PN5180_RF_OFF_TIME_US 5100u
```

Сколько поле должно оставаться выключенным, чтобы карты вернулись в состояние покоя. 5 мс недостаточно.

## pn5180.h: радиообмен

### pn5180_rf_transceive

```c
pn5180_rf_result_t pn5180_rf_transceive(pn5180_t *pn5180, const uint8_t *tx, size_t tx_len, uint8_t tx_last_bits,
                                        uint8_t *rx, size_t rx_size, size_t *rx_len, uint32_t timeout_us,
                                        uint32_t *rx_status);
```

Посылает кадр и принимает ответ; на ней построен код протоколов.

- `tx`, `tx_len` (от 1 до 260): кадр; `tx_last_bits`: число действительных битов в его последнем байте, 0 — все 8.
- `rx`, `rx_size`: буфер приёма, при `rx`, равном `NULL`, ответ отбрасывается; в `rx_len` (может быть `NULL`)
  записывается число сохранённых байт.
- `timeout_us`: время до начала ответа, его отсчитывает Timer1 от конца передачи, примерно до 19,7 с. 0 значит, что
  ответа не ждут: вызов возвращается, когда передача закончилась.
- В `rx_status` (может быть `NULL`) записывается регистр RX_STATUS с позицией коллизии и числом действительных битов
  последнего байта; см. константы `PN5180_RX_*`.

CRC и чётность следуют текущей конфигурации: `pn5180_enable_crc()`, `pn5180_disable_crc()` и их варианты `_rx_` и
`_tx_` включают и выключают CRC каждого направления (это static inline функции заголовка). После `select_by_uid()`
карты ISO14443A CRC включён в обоих направлениях.

### pn5180_send_data, pn5180_read_data, pn5180_rx_bytes_received

```c
bool     pn5180_send_data(pn5180_t *pn5180, const uint8_t *data, int len, uint8_t valid_bits);
bool     pn5180_read_data(pn5180_t *pn5180, int len, uint8_t *buffer);
uint32_t pn5180_rx_bytes_received(pn5180_t *pn5180);
```

Команды хоста SEND_DATA (от 0 до 260 байт, `valid_bits` — действительные биты последнего байта, 0 — все) и READ_DATA
(от 0 до 508 байт), а также число байт последнего приёма из RX_STATUS. Уровнем ниже, чем `pn5180_rf_transceive()`:
состоянием приёмопередатчика, флагами IRQ и тайм-аутом программа занимается сама.

## pn5180.h: аутентификация MIFARE

### pn5180_mifare_authenticate

```c
int16_t pn5180_mifare_authenticate(pn5180_t *pn5180, uint8_t blockno, const uint8_t *key, uint8_t key_type,
                                   const uint8_t uid[4]);
```

Команда MIFARE_AUTHENTICATE PN5180 с 6-байтным ключом и 4 байтами UID, с которыми аутентифицируется карта. Колбэк
`authenticate` вызывает её с нужными байтами UID. Возвращает статус, который сообщает PN5180 (техническое описание,
таблица 26); он же сохраняется в `pn5180->iso14443_last_auth_status`:

| Значение | Описание |
| -------- | -------- |
| `PN5180_MIFARE_AUTH_OK` (0) | ключ принят |
| `PN5180_MIFARE_AUTH_REFUSED` (1) | карта отвергла ключ; так же, если PN5180 сообщает об успехе, но Crypto1 выключен |
| `PN5180_MIFARE_AUTH_NO_ANSWER` (2) | карта не ответила |
| другое положительное значение | другой байт статуса PN5180 |
| `PN5180_MIFARE_AUTH_NONE` (-1) | ничего не послано: аргумент `NULL` или тип ключа, отличный от 60h и 61h |
| -3 | передача по SPI не удалась |
| -4 | результат не удалось проверить |

Типы ключей — `PN5180_MIFARE_CLASSIC_KEYA` (60h) и `PN5180_MIFARE_CLASSIC_KEYB` (61h).

## pn5180.h: обнаружение карты с малым потреблением

### pn5180_lpcd_prepare

```c
bool pn5180_lpcd_prepare(pn5180_t *pn5180);
```

Записывает настройки LPCD в EEPROM PN5180 (время включения поля, высокая чувствительность, самокалибровка), каждый
байт — только если он отличается. Вызывается один раз.

### pn5180_lpcd_enter

```c
bool pn5180_lpcd_enter(pn5180_t *pn5180, uint16_t wakeup_counter_ms);
```

Переводит PN5180 в режим LPCD с проверкой на карту каждые `wakeup_counter_ms` (от 1 до
`PN5180_MAX_WAKEUP_COUNTER_MS`, 2690). На прошивке 3.A и новее сначала измеряется опорное значение. С этого момента
поле выключено, а сессия ISO14443-4 помечается закрытой.

### pn5180_lpcd_wait

```c
bool pn5180_lpcd_wait(pn5180_t *pn5180, int timeout_ms, uint32_t *irq_status);
```

Ждёт на пине IRQ, без обращений по SPI, пока PN5180 не выйдет из режима LPCD; при `timeout_ms`, равном -1, ждёт
бесконечно. `true`, если PN5180 проснулся из-за карты или металла (LPCD IRQ); тогда конфигурация RF загружается
заново, а поле выключено. `false` по тайм-ауту (PN5180 всё ещё в режиме LPCD), при другой причине пробуждения или без
пина IRQ. В `irq_status` (может быть `NULL`) записывается статус IRQ, прочитанный при пробуждении.

## pn5180.h: регистры, EEPROM, команды

### pn5180_read_register, pn5180_write_register

```c
bool pn5180_read_register(pn5180_t *pn5180, uint8_t reg, uint32_t *value);
bool pn5180_write_register(pn5180_t *pn5180, uint8_t reg, uint32_t value);
bool pn5180_write_register_or_mask(pn5180_t *pn5180, uint8_t addr, uint32_t mask);   /* sets bits */
bool pn5180_write_register_and_mask(pn5180_t *pn5180, uint8_t addr, uint32_t mask);  /* clears the 0 bits */
```

Регистры PN5180, по 32 бита. Адреса (`PN5180_SYSTEM_CONFIG`, `PN5180_IRQ_STATUS`, `PN5180_RX_STATUS`,
`PN5180_RF_STATUS`, ...) и биты, которыми пользуется драйвер, определены в заголовке.

### pn5180_read_eeprom, pn5180_write_eeprom

```c
bool pn5180_read_eeprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len);
bool pn5180_write_eeprom(pn5180_t *pn5180, uint8_t addr, uint8_t *buffer, int len);
```

EEPROM PN5180: чтение с адреса 0, запись с 16h (`PN5180_EEPROM_MIN_ADDR`), то и другое до FEh
(`PN5180_EEPROM_MAX_ADDR`); `addr + len` не должно выходить за последний адрес. `PN5180_DIE_IDENTIFIER` (16 байт),
`PN5180_PRODUCT_VERSION`, `PN5180_FIRMWARE_VERSION` и `PN5180_EEPROM_VERSION` (по 2 байта, младшая часть первой)
идентифицируют чип; `PN5180_IRQ_PIN_CONFIG` хранит полярность пина IRQ. Число циклов записи EEPROM ограничено: писать
в неё в цикле нельзя.

### pn5180_send_command

```c
bool pn5180_send_command(pn5180_t *pn5180, uint8_t *send_buffer, size_t send_buffer_len, uint8_t *recv_buffer,
                         size_t recv_buffer_len);
```

Посылает команду хоста как есть (первый байт — код команды) и читает `recv_buffer_len` байт ответа в `recv_buffer`,
который может быть `NULL` для команды без ответа. Сама обслуживает NSS и BUSY.

### Статус IRQ

```c
uint32_t pn5180_get_irq_status(pn5180_t *pn5180);           /* 0 when it cannot be read */
bool     pn5180_clear_irq_status(pn5180_t *pn5180, uint32_t irq_mask);
bool     pn5180_clear_all_irqs(pn5180_t *pn5180);           /* static inline */
bool     pn5180_wait_for_irq(pn5180_t *pn5180, uint32_t irq_mask, const char *operation, uint32_t *irq_status);
```

Регистр статуса IRQ и его биты `PN5180_*_IRQ_STAT` (`PN5180_RX_IRQ_STAT`, `PN5180_TX_IRQ_STAT`,
`PN5180_IDLE_IRQ_STAT`, ..., `PN5180_LPCD_IRQ_STAT`). `pn5180_wait_for_irq()` ждёт — по пину IRQ или опрашивая
регистр, — пока не установится один из флагов `irq_mask`, но не дольше `pn5180->timeout_ms`; `operation` называет это
ожидание в логе.

### Состояние приёмопередатчика

```c
pn5180_transceive_state_t pn5180_get_transceive_state(pn5180_t *pn5180);
bool                      pn5180_set_transceiver_idle(pn5180_t *pn5180);   /* static inline */
```

Состояние приёмопередатчика и команда, которая возвращает его в состояние покоя и заодно сбрасывает флаги IRQ.

## pn5180.h: время и ожидания

### pn5180_delay_ms, pn5180_delay_us

```c
void pn5180_delay_ms(int ms);
void pn5180_delay_us(uint32_t us);
```

Точные паузы, которым не нужно устройство: целые тики RTOS задача спит, а остаток ждёт в активном цикле, который
занимает процессор на время до одного тика. Для паузы, которой точность не нужна, есть `vTaskDelay()`. Собственные
ожидания драйвера вместо этого спят на таймере устройства.

## pn5180.h: константы

| Константа | Значение | Описание |
| --------- | -------- | -------- |
| `PN5180_MAX_BUF_SIZE` | 512 | размер каждого буфера SPI и наименьший объём, который общая шина должна пропускать за транзакцию |
| `PN5180_SPI_MAX_CLOCK_HZ` | 7000000 | наибольшая частота SPI |
| `PN5180_RF_OFF_TIME_US` | 5100 | сколько поле должно быть выключено, чтобы карты сбросились |
| `PN5180_MIN_FIRMWARE_VERSION` | 0x0304 | самая старая прошивка, которую принимает `pn5180_init()` |
| `PN5180_FIRMWARE_VERSION_3_A` | 0x030A | первая прошивка с режимами опорного значения LPCD из технического описания ревизии 4.0 |
| `PN5180_MAX_WAKEUP_COUNTER_MS` | 2690 | самый длинный интервал LPCD |
| `PN5180_MIFARE_CLASSIC_KEYA`, `_KEYB` | 0x60, 0x61 | типы ключей |
| `PN5180_MIFARE_AUTH_OK`, `_REFUSED`, `_NO_ANSWER`, `_NONE` | 0, 1, 2, -1 | статус аутентификации |
| `PN5180_*_IRQ_STAT` | биты | флаги IRQ_STATUS |
| `PN5180_RX_*` | биты и позиции | поля RX_STATUS: коллизия, ошибки, действительные биты последнего байта, принятые кадры и байты |
| `PN5180_RF_STATUS_*` | маски | поля RF_STATUS: значение AGC, своё поле включено, обнаружено внешнее поле |
| адреса регистров и EEPROM | | `PN5180_SYSTEM_CONFIG`, `PN5180_TIMER1_CONFIG`, `PN5180_FIRMWARE_VERSION`, ... |

## pn5180-14443.h

### pn5180_14443_init

```c
pn5180_proto_t *pn5180_14443_init(pn5180_t *pn5180, int max_cards);
```

Создаёт объект протокола ISO14443A. `max_cards` — наибольшее число карт, которое перечисляет один опрос, 0 — значение
по умолчанию, 14; этот предел нужен на случай карты, которая не слушается HLTA и каждый раз показывает новый UID.
`NULL`, если `max_cards` отрицательно или кончилась память. Освобождается `free()`.

### pn5180_14443_get_all_uids_ex

```c
pn5180_uids_array_t *pn5180_14443_get_all_uids_ex(pn5180_proto_t *proto, pn5180_poll_status_t *status);
```

Опрос ISO14443A со статусом (`status` может быть `NULL`). Массив в куче при `PN5180_POLL_FOUND`, иначе `NULL`.

### pn5180_14443_4_transceive

```c
bool pn5180_14443_4_transceive(pn5180_t *pn5180, const uint8_t *apdu, size_t apdu_len, uint8_t *rx, size_t *rx_len);
```

Обменивается APDU с выбранной картой ISO14443-4: цепочки блоков в обе стороны, продления времени ожидания, повторные
передачи. `rx_len` на входе — размер `rx`, на выходе — длина ответа (данные, SW1, SW2). `false` при ошибке или если нет
активной сессии ISO14443-4; неудачный обмен завершает сессию через S(DESELECT), и карту нужно выбрать заново.

### pn5180_14443_4_select_file

```c
bool pn5180_14443_4_select_file(pn5180_t *pn5180, const uint8_t *file_id, size_t file_id_len);
```

SELECT по ISO 7816-4: по AID, если байт больше двух (P1 04h, P2 00h), иначе по идентификатору файла (P1 00h, P2 0Ch),
с одной повторной попыткой с P2 00h, если карта отвергает выбор файла. `true` при `90 00`.

### pn5180_14443_4_read_binary

```c
bool pn5180_14443_4_read_binary(pn5180_t *pn5180, uint16_t offset, uint8_t le, uint8_t *buffer, size_t *got);
```

READ BINARY по ISO 7816-4 из выбранного файла: `offset` до 7FFFh, `le` — сколько байт запрошено (0 — 256). `got` на
входе — размер буфера, на выходе — число полученных байт; если ответ не помещается, `false`, а в `got` — нужный размер.
`false` и при слове состояния с ошибкой.

### Утилиты APDU

```c
typedef struct {
    uint8_t cla, ins, p1, p2;
    const uint8_t *data;      /* points into the parsed buffer */
    size_t         data_len;
    bool           has_le;
    uint16_t       le;        /* an encoded Le of 0 is 256 */
} pn5180_apdu_command_t;

typedef struct {
    const uint8_t *data;      /* points into the parsed buffer */
    size_t         data_len;
    uint8_t        sw1, sw2;
} pn5180_apdu_response_t;

esp_err_t pn5180_apdu_parse_command(const uint8_t *buffer, size_t length, pn5180_apdu_command_t *command);
esp_err_t pn5180_apdu_parse_response(const uint8_t *buffer, size_t length, pn5180_apdu_response_t *response);
esp_err_t pn5180_apdu_build_response(uint8_t *buffer, size_t buffer_size, const uint8_t *data, size_t data_len,
                                     uint8_t sw1, uint8_t sw2, size_t *response_len);
uint16_t  pn5180_apdu_get_status(const pn5180_apdu_response_t *response);
```

Без выделения памяти и без обращений к железу.

- `pn5180_apdu_parse_command()`: короткие APDU случаев 1, 2S, 3S и 4S. `ESP_OK`; `ESP_ERR_NOT_SUPPORTED` для APDU
  расширенной длины, `ESP_ERR_INVALID_ARG` для неправильно составленных данных.
- `pn5180_apdu_parse_response()`: данные и SW1 SW2. `ESP_ERR_INVALID_ARG`, если байт меньше двух.
- `pn5180_apdu_build_response()`: записывает `DATA SW1 SW2`. `ESP_ERR_NO_MEM`, если буфер мал, `ESP_ERR_INVALID_ARG`
  при неверных аргументах.
- `pn5180_apdu_get_status()`: SW1 и SW2, собранные в одно слово, 0 для `NULL`.
- `PN5180_APDU_SW_SUCCESS` (9000h), `PN5180_APDU_SW_WRONG_LENGTH` (6700h), `PN5180_APDU_SW_WRONG_P1P2` (6A86h),
  `PN5180_APDU_SW_INS_NOT_SUPPORTED` (6D00h), `PN5180_APDU_SW_CLA_NOT_SUPPORTED` (6E00h).

## pn5180-15693.h

### pn5180_15693_init

```c
typedef enum {
    PN5180_15693_26KASK100 = 0x0D,   /* 26 kbit/s, ASK 100 % */
    PN5180_15693_26KASK10  = 0x0E,   /* 26 kbit/s, ASK 10 % */
} pn5180_15693_rf_config_t;

pn5180_proto_t *pn5180_15693_init(pn5180_t *pn5180, pn5180_15693_rf_config_t rf_config);
```

Создаёт объект протокола ISO15693; `rf_config` — то, что загружает `setup_rf()`. Инвентаризация идёт сначала с ASK
10 %, а при неудаче — с ASK 100 %, что бы ни было в `rf_config`. `authenticate` равен `NULL`. `NULL`, если кончилась
память. Освобождается `free()`.

### pn5180_15693_get_all_uids_ex

```c
pn5180_uids_array_t *pn5180_15693_get_all_uids_ex(pn5180_proto_t *proto, pn5180_poll_status_t *status);
```

Инвентаризация ISO15693 со статусом (`status` может быть `NULL`): `PN5180_POLL_FOUND`, `PN5180_POLL_NO_TARGET`,
`PN5180_POLL_TRANSPORT_ERROR`, `PN5180_POLL_NO_MEMORY` или `PN5180_POLL_INVALID_ARGUMENT`; никогда не
`PN5180_POLL_PROTOCOL_ERROR`. Элементы массива отсортированы по `agc`, сначала самые сильные.

## pn5180-mifare.h

Низкоуровневые операции с выбранной картой ISO14443A. Обычный путь — колбэки `block_read`, `block_write` и
`authenticate`; эти функции добавляют к ним операции с блоками значения.

### pn5180_mifare_block_read

```c
bool pn5180_mifare_block_read(pn5180_t *pn5180, int blockno, uint8_t *buffer, size_t buffer_len);
```

READ (30h) блока или первой страницы `blockno` (от 0 до 255): блок Classic или четыре страницы Ultralight / NTAG, с
переходом на страницу 0 в конце памяти. `true`, если карта ответила 16 байтами; из них копируются первые `buffer_len`.

### pn5180_mifare_block_write

```c
int pn5180_mifare_block_write(pn5180_t *pn5180, int blockno, const uint8_t *buffer, size_t buffer_len);
```

`buffer_len` ровно 4: WRITE (A2h) одной страницы Ultralight / NTAG. 16 и больше: MIFARE WRITE (A0h) блока из 16 байт.
0 при успехе; отрицательное значение при ошибке: -1 — неверные аргументы или нет ответа, -2 — подтверждение неверной
длины, -3 — NAK на команду, -5, -6 и -8 — то же для данных.

### Блоки значения

```c
bool pn5180_mifare_value_read(pn5180_t *pn5180, uint8_t blockno, int32_t *value);
bool pn5180_mifare_value_write(pn5180_t *pn5180, uint8_t blockno, int32_t value, uint8_t addr);
bool pn5180_mifare_increment(pn5180_t *pn5180, uint8_t blockno, uint32_t delta);
bool pn5180_mifare_decrement(pn5180_t *pn5180, uint8_t blockno, uint32_t delta);
bool pn5180_mifare_restore(pn5180_t *pn5180, uint8_t blockno);
bool pn5180_mifare_transfer(pn5180_t *pn5180, uint8_t blockno);
```

Сектор должен быть аутентифицирован.

- `pn5180_mifare_value_read()` читает блок и проверяет формат блока значения (значение, инвертированное значение,
  значение, затем четыре раза байт адреса, два из них инвертированы); для блока в другом формате — `false`, и `*value`
  не меняется.
- `pn5180_mifare_value_write()` записывает блок в формате блока значения со значением `value` и байтом адреса `addr`,
  обычно это номер блока.
- `pn5180_mifare_increment()`, `pn5180_mifare_decrement()` и `pn5180_mifare_restore()` кладут свой результат в буфер
  передачи карты; `pn5180_mifare_transfer()` сохраняет буфер передачи в блок.

## pn5180-ndef.h

### Типы

```c
typedef enum {
    PN5180_NDEF_TNF_EMPTY, PN5180_NDEF_TNF_WELL_KNOWN, PN5180_NDEF_TNF_MEDIA_TYPE, PN5180_NDEF_TNF_ABSOLUTE_URI,
    PN5180_NDEF_TNF_EXTERNAL, PN5180_NDEF_TNF_UNKNOWN, PN5180_NDEF_TNF_UNCHANGED, PN5180_NDEF_TNF_RESERVED
} pn5180_ndef_tnf_t;

typedef struct {
    pn5180_ndef_tnf_t tnf;
    uint8_t           type_len;
    uint8_t           id_len;
    uint32_t          payload_len;
    const uint8_t    *type;
    const uint8_t    *id;
    const uint8_t    *payload;
} pn5180_ndef_record_t;

typedef struct {
    pn5180_ndef_record_t *records;      /* array of the caller */
    size_t                record_count;
    size_t                capacity;
} pn5180_ndef_message_t;

typedef struct {
    uint8_t              *raw_data;     /* the encoded message */
    size_t                raw_data_len;
    pn5180_ndef_record_t *records;      /* chunks put together */
    size_t                record_count;
} pn5180_ndef_message_parsed_t;
```

Запись указывает в память, которой не владеет. `pn5180_ndef_message_t` — собираемое сообщение в памяти вызывающего
кода; `pn5180_ndef_message_parsed_t` — прочитанное или разобранное сообщение в куче.

Флаги заголовка записи: `PN5180_NDEF_MB`, `PN5180_NDEF_ME`, `PN5180_NDEF_CF`, `PN5180_NDEF_SR`, `PN5180_NDEF_IL`,
`PN5180_NDEF_TNF_MASK`. Типы Well-known: `PN5180_NDEF_RTD_TEXT` (`T`), `PN5180_NDEF_RTD_URI` (`U`),
`PN5180_NDEF_RTD_SMARTPOSTER` (`Sp`) и их константы `_LEN`.

### pn5180_ndef_result_t

| Значение | Код | Описание |
| -------- | --- | -------- |
| `PN5180_NDEF_OK` | 0 | успех |
| `PN5180_NDEF_ERR_INVALID_PARAM` | -1 | указатель `NULL` или неверный размер |
| `PN5180_NDEF_ERR_NO_MEMORY` | -2 | не удалось выделить память |
| `PN5180_NDEF_ERR_READ_FAILED` | -3 | карта не отдала данные |
| `PN5180_NDEF_ERR_WRITE_FAILED` | -4 | карта не приняла запись |
| `PN5180_NDEF_ERR_NO_NDEF` | -5 | не отформатирована под NDEF или сообщения нет |
| `PN5180_NDEF_ERR_PARSE_FAILED` | -6 | данные метки или сообщения противоречивы |
| `PN5180_NDEF_ERR_BUFFER_TOO_SMALL` | -7 | зарезервировано, не возвращается |
| `PN5180_NDEF_ERR_CARD_FULL` | -8 | сообщение не помещается |
| `PN5180_NDEF_ERR_UNSUPPORTED` | -9 | тип карты, версия схемы размещения или условия доступа, которые драйвер не поддерживает |
| `PN5180_NDEF_ERR_ACCESS_DENIED` | -10 | сообщение защищено от чтения |
| `PN5180_NDEF_ERR_READ_ONLY` | -11 | capability container не даёт права записи |

`const char *pn5180_ndef_result_to_string(pn5180_ndef_result_t result)` возвращает статический текст для лога.

### pn5180_ndef_read_card_auto

```c
pn5180_ndef_result_t pn5180_ndef_read_card_auto(pn5180_proto_t *proto, pn5180_uid_t *uid,
                                                pn5180_ndef_message_parsed_t **out_msg);
```

Читает сообщение NDEF выбранной карты по той схеме размещения, которой требует её `subtype`: Type 2, MIFARE Classic,
Type 4 или Type 5. Перед этим должна отработать `detect_card_type_and_capacity()`. Неудачное чтение повторяется один
раз после нового выбора. Сообщение освобождается `pn5180_ndef_free_parsed_message()`. Результаты для каждой схемы
размещения — в разделе [Чтение](ndef.md#чтение).

### pn5180_ndef_write_card_auto

```c
pn5180_ndef_result_t pn5180_ndef_write_card_auto(pn5180_proto_t *proto, const pn5180_uid_t *uid,
                                                 const pn5180_ndef_message_t *msg);
```

Записывает сообщение хотя бы из одной записи в NDEF TLV метки Type 2 или Type 5, отформатированной под NDEF. См.
[Запись на метку](ndef.md#запись-на-метку).

### pn5180_ndef_free_parsed_message

```c
void pn5180_ndef_free_parsed_message(pn5180_ndef_message_parsed_t *msg);
```

Освобождает сообщение, полученное от `pn5180_ndef_read_card_auto()`, `pn5180_ndef_parse_message()` или
`pn5180_ndef_read_from_selected_card()`. `NULL` допустим.

### Сборка сообщения

```c
void   pn5180_ndef_message_init(pn5180_ndef_message_t *msg, pn5180_ndef_record_t *records, size_t capacity);
bool   pn5180_ndef_message_add(pn5180_ndef_message_t *msg, const pn5180_ndef_record_t *rec);
void   pn5180_ndef_record_init(pn5180_ndef_record_t *rec, pn5180_ndef_tnf_t tnf, const uint8_t *type,
                               uint8_t type_len, const uint8_t *id, uint8_t id_len, const uint8_t *payload,
                               uint32_t payload_len);
bool   pn5180_ndef_make_text_record(pn5180_ndef_record_t *rec, const char *lang_code, const uint8_t *text,
                                    size_t text_len, bool utf16, uint8_t *payload_buf, size_t payload_buf_len);
bool   pn5180_ndef_make_uri_record(pn5180_ndef_record_t *rec, const char *uri, bool abbreviate,
                                   uint8_t *payload_buf, size_t payload_buf_len);
bool   pn5180_ndef_make_mime_record(pn5180_ndef_record_t *rec, const char *mime_type, const uint8_t *data,
                                    size_t data_len, uint8_t *type_buf, size_t type_buf_len);
bool   pn5180_ndef_make_external_record(pn5180_ndef_record_t *rec, const char *type_name, const uint8_t *data,
                                        size_t data_len, uint8_t *type_buf, size_t type_buf_len);
size_t pn5180_ndef_encode_message(const pn5180_ndef_message_t *msg, uint8_t *out, size_t out_len);
```

- `pn5180_ndef_message_add()` копирует запись, но не её данные; `false`, если массив заполнен.
- `pn5180_ndef_make_text_record()`: полезная нагрузка (байт статуса, код языка не длиннее 63 байт, текст) записывается
  в `payload_buf`, которому нужно `1 + strlen(lang_code) + text_len` байт.
- `pn5180_ndef_make_uri_record()`: полезная нагрузка (код префикса, остаток URI) записывается в `payload_buf`, которому
  нужно `1 + strlen(uri)` байт; с `abbreviate` самый длинный известный префикс заменяется своим кодом.
- `pn5180_ndef_make_mime_record()`, `pn5180_ndef_make_external_record()`: тип (от 1 до 255 байт) копируется в
  `type_buf` без NUL; полезная нагрузка указывает на `data`, который может быть `NULL`, только если `data_len` равен 0.
- `pn5180_ndef_encode_message()`: размер закодированного сообщения, если `out` равен `NULL` или `out_len` равен 0,
  иначе число записанных байт; 0 при ошибке, и тогда ничего не записано: нет записей, мал буфер, длина без своего
  указателя, запись Empty с типом, ID или полезной нагрузкой, запись Unknown с типом, TNF Unchanged или Reserved.

Все буферы, на которые указывает запись, должны оставаться действительными, пока сообщение не закодировано или не
записано.

### Записи

```c
pn5180_ndef_record_type_t pn5180_ndef_get_record_type(const pn5180_ndef_record_t *rec);
bool   pn5180_ndef_record_is_text(const pn5180_ndef_record_t *rec);
bool   pn5180_ndef_record_is_uri(const pn5180_ndef_record_t *rec);
bool   pn5180_ndef_record_is_smartposter(const pn5180_ndef_record_t *rec);
bool   pn5180_ndef_extract_text(const pn5180_ndef_record_t *rec, const uint8_t **text_out, size_t *text_len_out,
                                char *lang_buf, size_t lang_buf_len, bool *is_utf16);
size_t pn5180_ndef_extract_uri(const pn5180_ndef_record_t *rec, char *uri_buf, size_t uri_buf_len);
size_t pn5180_ndef_decode_smartposter(const pn5180_ndef_record_t *rec, pn5180_ndef_record_t *records,
                                      size_t capacity);
```

- `pn5180_ndef_get_record_type()`: `PN5180_NDEF_RECORD_TYPE_TEXT`, `_URI`, `_SMARTPOSTER`, `_MIME`, `_EXTERNAL`,
  `_EMPTY` или `_UNKNOWN`.
- `pn5180_ndef_extract_text()`: `true` для правильной записи Text. `*text_out` указывает в полезную нагрузку,
  `*text_len_out` байт, без завершающего NUL. Код языка записывается в `lang_buf` с завершающим NUL и обрезается, если
  он длиннее буфера (в 64 байта помещается любой); `lang_buf` и `is_utf16` могут быть `NULL`. При ошибке `lang_buf`
  остаётся как был.
- `pn5180_ndef_extract_uri()`: длина полного URI с развёрнутым префиксом, без NUL, или 0 для записи, которая не URI.
  В `uri_buf` записывается строка с завершающим NUL, если `uri_buf_len` > 0, обрезанная, если результат равен
  `uri_buf_len` или больше; `NULL` запрашивает только длину.
- `pn5180_ndef_decode_smartposter()`: записи сообщения внутри Smart Poster, указывающие в его полезную нагрузку. 0 для
  неправильного внутреннего сообщения, записей из фрагментов (chunk) или записей больше, чем `capacity`.

### Разбор

```c
pn5180_ndef_result_t pn5180_ndef_parse_message(const uint8_t *raw_data, size_t raw_data_len,
                                               pn5180_ndef_message_parsed_t **out_msg);
size_t pn5180_ndef_decode_message(const uint8_t *in, size_t in_len, pn5180_ndef_record_t *records, size_t capacity);
bool   pn5180_ndef_decode_next(const uint8_t *in, size_t in_len, size_t *offset, pn5180_ndef_record_t *out_rec,
                               bool *is_begin, bool *is_end);
```

- `pn5180_ndef_parse_message()`: закодированное сообщение (без TLV) — в сообщение в куче, которое владеет копией
  данных, фрагменты записей собраны вместе; первый фрагмент задаёт TNF, тип и ID, у следующих должен быть TNF
  Unchanged.
- `pn5180_ndef_decode_message()`: в массив вызывающего кода, записи указывают в `in`, фрагменты остаются отдельными
  записями. Число записей, 0 при ошибке или если массив мал.
- `pn5180_ndef_decode_next()`: одна запись по смещению `*offset`, которое сдвигается дальше; в `is_begin` и `is_end`
  (могут быть `NULL`) записываются флаги MB и ME.

Обе функции разбора сообщений проверяют, что Message Begin стоит только у первой записи, Message End — у последней,
после неё ничего нет, а последовательности фрагментов правильны.

### pn5180_ndef_read_from_selected_card (deprecated)

```c
pn5180_ndef_result_t pn5180_ndef_read_from_selected_card(pn5180_proto_t *proto, int start_block, int block_size,
                                                         int max_blocks, pn5180_ndef_auth_callback_t auth_cb,
                                                         pn5180_ndef_sector_id_callback_t sector_cb, void *auth_ctx,
                                                         pn5180_ndef_message_parsed_t **out_msg);
```

Читает блоки как есть, начиная со `start_block`, пока не найдёт полный NDEF TLV, и перед блоком вызывает `auth_cb`
(если задан `sector_cb` — только когда он сообщает о новом секторе). Устарела, вместо неё —
`pn5180_ndef_read_card_auto()`, которая знает раскладку памяти каждого типа карт: на метке Type 2 этой функции нужны
страница 4 и блоки по 4 байта, а при чтении по 16 байт любое сообщение длиннее первого прочитанного куска получается
искажённым.

## pn5180-ndef-tlv.h

### pn5180_ndef_tlv_find_ndef

```c
bool pn5180_ndef_tlv_find_ndef(const uint8_t *data, size_t data_len, size_t *search_pos, size_t *ndef_offset,
                               size_t *ndef_length);
```

Ищет NDEF TLV (тип 03h) в байтах области данных метки, пропуская другие TLV. `true`, если найдены его тип и длина:
`*ndef_offset` — смещение сообщения в `data`, `*ndef_length` — его объявленная длина, причём сообщение может выходить
за `data_len`, если в `data` лежит только начало памяти; это нужно проверить перед чтением. `false`, если полного
заголовка NDEF TLV пока нет или раньше встретился Terminator TLV; тогда `*search_pos` указывает на TLV, на котором
поиск остановился, чтобы его можно было продолжить с новыми данными.
