# Начало работы

*[In English](../en/getting-started.md)*

От пустого проекта ESP-IDF до программы, которая печатает UID каждой карты в поле и записанный на ней URI.

## Что нужно

- Модуль PN5180. У распространённой платы модуля антенна прямо на плате, а питание — 5 В для передатчика и 3,3 В для
  логики.
- Чип ESP32 со свободным хостом SPI и шестью GPIO (семью с пином IRQ). Примеры написаны для ESP32 и ESP32-S3.
- ESP-IDF 5.0.4 или новее, включая 6.x. 5.0.4 — первый выпуск 5.0 с `spi_bus_get_max_transaction_len()`, которая
  нужна драйверу.
- Карты: ISO14443A (MIFARE Classic, Ultralight, NTAG, DESFire и другие карты ISO14443-4, телефоны) или ISO15693 (ICODE
  SLIX и другие метки дальнего действия, vicinity).

## 1. Добавление компонента

Из ESP Component Registry, в каталоге проекта:

```sh
idf.py add-dependency "jef-sure/pn5180^0.8.2"
```

Команда записывает зависимость в `main/idf_component.yml`; менеджер компонентов скачает компонент при следующей
сборке. Вместо реестра можно скопировать этот репозиторий в `components/pn5180` проекта.

Чтобы вместо этого начать с работающей программы, создайте проект из примера:

```sh
idf.py create-project-from-example "jef-sure/pn5180:simple_main"
```

Примеры описаны в [simple_main](../../examples/simple_main/README.md),
[app_logic](../../examples/app_logic/README.md) и [ndef](../../examples/ndef/README.md).

## 2. Подключение модуля

| PN5180 | ESP32 (`simple_main`) | ESP32-S3 (`app_logic`) | Что это |
| ------ | --------------------- | ---------------------- | ------- |
| 5V     | 5V                    | 5V                     | питание передатчика |
| 3.3V   | 3V3                   | 3V3                    | питание логики |
| GND    | GND                   | GND                    | |
| RST    | 12                    | 4                      | аппаратный сброс, активный уровень низкий |
| NSS    | 5                     | 9                      | выбор устройства SPI (chip select), активный уровень низкий, им управляет драйвер |
| MOSI   | 23                    | 7                      | данные SPI к PN5180 |
| MISO   | 19                    | 8                      | данные SPI от PN5180 |
| SCK    | 18                    | 6                      | тактовый сигнал SPI |
| BUSY   | 21                    | 5                      | PN5180 занят |
| IRQ    | не подключён          | не подключён           | необязателен, см. [Пин IRQ](hardware.md#пин-irq) |

Оба примера используют `SPI3_HOST`. Подойдут любые GPIO, с двумя ограничениями: NSS, RST, SCK и MOSI — выходы ESP32,
поэтому GPIO, работающие только на вход (GPIO 34–39 у классического ESP32), для них не годятся, а GPIO флеша и PSRAM
заняты (6–11 у классического ESP32). Драйвер проверяет свои пины и отвергает пин, который не может использовать, называя
его в строке лога. Подробнее о питании, пинах и шине SPI — на странице [Подключение, шина SPI и IRQ](hardware.md).

## 3. Первая программа

`main/main.c`:

```c
#include <stdio.h>
#include <stdlib.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pn5180.h"
#include "pn5180-14443.h"
#include "pn5180-ndef.h"

static const char *TAG = "nfc";

void app_main(void)
{
    /* SPI host, SCK, MISO, MOSI, clock */
    pn5180_spi_t *spi = pn5180_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, 7000000);
    /* NSS, BUSY, RST */
    pn5180_t *pn5180 = spi ? pn5180_init(spi, GPIO_NUM_5, GPIO_NUM_21, GPIO_NUM_12) : NULL;
    if (pn5180 == NULL) {
        ESP_LOGE(TAG, "PN5180 not found");
        return;
    }
    /* Most cards one poll enumerates, 0 for the default of 14 */
    pn5180_proto_t *nfc = pn5180_14443_init(pn5180, 0);

    while (true) {
        /* Restart the field so that cards halted by the previous scan answer again. */
        pn5180_set_rf_off(pn5180);
        pn5180_delay_us(PN5180_RF_OFF_TIME_US); /* 5.1 ms */
        nfc->setup_rf(nfc);

        pn5180_poll_status_t status;
        pn5180_uids_array_t *cards = pn5180_14443_get_all_uids_ex(nfc, &status);
        for (int i = 0; cards != NULL && i < cards->uids_count; i++) {
            pn5180_uid_t *card = &cards->uids[i];
            printf("UID:");
            for (int j = 0; j < card->uid_length; j++) {
                printf(" %02X", card->uid[j]);
            }
            printf("\n");

            if (!nfc->select_by_uid(nfc, card)) {
                continue;
            }
            int blocks = 0, block_size = 0;
            if (nfc->detect_card_type_and_capacity(pn5180, card, &blocks, &block_size)) {
                nfc->select_by_uid(nfc, card); /* detection asked for a new select */
            }

            pn5180_ndef_message_parsed_t *msg = NULL;
            if (pn5180_ndef_read_card_auto(nfc, card, &msg) == PN5180_NDEF_OK) {
                for (size_t r = 0; r < msg->record_count; r++) {
                    char uri[256];
                    if (pn5180_ndef_extract_uri(&msg->records[r], uri, sizeof(uri)) > 0) {
                        printf("  URI: %s\n", uri);
                    }
                }
                pn5180_ndef_free_parsed_message(msg);
            }
            nfc->halt(nfc);
        }
        free(cards);
        if (status == PN5180_POLL_TRANSPORT_ERROR) {
            pn5180_recover(pn5180);
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }
}
```

Что она делает, по шагам:

1. `pn5180_spi_init()` инициализирует шину SPI и добавляет на неё PN5180 как устройство. `pn5180_init()` сбрасывает
   PN5180, ждёт его загрузки и проверяет прошивку. Если что-то не так, любая из них возвращает `NULL`, а в логе
   сказано, что именно.
2. `pn5180_14443_init()` создаёт объект протокола ISO14443A. Вся работа с картами идёт через него.
3. На каждом проходе цикла поле выключается на 5,1 мс и снова включается через `setup_rf()`. Карты, найденные опросом,
   остановлены, а остановленная карта отвечает на новый опрос, только если поле перед этим выключалось.
4. `pn5180_14443_get_all_uids_ex()` возвращает все карты в поле, а статус говорит, почему не вернулось ничего.
5. Для каждой карты: `select_by_uid()` будит её и выбирает, `detect_card_type_and_capacity()` определяет её тип и
   объём памяти, `pn5180_ndef_read_card_auto()` читает её сообщение NDEF, `halt()` завершает сессию.
6. Массив карт освобождается через `free()`, сообщение NDEF — через `pn5180_ndef_free_parsed_message()`.
7. `PN5180_POLL_TRANSPORT_ERROR` значит, что не ответил сам PN5180: `pn5180_recover()` его сбрасывает.

С реестром менеджер компонентов сам добавляет `pn5180` в зависимости `main`. С копией в `components/` добавьте
`pn5180` в `REQUIRES` или `PRIV_REQUIRES` в `main/CMakeLists.txt`, если там названы какие-то компоненты; `main`, у
которого не назван ни один, видит все компоненты.

## 4. Сборка и запуск

```sh
idf.py set-target esp32
idf.py build flash monitor
```

После загрузки в логе ничего нет, пока к антенне не поднесут карту; затем появляется строка `UID: 04 A2 ...` на каждую
карту и `URI: ...` для карты, на которой записан URI. Карта, которая остаётся в поле, появляется на каждом проходе.

Если ничего не появляется, см. [Устранение неполадок](troubleshooting.md): большинство первых проблем — это
подключение, питание или линия BUSY, которая не следует за передачами SPI.

## Что дальше

- [Как работает драйвер](how-it-works.md): объекты, жизнь сессии с картой, время и ожидания, память и задачи.
- [Поиск карт](polling.md): статусы опроса, несколько карт в поле, телефоны со случайным UID.
- [Карты ISO14443A](iso14443a.md), [ISO14443-4 и APDU](iso14443-4.md), [Метки ISO15693](iso15693.md).
- [NDEF](ndef.md): чтение, записи, запись на метку.
- [Справочник API](api.md).
