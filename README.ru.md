# Компонент ESP-IDF для PN5180

*[In English: README.md](README.md)*

Драйвер ESP-IDF для NFC-фронтенда NXP PN5180, подключённого по SPI: находит карты ISO14443A и ISO15693, читает NDEF
(NTAG / Ultralight, MIFARE Classic, Type 4, ISO15693) и записывает его на метки NTAG / Ultralight и ISO15693, даёт
доступ к блокам MIFARE Classic и обменивается APDU с картами ISO14443-4 в режиме считывателя.

**Несколько карт:** один опрос возвращает все карты в поле, а не только первую, и каждую из них потом можно выбрать и
прочитать по её UID. Даже при `max_cards` меньше числа карт ни одна карта не теряется насовсем: если поле оставлено
включённым, следующие опросы продолжают с картами, которые ещё не найдены, а после сброса поля ISO14443A разрешает
коллизии случайным образом, так что за несколько опросов находится каждая карта. См.
[Несколько карт в поле](docs/ru/polling.md#несколько-карт-в-поле).

```c
pn5180_spi_t   *spi    = pn5180_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, 7000000); /* SCK, MISO, MOSI */
pn5180_t       *pn5180 = pn5180_init(spi, GPIO_NUM_5, GPIO_NUM_21, GPIO_NUM_12);                      /* NSS, BUSY, RST */
pn5180_proto_t *nfc    = pn5180_14443_init(pn5180, 0);

nfc->setup_rf(nfc);
pn5180_uids_array_t *cards = nfc->get_all_uids(nfc);
for (int i = 0; cards != NULL && i < cards->uids_count; i++) {
    pn5180_uid_t *card = &cards->uids[i];      /* UID, SAK, ATQA, signal strength */
    if (nfc->select_by_uid(nfc, card)) {
        /* identify it, read its NDEF message or its blocks, then nfc->halt(nfc) */
    }
}
free(cards);
```

## Быстрый старт

```sh
idf.py add-dependency "jef-sure/pn5180^0.8.2"
```

Нужен ESP-IDF 5.0.4 или новее, включая 6.x. Подключите SCK, MOSI, MISO, NSS, BUSY и RST модуля к свободным GPIO,
подайте на него 5 В и 3,3 В и начните с [Начала работы](docs/ru/getting-started.md): там полная программа, которая
печатает UID каждой карты и записанный на ней URI. Или возьмите пример как новый проект:

```sh
idf.py create-project-from-example "jef-sure/pn5180:simple_main"
```

## Документация

| Страница | Что в ней |
| -------- | --------- |
| [Начало работы](docs/ru/getting-started.md) | добавление компонента, подключение, первая программа, сборка |
| [Как работает драйвер](docs/ru/how-it-works.md) | объекты, жизнь сессии с картой, поле, время и ожидания, память, задачи |
| [Поиск карт](docs/ru/polling.md) | опросы и их статус, несколько карт в поле, циклы опроса, случайные UID |
| [Карты ISO14443A](docs/ru/iso14443a.md) | типы карт, выбор, аутентификация MIFARE Classic, блоки и блоки значения, страницы Ultralight и NTAG |
| [ISO14443-4 и APDU](docs/ru/iso14443-4.md) | активация, обмен APDU, SELECT и READ BINARY, утилиты APDU, телефоны |
| [Метки ISO15693](docs/ru/iso15693.md) | конфигурация RF, инвентаризация, выбор, блоки |
| [NDEF](docs/ru/ndef.md) | чтение всех четырёх схем размещения, записи, построение сообщений, запись на метки |
| [Подключение, шина SPI и IRQ](docs/ru/hardware.md) | пины, общая шина SPI, пин IRQ, обнаружение карты с малым потреблением, два считывателя |
| [Устранение неполадок](docs/ru/troubleshooting.md) | признаки, причины и что попробовать |
| [Справочник API](docs/ru/api.md) | все типы, функции и константы |
| [Разработка](docs/ru/development.md) | репозиторий, тесты на компьютере, документация |

Примеры: [simple_main](examples/simple_main/README.md) — самый маленький цикл опроса на ESP32;
[app_logic](examples/app_logic/README.md) — определение типа карты, NDEF и дампы блоков с ключами MIFARE на ESP32-S3;
[ndef](examples/ndef/README.md) — фрагменты кода для NDEF. Список изменений — в [CHANGES.md](CHANGES.md).

## Возможности

- [Несколько карт](docs/ru/polling.md#несколько-карт-в-поле): один опрос перечисляет все карты в поле — с ISO14443A до
  `max_cards` (по умолчанию 14), с ISO15693 столько, сколько позволяют 192 кадра инвентаризации (около 50 меток с
  несвязанными UID)
- ISO14443A: антиколлизия с каскадными UID, типизированный статус опроса, выбор по UID
- ISO15693: инвентаризация с разрешением коллизий, выбор, чтение и запись блоков (номера блоков больше 255 —
  расширенными командами), системная информация
- Аутентификация MIFARE Classic и доступ к блокам; доступ к страницам Ultralight / NTAG; операции с блоками значения
- Определение типа карты: MIFARE Classic Mini / 1K / 4K, MIFARE Plus 2K / 4K (уровень безопасности 2), Ultralight,
  Ultralight C, Ultralight EV1, NTAG210 / 212 / 213 / 215 / 216, ISO14443-4
- Обмен APDU по ISO14443-4 (ISO-DEP) с цепочкой блоков в обе стороны, продлением времени ожидания (WTX), повторной
  передачей и S(DESELECT)
- Разбор коротких APDU ISO 7816-4 и построение ответов без хранения состояния
- Чтение NDEF с карт Type 2, MIFARE Classic (MAD1 / MAD2), Type 4 и Type 5; сборка записей, разбитых на части (chunked)
- Построение записей NDEF (Text, URI, MIME, External), кодирование сообщений, запись TLV на метки Ultralight / NTAG и
  ISO15693
- Тайм-аут приёма на аппаратном таймере PN5180; необязательный пин IRQ; своя или общая шина SPI
- `pn5180_recover()`, обнаружение карты с малым потреблением, защита от столкновения полей (RFCA) по выбору
- `pn5180_rf_transceive()` для своих кадров RF; доступ к регистрам и EEPROM

Не реализовано: ISO14443B, FeliCa, peer-to-peer, эмуляция карты, форматирование чистых меток, запись NDEF на карты
MIFARE Classic и Type 4, аутентификация Ultralight C / DESFire.

## Лицензия

Лицензия MIT. Подробности — в [LICENSE](LICENSE).
