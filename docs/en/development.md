# Development

*[По-русски](../ru/development.md)*

For those who change the driver: the layout of the repository, building the examples against it, the host tests and
the documentation.

## The repository

| Path | What it is |
| ---- | ---------- |
| `include/pn5180.h` | the reader layer: SPI, device, field, RF exchange, registers, EEPROM, LPCD; the protocol interface |
| `include/pn5180-14443.h`, `src/pn5180-14443.c` | ISO14443A: poll, select, card types, halt, MIFARE authentication; ISO14443-4 |
| `src/pn5180-apdu.c` | the APDU utilities, declared in `pn5180-14443.h` |
| `include/pn5180-15693.h`, `src/pn5180-15693.c` | ISO15693: inventory, select, blocks, system information |
| `include/pn5180-mifare.h`, `src/pn5180-mifare.c` | MIFARE READ and WRITE, value blocks |
| `include/pn5180-ndef.h`, `src/pn5180-ndef.c` | NDEF records and messages: building, encoding, parsing |
| `src/pn5180-ndef-auto.c` | NDEF on tags: Type 2, MIFARE Classic, Type 4, Type 5 |
| `include/pn5180-ndef-tlv.h`, `src/pn5180-ndef-tlv.c` | the NDEF TLV search |
| `include/pn5180-internal.h` | timeouts, debug logging and helpers shared by the sources; not public |
| `src/pn5180.c` | the reader layer |
| `examples/` | `simple_main`, `app_logic`, `ndef` |
| `host_test/` | tests on the computer, without hardware |
| `docs/en/`, `docs/ru/` | this documentation |
| `CHANGES.md` | release notes |

The protocol code talks to the PN5180 only through the functions of `pn5180.h`, `pn5180_rf_transceive()` most of all.
That boundary is what the host tests use: the first test program replaces `src/pn5180.c` and simulates cards behind
it, the second runs `src/pn5180.c` against a model of the chip.

## Building the examples

Inside the repository the examples build against the repository itself, whatever its directory is called; the
component manager is switched off for them:

```sh
. ~/esp/esp-idf/export.sh          # or the activation script of your ESP-IDF installation
idf.py -C examples/simple_main set-target esp32
idf.py -C examples/simple_main build
idf.py -C examples/app_logic set-target esp32s3
idf.py -C examples/app_logic build
```

`-B <directory>` puts the build elsewhere, which allows several ESP-IDF versions side by side. The component builds with
ESP-IDF 5.0.4 and later, 6.x included. Its public requirements are `driver` and, since ESP-IDF 5.3, `esp_driver_spi`
and `esp_driver_gpio`, because `pn5180.h` includes `driver/gpio.h` and `driver/spi_master.h`.

## Host tests

`host_test/` builds two programs for the computer and runs them under AddressSanitizer and UndefinedBehaviorSanitizer:

- **`pn5180_host_test`**: the protocol code (ISO14443, ISO15693, MIFARE, APDU, NDEF) with `src/pn5180.c` replaced by
  `host_test/fake_pn5180.c`, which answers `pn5180_rf_transceive()` with simulated cards (`host_test/sim_cards.c`):
  NTAG, Ultralight C, MIFARE Classic, an ISO14443-4 card with a Type 4 application, an ISO15693 tag.
- **`pn5180_chip_test`**: the reader layer `src/pn5180.c` itself, against stand-ins of the ESP-IDF SPI master, GPIO,
  `esp_timer` and semaphores (`host_test/stubs/`), with a model of the PN5180 host interface behind them
  (`host_test/chip_sim.c`: commands, BUSY, registers, EEPROM, the field).

```sh
make -C host_test test IDF_PATH=<path to esp-idf>
```

The Unity sources come from the ESP-IDF checkout, or from a plain Unity checkout with `UNITY_DIR=<path to Unity/src>`.
The GitHub workflow [`.github/workflows/host-test.yml`](../../.github/workflows/host-test.yml) runs the tests on every
push and pull request.

The tests cover polling (also of fields with many cards), selection, card identification, NDEF reading for all four
mappings and writing for Type 2 and Type 5, ISO14443-4 chaining and recovery from lost frames, MIFARE value operations,
and misbehaving cards (one that ignores HLTA, one that answers with empty chained blocks, a MIFARE Classic card that
misses authentications, a Type 4 card whose SELECT answers lack the status word). For the reader layer they cover the
SPI framing and the BUSY handshake, boot and firmware checks, pin checks, the field and RF collision avoidance, how
`pn5180_rf_transceive()` maps the receiver status to its results, the Timer1 values of the receive timeout, the MIFARE
authentication status, recovery, EEPROM writes, the IRQ pin and the timing of the driver's waits.

The model behaves as the datasheet describes the PN5180; real RF timing and real cards still need the hardware.

A new behaviour of the protocol code gets a test with a simulated card in `host_test/test_main.c`; a new behaviour of
the reader layer a test against the model in `host_test/test_chip.c`.

## Code style

`.clang-format` in the root holds the formatting. Public names start with `pn5180_` and `PN5180_`, in snake case.
Limits a program may want to change are parameters of the `..._init()` functions, not build-time macros.

## Documentation

The documentation is Markdown that reads the same on GitHub and on [jef-sure.github.io](https://jef-sure.github.io/),
where it is published from the latest release:

- `README.md` and `README.ru.md`: what the component is, a quick start, the map of the pages;
- `docs/en/*.md` and `docs/ru/*.md`: the pages, the same file names in both languages;
- `examples/*/README.md`: one page per example.

Links between pages are relative, so they work in the repository, in the component archive and on the site. A change
of behaviour also changes the page that describes it.

## The component archive

`idf_component.yml` lists what goes into the archive of the ESP Component Registry: everything is excluded, and the
files of the component, the examples and the documentation are included by name patterns. A new kind of file (a
`Kconfig`, a `.cpp` source, a picture in `docs/`) stays out until it is added to `include`. The host tests, the CI
configuration and the editor settings stay out.
