# ndef

Two NDEF snippets to copy into a program; this directory is not a project of its own and is not built.

- **`main/ndef_test.c`**, `run_ndef_demo()`: builds a message of a Text record and a URI record in memory, encodes it,
  prints the bytes and decodes them back. No reader is needed: the functions of `pn5180-ndef.h` that build and parse
  messages work on buffers alone.
- **`main/ndef_read_example.c`**, `example_read_ndef_from_card()`: reads the NDEF message of a selected card with
  `pn5180_ndef_read_card_auto()` and prints its records, with the URI expanded and the text with its language.

## Using them

Copy a file into the `main/` directory of a project that has the component (see
[Getting started](../../docs/en/getting-started.md)) and add it to `SRCS` in `main/CMakeLists.txt`.

`run_ndef_demo()` can be called from `app_main()` as it is. `example_read_ndef_from_card()` takes the protocol object
and a card that is selected and whose type was detected:

```c
pn5180_uid_t *card = &cards->uids[i];
if (proto->select_by_uid(proto, card)) {
    int blocks = 0, block_size = 0;
    if (proto->detect_card_type_and_capacity(proto->pn5180, card, &blocks, &block_size)) {
        proto->select_by_uid(proto, card);
    }
    example_read_ndef_from_card(proto, card);
    proto->halt(proto);
}
```

Writing a message to a tag, the records the driver knows and the results of each mapping are described in
[NDEF](../../docs/en/ndef.md).
