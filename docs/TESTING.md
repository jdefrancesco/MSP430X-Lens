# Testing MSP430X Lens

## Automated tests

Run the complete suite from the repository root:

```sh
make test
```

The runner uses `BNPYTHON` when set, searches for `bnpython3` on `PATH`, and
then falls back to Binary Ninja's standard macOS application path. For another
installation, provide its launcher explicitly:

```sh
BNPYTHON=/path/to/bnpython3 make test
```

User plugins are disabled during the run so an installed or stale copy cannot
affect results. The suite includes a Binary Ninja factory-path integration test
that constructs a raw MSP430F5438 main-flash image, creates the registered
`MSP430F5438` view, waits for analysis, and verifies its architecture, reset
handler, executable mapping, recovered sparse function, and R12 string-call
prototype recovery. A second base-zero lower-64-KiB fixture verifies F5438A
device-ID selection, typed factory TLV records, peripheral discovery,
CRC-16/CCITT-FALSE validation, and annotation idempotence.

## UI smoke test

Link this checkout into Binary Ninja's user plugin directory and generate the
deterministic raw fixture:

```sh
make dev-link fixture
```

The linker refuses to replace an existing plugin or symlink. Set
`BN_USER_PLUGIN_DIR` if Binary Ninja uses a nonstandard user plugin directory.
Restart Binary Ninja after creating the link or changing plugin code because
Architecture and BinaryView plugins are loaded at startup.

`make fixture` creates both `build/sparse-code-islands.bin` and
`build/base-zero-low64k-tlv.bin`. Open either using:

```text
MSP430F5438 Raw Firmware (MSP430X)
```

Verify the loader and registration:

1. Confirm the selected view is `MSP430F5438`, not generic `Raw` or
   `Firmware`.
2. Confirm the architecture/platform is `msp430x`.
3. Confirm the `Tools -> MSP430F5438` commands are present.
4. Run `Tools -> MSP430F5438 -> Diagnose active view`.
5. Confirm `0x5c00` is the reset-handler function.
6. Confirm `0x6000` is recovered as a function even though nothing references
   it.
7. Confirm the adjacent interrupt handlers at `0x6100`, `0x6108`, and `0x610c`
   are all recovered from one backed island.
8. Confirm the C initializer table at `0x6112`, immediately after those
   handlers, is data rather than another function.
9. Confirm the function at `0x6d00` contains `call r11` at `0x6d04` and the
   following `ret` at `0x6d06`, and is not marked `noreturn`.
10. Confirm the indirect call resolves through the pointer at `0xe000` to the
    returning function at `0x7de0`.
11. In the Strings sidebar, confirm the five-character junk run at `0x6800` is
    absent while `MSP430X!` at `0x6820` and the bootloader diagnostic at
    `0x6840` are present.
12. Open Pseudo C at `0x6e00` and confirm the call at `0x6e0a` includes
    `"module=startup state=%u result=%u"`. In Disassembly, confirm the string
    address is loaded into R12 immediately before that call. The target at
    `0x6e40` should have a first `char *format` parameter rather than losing the
    R12 value during HLIL simplification.
13. Confirm the long `0xff` ranges between code islands remain
    non-executable data.
14. Spot-check reset/vector and MSP430 header labels.

For the synthetic `build/base-zero-low64k-tlv.bin`, also verify:

1. The mapped view selects the `MSP430F5438A` device profile from ID bytes
   `05 80` at `0x1a04`.
2. `0x1a00`, `0x1a08`, `0x1a14`, and `0x1a26` render as named packed TLV
   structures, while the peripheral descriptor at `0x1a2e` is a bounded byte
   array rather than code.
3. Run `Tools -> MSP430F5438 -> Report TLV device descriptors and CRC16` and
   confirm the stored and computed CRC are both `0xc3ca`.
4. Confirm the report lists `CRC16` and `CRC16_RB` at peripheral base `0x150`.
5. Run `Diagnose active view` and confirm it reports
   `tlv=valid device=MSP430F5438A records=4 crc16=valid`.

The synthetic descriptor order and peripheral payload follow the device
descriptor table in TI's
[MSP430F5438A datasheet](https://www.ti.com/lit/ds/symlink/msp430f5419a.pdf).

If `Open With Options` predicts ARM/Thumb, close the view and reopen it with
the exact MSP430F5438 view type. The generic firmware loader is not the mapped
MSP430F5438 loader.

Automatic strings are discovered only during Binary Ninja's first analysis
pass. If short junk strings remain after a plugin update, close the old view and
reopen the original firmware; `Re-run MSP430X analysis` cannot remove entries
already recorded by the core string scanner. The mapped-raw loader applies the
eight-character minimum automatically. Before opening an ELF, set Binary
Ninja's `analysis.limits.minStringLength` option to eight manually; the planned
ELF pre-analysis hook will make that per-view setup automatic.

For an already-open mapped or ELF file, run
`Tools -> MSP430F5438 -> Re-run MSP430X analysis` and check the log for:

```text
Seeded N unreferenced MSP430X sparse code-island function(s).
```

For a direct call preceded by a constant R12 string load, also confirm the log
reports recovered R12 string parameters and that the string appears as the
first argument in Pseudo C. The recovery is intentionally skipped when the
target already has a user type, an R12 parameter, or a more specific inferred
prototype.

## Larger-firmware readiness

Before relying on changes to device mapping for a larger MSP430X target, test
at least one image with real backed contents above `0x10000`. Confirm that:

- backed high-bank flash is executable, read-only code;
- unbacked or erased high-bank tails remain non-executable data;
- direct calls and recovered functions use their full 20-bit addresses; and
- strings or lookup tables in high banks are not seeded as functions.

The bundled deterministic fixture covers main flash through `0xffff`; high-bank
mapping remains a separate manual check until a high-bank fixture is added.
