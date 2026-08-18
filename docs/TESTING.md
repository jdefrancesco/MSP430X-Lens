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

The ELF factory-path integration test constructs a dependency-free ELF32
`EM_MSP430` executable and verifies that `msp430x`, string filtering, vectors,
header labels, and TLV annotations are installed before initial analysis
without changing ELF sections or creating duplicate-platform functions.

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

Disable any Plugin Manager installation of MSP430X Lens while the development
symlink is active. Two enabled copies can register different versions in
load-order-dependent fashion; restart Binary Ninja after enabling or disabling
either copy.

`make fixture` creates `build/sparse-code-islands.bin`,
`build/base-zero-low64k-tlv.bin`, and `build/msp430x-lens-fixture.elf`. Open the
two raw images using:

```text
MSP430F5438 Raw Firmware (MSP430X)
```

Verify the loader and registration:

1. Confirm the selected view is `MSP430F5438`, not generic `Raw` or
   `Firmware`.
2. Confirm the architecture/platform is `msp430x`.
3. Confirm the `Tools -> MSP430F5438` commands are present.
4. Run `Tools -> MSP430F5438 -> Diagnose active view`.
5. Let initial analysis and the automatic `Recovering MSP430X R12 string call
   sites` background task finish. Do not run a manual analysis command for this
   smoke test.
6. Confirm `0x5c00` is the reset-handler function.
7. Confirm `0x6000` is recovered as a function even though nothing references
   it.
8. Confirm the adjacent interrupt handlers at `0x6100`, `0x6108`, and `0x610c`
   are all recovered from one backed island.
9. Confirm the C initializer table at `0x6112`, immediately after those
   handlers, is data rather than another function.
10. Confirm the function at `0x6d00` contains `call r11` at `0x6d04` and the
   following `ret` at `0x6d06`, and is not marked `noreturn`.
11. Confirm the indirect call resolves through the pointer at `0xe000` to the
    returning function at `0x7de0`.
12. In the Strings sidebar, confirm the five-character junk run at `0x6800` is
    absent while `MSP430X!` at `0x6820` and the bootloader diagnostic at
    `0x6840` are present.
13. Open Pseudo C at `0x6e00` and confirm the call at `0x6e0a` includes
    `"module=startup state=%u result=%u"`. In Disassembly, confirm the string
    address is loaded into R12 immediately before that call. The call-site type
    adjustment should have a first `char *format` parameter while the target at
    `0x6e40` retains its original auto-inferred type.
14. Confirm the long `0xff` ranges between code islands remain
    non-executable data.
15. Open Pseudo C at `0x6f00` and confirm the unused hardware read remains
    visible as `mmio_read16(&DMACTL0)`. Confirm `DMACTL0` at `0x500` is a
    volatile two-byte data variable; the `_L`/`_H` aliases should remain
    navigable symbols without overlapping data variables.
16. Spot-check reset/vector and other MSP430 header labels.

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

Open `build/msp430x-lens-fixture.elf` with the normal `ELF` view and verify,
before running any manual plugin command:

1. Architecture and platform are both `msp430x`.
2. `_start` remains the single function at `0x5c00`; there is no parallel
   built-in `msp430` function.
3. `.tlv`, `.text`, `.rodata`, and `.vectors` retain their ELF permissions.
4. The F5438A TLV types/CRC comment, `vector_reset`, and `WDTCTL` label are
   already present.
5. The five-character string at `0x6800` is absent while the strings at
   `0x6820` and `0x6840` are present.

The fixture carries a CRC-valid F5438A TLV block, which is why the device labels
appear automatically. An MSP430 ELF without a supported descriptor still opens
as `msp430x`, but intentionally receives no assumed F5438 addresses. After its
initial analysis, choose the matching F5438 or F5438A `Re-run MSP430X analysis`
command to select that profile explicitly. To select it before initial analysis,
set `MSP430 ELF Device Profile` in Open With Options (or Binary Ninja Settings)
before opening the ELF. `Auto` does not infer a device from flash bounds alone:
multiple MSP430 variants share the F5438 memory size and address range.

For the two `.bin` fixtures only: if `Open With Options` predicts ARM/Thumb,
close the view and reopen it with the exact MSP430F5438 raw view type. Do not
open the `.elf` fixture with the raw view; it must remain on the normal `ELF`
loader path.

Automatic strings are discovered only during Binary Ninja's first analysis
pass. If short junk strings remain after a plugin update, close the old view and
reopen the original firmware; `Re-run MSP430X analysis` cannot remove entries
already recorded by the core string scanner. Both mapped-raw and ELF executable
views apply the inherited eight-character minimum automatically.

For a direct call preceded by a constant R12 string load in a newly opened
mapped-raw or prepared ELF view, confirm the log reports automatic R12 string
recovery and that the string appears as the first argument in Pseudo C without
selecting `Re-run MSP430X analysis`. Recovery is
intentionally skipped when the target already has a user type, an R12
parameter, a more specific inferred prototype, or any existing call-site
override. Zero-parameter auto-inferred callees remain eligible; their no-return
behavior is preserved. The recovered fact is stored as a durable user override
on that one call site because Binary Ninja can remove an automatic adjustment
during later analysis. Recovery runs as a background task, and the log must not
contain `UI threads are not permitted to wait for analysis completion`. When it
finishes, an already open Pseudo C pane should repaint with the recovered string
argument; navigating away and back must not be required. After Binary Ninja
becomes idle, confirm the argument does not disappear again. The manual re-run
command remains the fallback for older already-open views and for analysis
changes made after the automatic pass. Reopening an executable MSP430X ELF
BNDB should schedule the same recovery even though Binary Ninja does not save
the plugin's auto preparation marker in databases.

For an already-open mapped or ELF file, run
`Tools -> MSP430F5438 -> Re-run MSP430X analysis` and check the log for:

```text
Seeded N unreferenced MSP430X sparse code-island function(s).
```

## Larger-firmware readiness

Before relying on changes to device mapping for a larger MSP430X target, test
at least one image with real backed contents above `0x10000`. Confirm that:

- backed high-bank flash is executable, read-only code;
- unbacked or erased high-bank tails remain non-executable data;
- direct calls and recovered functions use their full 20-bit addresses; and
- strings or lookup tables in high banks are not seeded as functions.

The bundled deterministic fixture covers main flash through `0xffff`; high-bank
mapping remains a separate manual check until a high-bank fixture is added.
