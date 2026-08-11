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
handler, executable mapping, and recovered sparse function.

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

Open `build/sparse-code-islands.bin` using:

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
11. Confirm the long `0xff` ranges between code islands remain
   non-executable data.
12. Spot-check reset/vector and MSP430 header labels.

If `Open With Options` predicts ARM/Thumb, close the view and reopen it with
the exact MSP430F5438 view type. The generic firmware loader is not the mapped
MSP430F5438 loader.

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
