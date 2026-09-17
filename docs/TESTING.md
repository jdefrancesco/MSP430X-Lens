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
CRC-16/CCITT-FALSE validation, and annotation idempotence. A third mapped-raw
fixture backs flash above `0xffff` and verifies 20-bit `CALLA` discovery while
recovering one referenced address-word target and rejecting unreferenced
high-bank bytes that merely resemble a function. Exact bytes reduced from a
larger F5438A image additionally verify that three nearby erased-boundary
`RETA` routines are recovered as a cluster, while a standalone `RETA`, legacy
`RET`, and accidental calibration-table `RETI` remain unseeded. A packed
command-name/descriptor pair from the same image verifies that touching
NUL-terminated strings remain separate data variables. Exact instruction-byte
tests also verify conservative structure recovery from parameter-relative
byte, word, and address-width accesses, register-alias tracking, clean
`load20`/`store20` field rendering, idempotence, and rejection of conflicting,
array-shaped, user-typed, or already-specific pointer candidates.

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
`build/base-zero-low64k-tlv.bin`, `build/high-bank-raw.bin`, and
`build/msp430x-lens-fixture.elf`. Open the three raw images using:

```text
MSP430F5438 Raw Firmware (MSP430X)
```

Verify the loader and registration:

1. Confirm the selected view is `MSP430F5438`, not generic `Raw` or
   `Firmware`.
2. Confirm the architecture/platform is `msp430x`.
3. Confirm the `Tools -> MSP430F5438` commands are present.
4. Run `Tools -> MSP430F5438 -> Diagnose active view`.
5. Let initial analysis and the automatic `Recovering MSP430X high-bank
   functions, indirect targets, R12 string call sites, and structures`
   background task finish. Do not run a manual analysis command for this smoke
   test.
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
15. Confirm non-erased flash section names use `.backed_N`, not `.code_N`;
    this name intentionally covers both instructions and file-backed data.
16. Open Pseudo C at `0x6f00` and confirm the unused hardware read remains
    visible as `mmio_read16(&DMACTL0)`. Confirm `DMACTL0` at `0x500` is a
    volatile two-byte data variable; the `_L`/`_H` aliases should remain
    navigable symbols without overlapping data variables.
17. Open Pseudo C at `0x6f40` and confirm its first parameter is
    `struct msp430x_auto_struct_06f40_r12*`. The body must contain
    `load20(&arg1->field_08)` and `store20(&arg1->field_0c, ...)`, with no
    exposed `0xfffff` masks. Running `Recover inferred structures` again must
    not create a duplicate type.
18. Spot-check reset/vector and other MSP430 header labels.

For a real raw slice whose first byte does not represent address `0` or
`0x5c00`, choose the same mapped view in `Open With Options` and enter the
exact first address in the editable `Image Base` field. Select
`MSP430F5438A` in `MSP430 Device Profile` when that revision is known but its
TLV block is absent. Both choices must be reflected before initial analysis;
an ordinary reanalysis cannot repair bytes that were mapped at the wrong base.

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

For `build/high-bank-raw.bin`, also verify:

1. The direct `CALLA` in the reset path resolves to a function at `0x11000`,
   not a truncated low-64-KiB address.
2. The erased backed range near `0x11100` and the unbacked range at `0x12000`
   are non-executable.
3. The string at `0x11200` and lookup table at `0x11300` are data, not
   functions.
4. The unreferenced bytes at `0x11400` look like a valid
   `push/nop/pop/ret` routine but remain data. This confirms mapped-raw linear
   sweep is disabled and an isolated high-bank shape requires reference,
   symbol, or analyst evidence.
5. The wrapper at `0x7000` contains `CALLA &0x11500` followed by `RET`. The
   four-byte address-word slot at `0x11500` resolves to a function at `0x11600`,
   and the call has that full 20-bit indirect target without losing its
   returning fallthrough.

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

For the three `.bin` fixtures only: if `Open With Options` predicts ARM/Thumb,
close the view and reopen it with the exact MSP430F5438 raw view type. Do not
open the `.elf` fixture with the raw view; it must remain on the normal `ELF`
loader path.

Automatic strings are discovered only during Binary Ninja's first analysis
pass. If short junk strings remain after a plugin update, close the old view and
reopen the original firmware; `Re-run MSP430X analysis` cannot remove entries
already recorded by the core string scanner. Both mapped-raw and ELF executable
views apply the inherited eight-character minimum automatically.

Likewise, reopen the original firmware after updating from a release that
coalesced a packed string pool into one large character array. On a fresh view,
adjacent command names and descriptions must each render as their own string
data variable even when one starts immediately after the preceding NUL byte.

For a direct call preceded by a constant R12 string load in a newly opened
mapped-raw or prepared ELF view, confirm the log reports automatic R12 string
recovery and that the string appears as the first argument in Pseudo C without
selecting `Re-run MSP430X analysis`. Recovery is
intentionally skipped when the target already has a user type, an R12
parameter, a more specific inferred prototype, or any existing call-site
override. Zero-parameter auto-inferred callees remain eligible; their no-return
behavior is preserved. A string containing `%` conversions should name the
local parameter `format`, but must not infer ellipsis or extra arguments unless
the call-site instructions prove those arguments. The recovered fact is stored
as a durable user override on that one call site because Binary Ninja can
remove an automatic adjustment during later analysis. Recovery runs as a
background task, and the log must not
contain `UI threads are not permitted to wait for analysis completion`. When it
finishes, an already open Pseudo C pane should repaint with the recovered string
argument; navigating away and back must not be required. After Binary Ninja
becomes idle, confirm the argument does not disappear again. The manual re-run
command remains the fallback for older already-open views and for analysis
changes made after the automatic pass. Reopening an executable MSP430X ELF
BNDB should schedule the same recovery even though Binary Ninja does not save
the plugin's auto preparation marker in databases.

At fixture function `0x6e40`, confirm the automatic type has no R4-R6
parameters: those registers are only saved by the opening `PUSH` instructions
and restored before `RET`. The call at `0x6e0a` should consequently show only
its recovered string argument, with no trailing callee-save register argument.
An auto parameter must remain when its entry value has any semantic SSA use,
and user-authored function types must never be changed by this cleanup.

The raw fixtures include this exact structure case at `0x6f40`. More generally,
firmware with two or more non-overlapping fixed-offset accesses from one
function parameter should receive a stable `msp430x_auto_struct_*` pointer
type and named `field_XX` members. Address-width `.A` accesses must remain
visible as `load20(&arg1->field_XX)` or `store20(&arg1->field_XX, ...)`; Pseudo
C must not gain `0xfffff` masks. Run `Tools -> MSP430F5438 -> Recover inferred
structures` (or the F5438A equivalent) a second time and confirm that it finds
no new candidates or duplicate types. Existing user types, specific inferred
pointer types, conflicting field widths, overlaps, and regular same-width
array strides must remain unchanged.

When external symbols identify MSP430 EABI helpers, use
`Tools -> MSP430F5438 -> Import raw function symbols` for a linker map or `nm`
output. For one-off manual entries, use
`Tools -> MSP430F5438 -> Paste raw function symbols` with address/name lines
such as `0x8c20 __MSP430_mpyi`. Use
`Tools -> MSP430F5438 -> Report MSP430 ABI helper names` to print the accepted
PDF aliases and canonical names. Then run
`Tools -> MSP430F5438 -> Re-run MSP430X analysis` and confirm aliases such as
`__MSP430_mpyi` are normalized to `__mspabi_mpyi`, ordinary helper prototypes
are present only when the function has no user type, and special two-64-bit
helpers such as `__mspabi_mpyll` receive an R8::R11/R12::R15 comment instead of
an ordinary forced prototype. Also confirm generic names such as
`0x8c20 journal_append` rename only default-named functions and do not replace
an existing meaningful function name.

For stripped raw binaries without helper symbols, run
`Tools -> MSP430F5438 -> Report raw helper candidates`. Confirm the output
lists only repeated direct-call targets that still have default names, includes
representative caller call-site addresses, and prints editable
`0xADDR __MSP430_<helper_name>` template lines for manual confirmation before
pasting helper or generic function names with `Paste raw function symbols`.

For an already-open mapped or ELF file, run
`Tools -> MSP430F5438 -> Re-run MSP430X analysis` and check the log for:

```text
Seeded N unreferenced MSP430X sparse code-island function(s).
Seeded N clustered high-confidence MSP430X high-bank function(s).
```

The second line appears only when a manual re-run finds a new qualifying
cluster. On a fresh mapped view, the loader instead reports
`clustered_high_bank_functions=N` because it performs that recovery before
Binary Ninja's first analysis pass.

On a fresh `build/high-bank-raw.bin` view, wait for automatic post-analysis
recovery, then run `Tools -> MSP430F5438 -> Report unreferenced function
candidates` and wait for its background task. Confirm the log says the report
is read-only, lists `[strong] 0x011700` with `exit=reta` and a `0x011700
<confirmed_function_name>` template, and does not list an address inside the
string at `0x11200` or lookup table at `0x11300`. The deliberately code-shaped
bytes at `0x11400` may appear only as `[ambiguous]`; do not import them. Confirm
`0x11700` remains absent from the Functions list after the report. To test the
separate confirmation path, replace the placeholder for `0x11700` with a
chosen name and submit only that row through `Paste raw function symbols`;
only then should Binary Ninja create the function.

## Larger-firmware readiness

Before relying on changes to device mapping for a larger MSP430X target, test
at least one image with real backed contents above `0x10000`. Confirm that:

- backed high-bank flash retains its executable, read-only mapping without
  treating every backed section as proven code;
- unbacked or erased high-bank tails remain non-executable data;
- direct calls and recovered functions use their full 20-bit addresses; and
- strings or lookup tables in high banks are not seeded as functions;
- three-or-more nearby erased-boundary `RETA` routines are recovered without
  enabling linear sweep; and
- isolated `RET`/`RETI` shapes inside calibration or packed-resource data are
  not promoted.

The bundled `build/high-bank-raw.bin` fixture automates these checks through
`0x117ff`. Continue to repeat them on representative production firmware,
especially when a device stores compressed, encrypted, or lookup data in an
otherwise executable flash bank.
