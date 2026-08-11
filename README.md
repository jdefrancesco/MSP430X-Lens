# MSP430X Lens

MSP430X Lens adds MSP430X firmware support to Binary Ninja, with a focus on the
MSP430F5438/MSP430F5438A MCUs. It was written with the ability to ingest raw firmware
images; however having an ELF will make analysis much easier. MSP430X Lens's
core features include:

- `MSP430X` ISA support; lifting the MSP430/MSP430X CPUX forms for better analysis (duh)..
- Ability to map raw firmware MSP430F5438/F5438A images. TI-TXT/ELF firmware is supported if available.
- Vector-table seeding, Flash/RAM/Peripheral sections, and TI header labels.
- Collapsing and simplifying the decompilation output without all the
artifacts that Ghidra generally leaves.
- Pure Python. No external dependencies used making porting and installation easier.

## Agentic Augmented

The beginning of this project (i.e lifting) was written by hand to ensure the correct
semantics were being preserved. Since the core of this plugin has been constructed;
agentic programming is utilized. Agentic code should still be read in full,
keeping technical debt to a minimum. If you would like to contribute to this plugin
please read the [CONTRIBUTION](./CONTRIBUTION.md). It contains guidance on how
agentic code should be utilized if you choose to use it.


## Install

Once the plugin is listed in the Binary Ninja Plugin Manager, install it from
`Plugins -> Manage Plugins`, then restart Binary Ninja. Architecture and
BinaryView plugins are loaded at startup.

For a manual development install, clone the repository and copy or symlink it
as a directory named `msp430xlens` under the Binary Ninja user plugin
directory:

- macOS: `~/Library/Application Support/Binary Ninja/plugins/msp430xlens`
- Linux: `~/.binaryninja/plugins/msp430xlens`
- Windows: `%APPDATA%\Binary Ninja\plugins\msp430xlens`

Restart Binary Ninja after installing. To uninstall a manual installation,
remove only the `msp430xlens` directory or symlink you created.

The plugin has no third-party Python dependencies. It requires Binary Ninja
5.3.9757 or newer.

## Quick Start

Open raw firmware with the mapped view type:

```text
MSP430F5438 Raw Firmware (MSP430X)
```

The mapped view creates segments, sections, header labels, interrupt vectors,
and entry points before Binary Ninja's first analysis pass. Avoid opening as
plain `Raw`, analyzing, and then retrofitting the map.

Best path for a raw dump:

1. Install the plugin and restart Binary Ninja.
2. Open the firmware with view type `MSP430F5438 Raw Firmware (MSP430X)`.
3. Use `Tools -> MSP430F5438 -> Diagnose active view`.
4. Use `Tools -> MSP430F5438 -> Re-run MSP430X analysis` after editing the
   lifter, importing symbols/types, or refreshing vector functions.

Commands live under:

```text
Tools -> MSP430F5438
Tools -> MSP430F5438A
```

Useful commands include:

- `Register mapped raw firmware view`
- `Apply memory map (auto base)`
- `Apply memory map (main flash @ 0x5c00)`
- `Apply memory map (full image @ 0)`
- `Diagnose active view`
- `Report CPUX fallback instructions`
- `Re-run MSP430X analysis`
- `Apply MSP430 header labels`

If you accidentally run an `Apply memory map` command on an already mapped
`MSP430F5438 Raw Firmware (MSP430X)` view, the plugin refreshes
architecture/vector analysis without rebuilding segments.

## UI Smoke Test

After installing or changing plugin registration code:

1. Restart Binary Ninja.
2. Open firmware as `MSP430F5438 Raw Firmware (MSP430X)`.
3. Confirm the view title contains `MSP430F5438 Raw Firmware (MSP430X)`.
4. Confirm the architecture/platform shown by the view is `msp430x`.
5. Confirm `Tools -> MSP430F5438` commands are present.
6. Run `Tools -> MSP430F5438 -> Diagnose active view`.
7. Spot-check that reset/vector labels and header-derived peripheral labels are present.

If the options dialog shows ARM/Thumb, close that view and reopen with the
exact MSP430F5438 view type. The generic firmware loader is not this plugin.

## Workflow Notes

If a suspicious `cpux 0x....` mnemonic appears in code, use
`Tools -> MSP430F5438 -> Report CPUX fallback instructions`. It reports only
fallback decodes that still live inside analyzed functions, which helps separate
missing lifter coverage from lookup tables or strings that merely look like
opcodes when viewed as linear bytes.

On the `MSP430F5438` tab in `Open With Options`, the read-only `Platform` load
option should show `msp430x`. If it still shows `thumb2`, restart Binary Ninja
after reinstalling the plugin so stale registrations are gone.

The interrupt vector table is forced into 64 separate two-byte `uint16_t` data
entries, with each populated target still seeded as a reset/ISR function.
Image-base autodetection scores candidate vector tables, so a 64 KiB
low-address image with vectors at file offset `0xff80` opens at base `0`, while
a main-flash slice still opens at base `0x5c00`.

Long erased flash spans (`0xff`) are marked as non-executable data when the
mapped view is created. If analysis has already produced many tiny functions in
erased flash, restart Binary Ninja and reopen the firmware as
`MSP430F5438 Raw Firmware (MSP430X)` so the split map is present before initial
analysis.

Small backed code islands between those erased spans are also seeded as
functions when they have a conservative MSP430 prologue-and-return shape. This
is done during initial mapped-raw loading and by `Re-run MSP430X analysis` for
existing mapped or ELF views, including executable segments outside the
F5438-specific flash range.

Printable, null-terminated ASCII runs in flash are defined as data during
mapped-view creation. Re-running analysis also removes stale functions that
start inside those strings or in short zero padding next to them, which prevents
string tables from decompiling into noisy carry/flag-heavy pseudocode or tiny
`bra @pc` functions.

After importing external symbols or types, such as names recovered from a
Ghidra project, use `Tools -> MSP430F5438 -> Re-run MSP430X analysis`. This
refreshes vector entry points, removes boundary data symbols that collide with
real functions, and reapplies the MSP430X calling convention used for imported
function prototypes.

MSP430 header labels are applied automatically during mapped-view creation and
analysis refresh. The parser reads headers under `inc/`, plus any paths listed
in `MSP430_HEADER_PATHS` separated by your shell path separator. It recognizes
TI-style `sfrb`/`sfrw` register definitions, module base labels, vector labels,
TLV labels, and simple aliases such as board/HAL names that point at a known
register label.

## Test

Run all Binary Ninja-backed unit and loader-integration tests:

```sh
make test
```

Generate a deterministic raw image for visual testing with `make fixture`.
More details, including the guarded `make dev-link` setup, are in
[docs/TESTING.md](docs/TESTING.md).

## Known Limitations

The automatic raw-firmware memory map targets MSP430F5438/F5438A devices. The
`msp430x` architecture can still be selected for other MSP430X firmware, but
device-specific sections and peripheral symbols must be supplied separately.

The implementation status and deliberately conservative CPUX fallbacks are
tracked in [docs/CPUX_SIDE_EFFECT_AUDIT.md](docs/CPUX_SIDE_EFFECT_AUDIT.md).

## License

The plugin is released under the [MIT License](LICENSE). Bundled Texas
Instruments headers retain their BSD 3-Clause terms; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
