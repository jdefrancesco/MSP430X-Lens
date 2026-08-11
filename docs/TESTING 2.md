# Testing

## Headless Tests

Run the MSP430X architecture and MSP430F5438 mapped-view tests with Binary
Ninja's headless Python:

```sh
./scripts/run_headless_bn_tests.sh
```

The runner uses `BN_PYTHON` when set, then searches for `bnpython3` on `PATH`,
then falls back to the standard macOS app bundle path:

```sh
BN_PYTHON="/Applications/Binary Ninja.app/Contents/MacOS/bnpython3" ./scripts/run_headless_bn_tests.sh
```

It sets `BN_DISABLE_USER_PLUGINS=1` by default so unrelated installed plugins do
not affect the test process. Set `BN_DISABLE_USER_PLUGINS=0` if you specifically
want to test with your normal user plugin set loaded.

The runner invokes the test modules explicitly instead of using unittest
discovery. This avoids a Binary Ninja headless teardown crash seen when
discovering tests in this repository.

The tests intentionally use Binary Ninja's real `LowLevelILFunction` so invalid
LLIL builder calls fail under the same API used by the plugin.

Known Binary Ninja quirk: direct, focused `bnpython3 -m unittest ...` commands
can occasionally panic during Binary Ninja startup with a `reqwest` /
`system-configuration` error before tests run. The standard
`./scripts/run_headless_bn_tests.sh` path has been more reliable. Re-run the
standard runner before treating that startup panic as a plugin regression.

## UI Smoke Test

Run this after packaging, install, BinaryView registration, or architecture
registration changes:

1. `./scripts/install_binaryninja_plugin.sh`
2. Restart Binary Ninja.
3. Open firmware as `MSP430F5438 Raw Firmware (MSP430X)`.
4. Confirm the view is not generic `Raw` or generic `Firmware`.
5. Confirm the view architecture/platform is `msp430x`.
6. Confirm `Tools -> MSP430F5438` commands are present.
7. Run `Tools -> MSP430F5438 -> Diagnose active view`.
8. Spot-check reset/vector labels, MSP430 header labels, and that analysis starts.

If `Open With Options` predicts ARM/Thumb, close that view and reopen with the
exact MSP430F5438 view type. The generic firmware loader is not the mapped
MSP430F5438 loader.

## Larger Firmware Readiness

Before using the plugin in the lab on a larger MSP430X target, smoke-test at
least one image that has real backed contents above `0x10000`. Confirm high-bank
flash sections map as executable/read-only code when backed by bytes, while
unbacked/erased tails stay non-executable data.

Generate a deterministic high-bank fixture with:

```sh
python3 scripts/make_high_bank_fixture.py
```

Open `samples/msp430f5438_high_bank_fixture.bin` as
`MSP430F5438 Raw Firmware (MSP430X)`. It is a full-size test image with a reset
vector, low-flash startup code, and callable routines plus strings in flash
banks above `0x10000`.
