# Testing MSP430X Lens

## Automated tests

Run the complete suite from the repository root:

```sh
make test
```

The runner finds `bnpython3` on `PATH` or in the standard macOS application
location. For another installation, provide its launcher explicitly:

```sh
BNPYTHON=/path/to/bnpython3 make test
```

The suite includes a real Binary Ninja integration test. It constructs a raw
MSP430F5438 main-flash image, loads `MSP430F5438BinaryView`, waits for analysis,
and checks that the reset handler and an unreferenced function between erased
flash spans were both created.

## UI smoke test

Link this checkout into Binary Ninja's user plugin directory once:

```sh
make dev-link
```

The linker refuses to replace an existing plugin or symlink. Set
`BN_USER_PLUGIN_DIR` if Binary Ninja uses a nonstandard user plugin directory.
Restart Binary Ninja after creating the link or changing plugin code.

Generate the deterministic raw test image:

```sh
make fixture
```

Then open `build/sparse-code-islands.bin` using:

```text
MSP430F5438 Raw Firmware (MSP430X)
```

Verify the following:

- `0x5c00` is the reset-handler function.
- `0x6000` is automatically recovered as a function even though nothing
  references it.
- The long `0xff` range between them remains non-executable data.

For an already-open mapped or ELF file, run
`Tools -> MSP430F5438 -> Re-run MSP430X analysis` and check the log for:

```text
Seeded N unreferenced MSP430X sparse code-island function(s).
```
