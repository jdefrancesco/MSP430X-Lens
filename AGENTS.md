# MSP430X Lens Contributor Guide

## Mission

MSP430X Lens makes MSP430X firmware practical to analyze in Binary Ninja,
especially when the only available artifact is a raw flash dump. Changes
should improve analysis without hiding uncertainty or inventing code where the
firmware more likely contains data.

The current device focus is MSP430F5438/MSP430F5438A. Keep the architecture
usable for other MSP430X binaries and move device-specific behavior toward
explicit profiles instead of adding more global assumptions.

## Engineering priorities

1. Preserve MSP430X semantics. Registers and addresses are 20-bit where the
   architecture requires them; do not silently flatten CPUX behavior to plain
   16-bit MSP430 behavior.
2. Treat raw firmware as a first-class workflow. ELF support matters, but raw
   images must receive their map, vectors, labels, and analysis seeds before
   Binary Ninja's first analysis pass.
3. Prefer conservative inference. A missed function can be seeded later; a
   lookup table misclassified as code pollutes control flow and decompilation.
4. Keep uncertainty visible. Unknown CPUX forms should remain explicit
   fallbacks until their encoding and side effects are understood.
5. Make behavior reproducible with exact instruction bytes and automated
   loader tests.

## Repository map

- `msp430x_arch.py`: instruction decoding, disassembly tokens, branch metadata,
  calling convention behavior, and LLIL lifting.
- `msp430_tlv.py`: pure factory device-descriptor parsing, CRC16 validation,
  and peripheral-discovery decoding.
- `msp430f5438_memory_map.py`: device profiles, mapped raw BinaryView, vector
  seeding, header symbols, code/data heuristics, diagnostics, and UI commands.
- `inc/`: bundled TI-derived device and peripheral headers. Preserve their
  licensing and provenance.
- `tests/fixture_firmware.py`: deterministic raw firmware used by automated and
  UI smoke tests.
- `tests/`: unit and Binary Ninja factory-path integration tests.
- `docs/TESTING.md`: development installation and test procedures.
- `plugin.json`: Binary Ninja plugin metadata and the authoritative release
  version.

## Required workflow

Before changing analysis behavior:

1. Identify whether the issue belongs to mapping, discovery, decoding, control
   flow, LLIL, or type recovery. Do not compensate for a decoder defect with a
   broader code-discovery heuristic.
2. Capture the relevant raw bytes and expected instruction behavior.
3. Check both mapped-raw and ELF/custom-segment implications when applicable.

After changing code:

```sh
make test
```

For UI-sensitive changes:

```sh
make dev-link fixture
```

Restart Binary Ninja after Python plugin changes, open the fixture with
`MSP430F5438 Raw Firmware (MSP430X)`, and follow `docs/TESTING.md`.

## Architecture changes

- Keep instruction decoding, rendered text, `InstructionInfo` branches, and
  LLIL semantics synchronized.
- Add regression cases using exact little-endian instruction bytes.
- Model calls, returns, direct branches, indirect branches, and stack effects
  explicitly so function discovery does not depend on linear sweep.
- Preserve CPUX extension-word, repeat-prefix, address-word, and 20-bit
  wraparound behavior.
- Do not replace an unknown instruction with guessed semantics merely to remove
  `cpux` or `unimplemented` output. Use the fallback report to collect evidence.

## Loader and analysis changes

- Apply mappings and executable/data permissions before initial analysis.
- Keep erased flash, strings, initializer records, and lookup/jump tables out
  of code unless there is strong contrary evidence.
- Function-seeding heuristics must be bounded, deterministic, and covered by a
  negative test that demonstrates likely data is rejected.
- Avoid hard-coded F5438 address limits in architecture-wide logic. Put new
  device layouts in `DeviceSpec` profiles and use the selected profile.
- Ensure re-running analysis is idempotent: do not duplicate symbols, data
  variables, comments, functions, or indirect branch targets.

## Tests and fixtures

- `make test` must pass through Binary Ninja's bundled Python.
- Integration tests should create views through the registered
  `BinaryViewType`, matching the UI loader path.
- Keep generated firmware and Binary Ninja databases out of Git. Do not ignore
  every `*.bin`; intentional firmware fixtures may belong in the repository.
- When fixing a real firmware failure, reduce it to the smallest byte sequence
  that still reproduces the issue and add it to the appropriate test.

## Dependencies and compatibility

- Keep the plugin dependency-free unless a dependency is clearly justified.
- Maintain the minimum Binary Ninja build declared in `plugin.json` or update
  the manifest and documentation together.
- Treat Binary Ninja API differences defensively when they affect supported
  releases, but do not swallow analysis errors that a regression test can
  expose.

## Releases

- Bump the semantic version in `plugin.json`; it is the authoritative version.
- Use a patch bump for compatible fixes and a minor bump for new analysis or
  loader capabilities while the project remains pre-1.0.
- Update `README.md` and `docs/TESTING.md` whenever the user workflow changes.
- Before tagging a release, run `make test` and complete the UI smoke test.

## Definition of done

A change is complete when its behavior is technically justified, its raw bytes
or loader condition are represented in tests, automated tests pass, the UI path
is checked when relevant, and the documentation accurately describes the
result and remaining limitations.
