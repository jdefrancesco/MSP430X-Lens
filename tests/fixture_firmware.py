"""Generate a small raw F5438 image for automated and visual smoke tests."""

from __future__ import annotations

from pathlib import Path
import sys


MAIN_FLASH_START = 0x5C00
MAIN_FLASH_END = 0xFFFF
RESET_VECTOR = 0xFFFE
RESET_HANDLER = 0x5C00
SPARSE_FUNCTION_ADDRESS = 0x6000
PACKED_ISR_ADDRESS = 0x6100
INDIRECT_CALL_WRAPPER_ADDRESS = 0x6D00
INDIRECT_CALL_TARGET_ADDRESS = 0x7DE0
INDIRECT_CALL_POINTER_ADDRESS = 0xE000
ERASED_GAP_ADDRESS = 0x6050

# call #0x7de0; call #0x6d00; ret. Direct references make both functions
# deterministic analysis roots for the integration fixture.
RESET_FUNCTION = bytes.fromhex("b0 12 e0 7d b0 12 00 6d 30 41")

# push r4; mov r14,r4; mov r12,0(r13); add #2,r13; sub #1,r4;
# jne $-8; pop r4; ret -- representative of the missed code in the screenshot.
SPARSE_FUNCTION = bytes.fromhex(
    "04 12 04 4e 8d 4c 00 00 3d 50 02 00 14 83 fa 23 34 41 30 41"
)

# Three adjacent handlers in one backed island. The middle handler is a leaf
# without a conventional prologue, so it is discoverable only as part of the
# RETI-terminated chain.
PACKED_ISR_ROUTINES = (
    bytes.fromhex("0f 14 1c 43 0f 16 00 13"),
    bytes.fromhex("1c e3 00 13"),
    bytes.fromhex("04 12 34 41 00 13"),
)
PACKED_ISR_STARTS = (
    PACKED_ISR_ADDRESS,
    PACKED_ISR_ADDRESS + len(PACKED_ISR_ROUTINES[0]),
    PACKED_ISR_ADDRESS + len(PACKED_ISR_ROUTINES[0]) + len(PACKED_ISR_ROUTINES[1]),
)
CINIT_TABLE_ADDRESS = PACKED_ISR_ADDRESS + sum(map(len, PACKED_ISR_ROUTINES))

# Four valid TI/EABI records meet the conservative table threshold. Their
# payloads deliberately look like complete RET/RETA/RETI routines, proving the
# table remains data even when it immediately follows a packed code cluster.
CINIT_TABLE = bytes.fromhex(
    "08 00 b6 3a 00 00 04 12 03 43 34 41 30 41 "
    "06 00 be 3a 00 00 0f 4c 0f 5d 10 01 "
    "0a 00 c4 3a 00 00 0f 14 92 d3 b0 01 0f 16 00 13 "
    "06 00 ce 3a 00 00 92 d3 b0 01 00 13"
)
CINIT_TABLE_END = CINIT_TABLE_ADDRESS + len(CINIT_TABLE)
CINIT_RECORD_ADDRESSES = tuple(
    CINIT_TABLE_ADDRESS + offset for offset in (0x00, 0x0E, 0x1A, 0x2A)
)
CINIT_PAYLOAD_ADDRESSES = tuple(
    CINIT_TABLE_ADDRESS + offset for offset in (0x06, 0x14, 0x20, 0x30)
)

# mov &0xe000, r11; call r11; ret. The pointer names a known returning target,
# so analysis must retain the fallthrough after the register-indirect call.
INDIRECT_CALL_WRAPPER = bytes.fromhex("1b 42 00 e0 8b 12 30 41")
INDIRECT_CALL_TARGET = bytes.fromhex("03 43 30 41")


def build_sparse_raw_firmware() -> bytes:
    """Return a main-flash image with sparse and packed code/data islands."""

    image = bytearray(b"\xff" * (MAIN_FLASH_END - MAIN_FLASH_START + 1))

    def place(address: int, data: bytes) -> None:
        offset = address - MAIN_FLASH_START
        image[offset:offset + len(data)] = data

    place(RESET_HANDLER, RESET_FUNCTION)
    place(SPARSE_FUNCTION_ADDRESS, SPARSE_FUNCTION)
    place(PACKED_ISR_ADDRESS, b"".join(PACKED_ISR_ROUTINES))
    place(CINIT_TABLE_ADDRESS, CINIT_TABLE)
    place(INDIRECT_CALL_WRAPPER_ADDRESS, INDIRECT_CALL_WRAPPER)
    place(INDIRECT_CALL_TARGET_ADDRESS, INDIRECT_CALL_TARGET)
    place(
        INDIRECT_CALL_POINTER_ADDRESS,
        INDIRECT_CALL_TARGET_ADDRESS.to_bytes(2, "little"),
    )
    place(RESET_VECTOR, RESET_HANDLER.to_bytes(2, "little"))
    return bytes(image)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    output = Path(args[0] if args else "build/sparse-code-islands.bin")
    firmware = build_sparse_raw_firmware()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(firmware)
    print(f"Wrote {len(firmware):#x} bytes to {output}")
    print("Open with: MSP430F5438 Raw Firmware (MSP430X)")
    print(f"Expected reset function: {RESET_HANDLER:#x}")
    print(f"Expected recovered sparse function: {SPARSE_FUNCTION_ADDRESS:#x}")
    packed_starts = ", ".join(f"{addr:#x}" for addr in PACKED_ISR_STARTS)
    print(f"Expected packed ISR functions: {packed_starts}")
    print(f"Expected C initializer data (not code): {CINIT_TABLE_ADDRESS:#x}")
    print(f"Expected returning indirect-call wrapper: {INDIRECT_CALL_WRAPPER_ADDRESS:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
