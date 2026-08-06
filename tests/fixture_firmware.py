"""Generate a small raw F5438 image for automated and visual smoke tests."""

from __future__ import annotations

from pathlib import Path
import sys


MAIN_FLASH_START = 0x5C00
MAIN_FLASH_END = 0xFFFF
RESET_VECTOR = 0xFFFE
RESET_HANDLER = 0x5C00
SPARSE_FUNCTION_ADDRESS = 0x6000

# nop; ret
RESET_FUNCTION = bytes.fromhex("03 43 30 41")

# push r4; mov r14,r4; mov r12,0(r13); add #2,r13; sub #1,r4;
# jne $-8; pop r4; ret -- representative of the missed code in the screenshot.
SPARSE_FUNCTION = bytes.fromhex(
    "04 12 04 4e 8d 4c 00 00 3d 50 02 00 14 83 fa 23 34 41 30 41"
)


def build_sparse_raw_firmware() -> bytes:
    """Return a main-flash-only image with one unreferenced code island."""

    image = bytearray(b"\xff" * (MAIN_FLASH_END - MAIN_FLASH_START + 1))

    def place(address: int, data: bytes) -> None:
        offset = address - MAIN_FLASH_START
        image[offset:offset + len(data)] = data

    place(RESET_HANDLER, RESET_FUNCTION)
    place(SPARSE_FUNCTION_ADDRESS, SPARSE_FUNCTION)
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
