"""Generate a small raw F5438 image for automated and visual smoke tests."""

from __future__ import annotations

from pathlib import Path
import sys


MAIN_FLASH_START = 0x5C00
MAIN_FLASH_END = 0xFFFF
LOW_64K_SIZE = 0x10000
RESET_VECTOR = 0xFFFE
RESET_HANDLER = 0x5C00
TLV_DESCRIPTOR_ADDRESS = 0x1A00
TLV_DESCRIPTOR_SIZE = 0x100
TLV_STORED_CRC = 0xC3CA
SPARSE_FUNCTION_ADDRESS = 0x6000
PACKED_ISR_ADDRESS = 0x6100
INDIRECT_CALL_WRAPPER_ADDRESS = 0x6D00
INDIRECT_CALL_TARGET_ADDRESS = 0x7DE0
INDIRECT_CALL_POINTER_ADDRESS = 0xE000
STRING_CALL_ARGUMENT_ADDRESS = 0x6A00
STRING_CALLER_ADDRESS = 0x6E00
STRING_CALL_TARGET_ADDRESS = 0x6E40
ERASED_GAP_ADDRESS = 0x6050
SHORT_JUNK_STRING_ADDRESS = 0x6800
EXACT_MIN_STRING_ADDRESS = 0x6820
LONG_STRING_ADDRESS = 0x6840

# The short printable run resembles the accidental strings Binary Ninja finds
# in instruction bytes at its default four-byte threshold. The other two cover
# the firmware-specific minimum and an unambiguously useful diagnostic string.
SHORT_JUNK_STRING = b"BDI6@\x00"
EXACT_MIN_STRING = b"MSP430X!\x00"
LONG_STRING = b"cmd_enter_bootloader: request/response descriptor 11\x00"
STRING_CALL_ARGUMENT = b"module=startup state=%u result=%u\x00"

# call #0x7de0; call #0x6d00; call #0x6e00; ret. Direct references make the
# integration helpers deterministic analysis roots.
RESET_FUNCTION = bytes.fromhex(
    "b0 12 e0 7d b0 12 00 6d b0 12 00 6e 30 41"
)

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

# A reduced version of the real R12 string-call failure. Binary Ninja infers
# the target's callee-save PUSH/POP pairs as R4-R6 parameters and otherwise
# drops the proven R12 string assignment from HLIL.
STRING_CALLER = bytes.fromhex(
    "04 12 05 12 06 12 "
    "3c 40 00 6a "
    "b0 12 40 6e "
    "36 41 35 41 34 41 30 41"
)
STRING_CALL_TARGET = bytes.fromhex(
    "04 12 05 12 06 12 36 41 35 41 34 41 30 41"
)

# Synthetic MSP430F5438A values arranged like the datasheet's descriptor table.
# The CRC word at 0x1a02 is little-endian CRC-16/CCITT-FALSE over the inclusive
# range 0x1a04..0x1aff.  Keeping the literal checksum here (rather than deriving
# it with the implementation under test) makes this an independent test vector.
_TLV_PERIPHERAL_DESCRIPTOR = bytes.fromhex(
    "08 8a 0c 86 0e 30 2e 98 00 21 "
    "00 23 00 0f 00 05 00 fc 00 1f 10 41 02 30 02 38 01 3c 00 3d "
    "00 44 00 40 01 48 02 42 03 a0 05 51 02 52 02 53 02 54 02 55 "
    "02 56 08 5f 02 62 04 61 04 67 0e 68 02 85 04 47 0c 90 04 90 "
    "04 90 04 90 08 d1 "
    "64 65 40 90 91 d0 60 61 94 95 46 62 63 50 92 93 96 97 51 68 00"
)
assert len(_TLV_PERIPHERAL_DESCRIPTOR) == 0x61

_tlv_descriptor = bytearray(b"\xff" * TLV_DESCRIPTOR_SIZE)
_tlv_descriptor[0x00:0x08] = bytes.fromhex("06 06 ca c3 05 80 12 34")
_tlv_descriptor[0x08:0x14] = bytes.fromhex(
    "08 0a 11 22 33 44 34 12 78 56 01 00"
)
_tlv_descriptor[0x14:0x26] = bytes.fromhex(
    "11 10 ff 7f f0 ff 00 01 00 02 00 03 00 04 00 05 00 06"
)
_tlv_descriptor[0x26:0x2E] = bytes.fromhex("12 06 11 11 22 22 33 33")
_tlv_descriptor[0x2E:0x30] = bytes((0x02, len(_TLV_PERIPHERAL_DESCRIPTOR)))
_tlv_descriptor[0x30:0x91] = _TLV_PERIPHERAL_DESCRIPTOR
_tlv_descriptor[0x91] = 0xFF
TLV_DESCRIPTOR = bytes(_tlv_descriptor)
del _tlv_descriptor


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
    place(SHORT_JUNK_STRING_ADDRESS, SHORT_JUNK_STRING)
    place(EXACT_MIN_STRING_ADDRESS, EXACT_MIN_STRING)
    place(LONG_STRING_ADDRESS, LONG_STRING)
    place(STRING_CALL_ARGUMENT_ADDRESS, STRING_CALL_ARGUMENT)
    place(INDIRECT_CALL_WRAPPER_ADDRESS, INDIRECT_CALL_WRAPPER)
    place(INDIRECT_CALL_TARGET_ADDRESS, INDIRECT_CALL_TARGET)
    place(STRING_CALLER_ADDRESS, STRING_CALLER)
    place(STRING_CALL_TARGET_ADDRESS, STRING_CALL_TARGET)
    place(
        INDIRECT_CALL_POINTER_ADDRESS,
        INDIRECT_CALL_TARGET_ADDRESS.to_bytes(2, "little"),
    )
    place(RESET_VECTOR, RESET_HANDLER.to_bytes(2, "little"))
    return bytes(image)


def build_base_zero_low64k_firmware() -> bytes:
    """Return a base-zero lower-64-KiB fixture with TLV and main flash."""

    image = bytearray(b"\xff" * LOW_64K_SIZE)
    image[TLV_DESCRIPTOR_ADDRESS:TLV_DESCRIPTOR_ADDRESS + TLV_DESCRIPTOR_SIZE] = (
        TLV_DESCRIPTOR
    )
    image[MAIN_FLASH_START:MAIN_FLASH_END + 1] = build_sparse_raw_firmware()
    return bytes(image)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    low64k_image = bool(args and args[0] == "--low64k")
    if low64k_image:
        args = args[1:]
    default_name = (
        "build/base-zero-low64k-tlv.bin"
        if low64k_image
        else "build/sparse-code-islands.bin"
    )
    output = Path(args[0] if args else default_name)
    firmware = (
        build_base_zero_low64k_firmware()
        if low64k_image
        else build_sparse_raw_firmware()
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(firmware)
    print(f"Wrote {len(firmware):#x} bytes to {output}")
    print("Open with: MSP430F5438 Raw Firmware (MSP430X)")
    if low64k_image:
        print(
            f"Expected TLV descriptors: {TLV_DESCRIPTOR_ADDRESS:#x} "
            f"(stored CRC16 {TLV_STORED_CRC:#06x})"
        )
    print(f"Expected reset function: {RESET_HANDLER:#x}")
    print(f"Expected recovered sparse function: {SPARSE_FUNCTION_ADDRESS:#x}")
    packed_starts = ", ".join(f"{addr:#x}" for addr in PACKED_ISR_STARTS)
    print(f"Expected packed ISR functions: {packed_starts}")
    print(f"Expected C initializer data (not code): {CINIT_TABLE_ADDRESS:#x}")
    print(f"Expected returning indirect-call wrapper: {INDIRECT_CALL_WRAPPER_ADDRESS:#x}")
    print(
        f"Expected R12 string call in Pseudo C: {STRING_CALLER_ADDRESS:#x} "
        f"-> {STRING_CALL_TARGET_ADDRESS:#x}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
