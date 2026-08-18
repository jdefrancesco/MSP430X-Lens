"""Generate a small raw F5438 image for automated and visual smoke tests."""

from __future__ import annotations

from pathlib import Path
import struct
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
MMIO_READ_FUNCTION_ADDRESS = 0x6F00
ERASED_GAP_ADDRESS = 0x6050
SHORT_JUNK_STRING_ADDRESS = 0x6800
EXACT_MIN_STRING_ADDRESS = 0x6820
LONG_STRING_ADDRESS = 0x6840
ELF_STRING_REGION_END = 0x6880
ELF_MACHINE_MSP430 = 105
ELF_FLAGS_MSP430X54 = 54

# The short printable run resembles the accidental strings Binary Ninja finds
# in instruction bytes at its default four-byte threshold. The other two cover
# the firmware-specific minimum and an unambiguously useful diagnostic string.
SHORT_JUNK_STRING = b"BDI6@\x00"
EXACT_MIN_STRING = b"MSP430X!\x00"
LONG_STRING = b"cmd_enter_bootloader: request/response descriptor 11\x00"
STRING_CALL_ARGUMENT = b"module=startup state=%u result=%u\x00"

# A small, ordinary leaf function for the ELF entry point.  Keeping this
# independent of the raw fixture's call graph makes the ELF factory-path test
# exercise loader setup without creating references to absent sections.
ELF_RESET_FUNCTION = bytes.fromhex("03 43 30 41")

# call #0x7de0; call #0x6d00; call #0x6e00; call #0x6f00; ret. Direct
# references make the integration helpers deterministic analysis roots.
RESET_FUNCTION = bytes.fromhex(
    "b0 12 e0 7d b0 12 00 6d b0 12 00 6e b0 12 00 6f 30 41"
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

# push r12; mov &DMACTL0,r12; pop r12; ret.  The restored r12 makes the MMIO
# read's result deliberately unused.  A normal load therefore disappears
# during MLIL dead-code elimination, while a side-effecting MMIO read must
# remain visible in Pseudo C as a reference to the header-derived DMACTL0 name.
MMIO_READ_FUNCTION = bytes.fromhex(
    "0c 12 1c 42 00 05 3c 41 30 41"
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
    place(MMIO_READ_FUNCTION_ADDRESS, MMIO_READ_FUNCTION)
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


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def build_msp430_elf_firmware() -> bytes:
    """Return a minimal linked ELF32/MSP430 image for factory-path tests.

    The fixture is assembled directly so the test suite does not depend on an
    MSP430 compiler or linker.  It contains only standard ELF headers, four
    loadable device sections, and a conventional ``_start`` function symbol.
    """

    rodata = bytearray(
        b"\xff" * (ELF_STRING_REGION_END - SHORT_JUNK_STRING_ADDRESS)
    )

    def place_rodata(address: int, data: bytes) -> None:
        offset = address - SHORT_JUNK_STRING_ADDRESS
        rodata[offset:offset + len(data)] = data

    place_rodata(SHORT_JUNK_STRING_ADDRESS, SHORT_JUNK_STRING)
    place_rodata(EXACT_MIN_STRING_ADDRESS, EXACT_MIN_STRING)
    place_rodata(LONG_STRING_ADDRESS, LONG_STRING)

    vectors = bytearray(b"\xff" * (MAIN_FLASH_END - 0xFF80 + 1))
    vectors[RESET_VECTOR - 0xFF80:RESET_VECTOR - 0xFF80 + 2] = (
        RESET_HANDLER.to_bytes(2, "little")
    )

    # name, virtual address, contents, program-header flags, section flags
    # ELF PF_R/PF_X are 4/1 and SHF_ALLOC/SHF_EXECINSTR are 2/4.
    loadable_sections = (
        (".tlv", TLV_DESCRIPTOR_ADDRESS, TLV_DESCRIPTOR, 4, 2),
        (".text", RESET_HANDLER, ELF_RESET_FUNCTION, 5, 6),
        (".rodata", SHORT_JUNK_STRING_ADDRESS, bytes(rodata), 4, 2),
        (".vectors", 0xFF80, bytes(vectors), 4, 2),
    )

    elf_header_size = 52
    program_header_size = 32
    section_header_size = 40
    program_header_count = len(loadable_sections)
    cursor = _align_up(
        elf_header_size + program_header_size * program_header_count,
        16,
    )

    offsets: dict[str, int] = {}
    contents: dict[str, bytes] = {}
    for name, _address, data, _program_flags, _section_flags in loadable_sections:
        offsets[name] = cursor
        contents[name] = data
        cursor = _align_up(cursor + len(data), 4)

    symbol_names = ("_start", "__msp430f5438_flash_start")
    symbol_name_offsets = {}
    string_table_builder = bytearray(b"\x00")
    for name in symbol_names:
        symbol_name_offsets[name] = len(string_table_builder)
        string_table_builder.extend(name.encode("ascii") + b"\x00")
    string_table = bytes(string_table_builder)
    offsets[".strtab"] = cursor
    contents[".strtab"] = string_table
    cursor = _align_up(cursor + len(string_table), 4)

    # Elf32_Sym: null, global STT_FUNC `_start`, then a loader-owned boundary
    # STT_OBJECT. The latter proves pre-analysis preparation never removes an
    # existing ELF symbol merely because a function begins at the same address.
    symbol_table = (
        bytes(16)
        + struct.pack(
            "<IIIBBH",
            symbol_name_offsets["_start"],
            RESET_HANDLER,
            len(ELF_RESET_FUNCTION),
            0x12,
            0,
            2,
        )
        + struct.pack(
            "<IIIBBH",
            symbol_name_offsets["__msp430f5438_flash_start"],
            RESET_HANDLER,
            0,
            0x11,
            0,
            2,
        )
    )
    offsets[".symtab"] = cursor
    contents[".symtab"] = symbol_table
    cursor = _align_up(cursor + len(symbol_table), 4)

    section_names = (
        "",
        ".tlv",
        ".text",
        ".rodata",
        ".vectors",
        ".symtab",
        ".strtab",
        ".shstrtab",
    )
    section_name_offsets = {"": 0}
    section_name_table = bytearray(b"\x00")
    for name in section_names[1:]:
        section_name_offsets[name] = len(section_name_table)
        section_name_table.extend(name.encode("ascii") + b"\x00")

    offsets[".shstrtab"] = cursor
    contents[".shstrtab"] = bytes(section_name_table)
    cursor = _align_up(cursor + len(section_name_table), 4)

    section_header_offset = cursor
    section_header_count = len(section_names)
    image = bytearray(
        section_header_offset + section_header_size * section_header_count
    )
    for name, data in contents.items():
        start = offsets[name]
        image[start:start + len(data)] = data

    elf_ident = b"\x7fELF" + bytes((1, 1, 1, 0xFF, 0)) + bytes(7)
    struct.pack_into(
        "<16sHHIIIIIHHHHHH",
        image,
        0,
        elf_ident,
        2,  # ET_EXEC
        ELF_MACHINE_MSP430,
        1,
        RESET_HANDLER,
        elf_header_size,
        section_header_offset,
        ELF_FLAGS_MSP430X54,
        elf_header_size,
        program_header_size,
        program_header_count,
        section_header_size,
        section_header_count,
        section_names.index(".shstrtab"),
    )

    for index, (name, address, data, program_flags, _section_flags) in enumerate(
        loadable_sections
    ):
        struct.pack_into(
            "<IIIIIIII",
            image,
            elf_header_size + program_header_size * index,
            1,  # PT_LOAD
            offsets[name],
            address,
            address,
            len(data),
            len(data),
            program_flags,
            2,
        )

    # Elf32_Shdr fields: name, type, flags, address, offset, size, link, info,
    # alignment, entry size.  Section indexes are fixed by section_names.
    section_headers = (
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (
            section_name_offsets[".tlv"],
            1,
            2,
            TLV_DESCRIPTOR_ADDRESS,
            offsets[".tlv"],
            len(TLV_DESCRIPTOR),
            0,
            0,
            1,
            0,
        ),
        (
            section_name_offsets[".text"],
            1,
            6,
            RESET_HANDLER,
            offsets[".text"],
            len(ELF_RESET_FUNCTION),
            0,
            0,
            2,
            0,
        ),
        (
            section_name_offsets[".rodata"],
            1,
            2,
            SHORT_JUNK_STRING_ADDRESS,
            offsets[".rodata"],
            len(rodata),
            0,
            0,
            1,
            0,
        ),
        (
            section_name_offsets[".vectors"],
            1,
            2,
            0xFF80,
            offsets[".vectors"],
            len(vectors),
            0,
            0,
            2,
            0,
        ),
        (
            section_name_offsets[".symtab"],
            2,
            0,
            0,
            offsets[".symtab"],
            len(symbol_table),
            section_names.index(".strtab"),
            1,
            4,
            16,
        ),
        (
            section_name_offsets[".strtab"],
            3,
            0,
            0,
            offsets[".strtab"],
            len(string_table),
            0,
            0,
            1,
            0,
        ),
        (
            section_name_offsets[".shstrtab"],
            3,
            0,
            0,
            offsets[".shstrtab"],
            len(section_name_table),
            0,
            0,
            1,
            0,
        ),
    )
    for index, fields in enumerate(section_headers):
        struct.pack_into(
            "<IIIIIIIIII",
            image,
            section_header_offset + section_header_size * index,
            *fields,
        )

    return bytes(image)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    elf_image = bool(args and args[0] == "--elf")
    if elf_image:
        args = args[1:]
    low64k_image = not elf_image and bool(args and args[0] == "--low64k")
    if low64k_image:
        args = args[1:]
    default_name = (
        "build/msp430x-lens-fixture.elf"
        if elf_image
        else (
            "build/base-zero-low64k-tlv.bin"
            if low64k_image
            else "build/sparse-code-islands.bin"
        )
    )
    output = Path(args[0] if args else default_name)
    firmware = (
        build_msp430_elf_firmware()
        if elf_image
        else (
            build_base_zero_low64k_firmware()
            if low64k_image
            else build_sparse_raw_firmware()
        )
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(firmware)
    print(f"Wrote {len(firmware):#x} bytes to {output}")
    print(
        "Open with: ELF"
        if elf_image
        else "Open with: MSP430F5438 Raw Firmware (MSP430X)"
    )
    if elf_image:
        print(
            f"Expected TLV descriptors: {TLV_DESCRIPTOR_ADDRESS:#x} "
            f"(stored CRC16 {TLV_STORED_CRC:#06x})"
        )
        print(f"Expected reset function: {RESET_HANDLER:#x}")
        print(
            "Expected accepted strings: "
            f"{EXACT_MIN_STRING_ADDRESS:#x}, {LONG_STRING_ADDRESS:#x}"
        )
        print(f"Expected rejected junk string: {SHORT_JUNK_STRING_ADDRESS:#x}")
        return 0
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
    print(
        f"Expected retained DMACTL0 read in Pseudo C: {MMIO_READ_FUNCTION_ADDRESS:#x}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
