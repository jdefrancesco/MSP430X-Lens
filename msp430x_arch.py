"""Binary Ninja architecture plugin for TI MSP430X firmware.

MSP430 devices are 16-bit RISC microcontrollers commonly used for low-power
sensing, logging, and RF applications. MSP430X extends the architecture with a
20-bit address space and CPUX instructions. An analyzer that treats those
extension words as ordinary MSP430 opcodes can produce misleading code and
control flow.

This module provides instruction decoding, disassembly tokens, branch metadata,
and LLIL lifting for the core MSP430/MSP430X forms. It also recognizes a small
set of compiler-generated instruction sequences as local pseudo-instructions;
those folds preserve the sequence's effects while keeping decompiler output
readable. The plugin remains under active development, and issue reports are
welcome.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from binaryninja import (
    Architecture,
    BranchType,
    CallingConvention,
    Endianness,
    FlagRole,
    IntrinsicInfo,
    IntrinsicInput,
    InstructionInfo,
    InstructionTextToken,
    InstructionTextTokenType,
    RegisterInfo,
    Type,
)
from binaryninja.lowlevelil import LLIL_TEMP, LowLevelILLabel


REG_NAMES = (
    "pc",
    "sp",
    "sr",
    "cg2",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)

DOUBLE_OPS = {
    0x4: "mov",
    0x5: "add",
    0x6: "addc",
    0x7: "subc",
    0x8: "sub",
    0x9: "cmp",
    0xA: "dadd",
    0xB: "bit",
    0xC: "bic",
    0xD: "bis",
    0xE: "xor",
    0xF: "and",
}

DOUBLE_OPS_X = {mnemonic: f"{mnemonic}x" for mnemonic in DOUBLE_OPS.values()}

COMPACT_SHIFT_OPS = {
    0: "rrcm",
    1: "rram",
    2: "rlam",
    3: "rrum",
}

SINGLE_OPS = {
    0: "rrc",
    1: "swpb",
    2: "rra",
    3: "sxt",
    4: "push",
    5: "call",
    6: "reti",
}

JUMP_CONDS = {
    0: ("jnz", "ne"),
    1: ("jz", "eq"),
    2: ("jnc", "cc"),
    3: ("jc", "cs"),
    4: ("jn", "mi"),
    5: ("jge", "ge"),
    6: ("jl", "lt"),
    7: ("jmp", "al"),
}

ADDR_MASK = 0xFFFFF
MAX_INSTR_LENGTH = 64
# Keep the bytes column compact in linear disassembly. Some readability pseudos
# scan longer idioms, but showing all of those bytes makes BN reserve a huge
# gutter between opcodes and mnemonics.
OPCODE_DISPLAY_LENGTH = 8
# SR is a 16-bit register, but only SR.11:0 are status/control state. On an
# interrupt, the CPU borrows bits 15:12 of the stacked SR word for PC.19:16;
# RETI must split that shared word before restoring either register.
SR_MASK = 0x0FFF
SR_FLAG_BITS = {
    "c": 0,
    "z": 1,
    "n": 2,
    "v": 8,
}
SR_TRACKED_FLAG_MASK = sum(1 << bit for bit in SR_FLAG_BITS.values())


@dataclass(slots=True)
class Operand:
    """Normalized operand shared by decoding, rendering, and LLIL lifting."""

    kind: str
    reg: Optional[int] = None
    value: int = 0
    text: str = ""
    addr: Optional[int] = None
    autoinc: bool = False


@dataclass(slots=True)
class Decoded:
    """Decoded instruction independent of Binary Ninja UI and IL objects.

    ``size`` is a Binary Ninja byte width. Address-word operations use a
    four-byte IL container and are explicitly canonicalized to 20 bits where
    architectural semantics require it.
    """

    word: int
    mnemonic: str = "???"
    fmt: str = "bad"
    length: int = 2
    size: int = 2
    src: Optional[Operand] = None
    dst: Optional[Operand] = None
    target: Optional[int] = None
    cond: Optional[str] = None
    opcode: Optional[int] = None
    bw: int = 0
    ext: Optional[int] = None
    rpt_count: Optional[int] = None
    rpt_reg: Optional[int] = None
    subc_zero_carry: bool = False
    imm: int = 0
    targets: Tuple[int, ...] = ()


DecodedBranch = Tuple[str, Optional[int]]


def u16(data: bytes, offset: int = 0) -> Optional[int]:
    """Read one little-endian instruction word, or return ``None`` if short."""

    if len(data) < offset + 2:
        return None
    return data[offset] | (data[offset + 1] << 8)


def s16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def s10(value: int) -> int:
    value &= 0x03FF
    return value - 0x0400 if value & 0x0200 else value


def s20(value: int) -> int:
    value &= ADDR_MASK
    return value - 0x100000 if value & 0x80000 else value


def mask_for_size(size: int) -> int:
    """Return the architectural value mask for a Binary Ninja IL width.

    Binary Ninja uses 32-bit containers for address-width operations, but
    MSP430X address operands are only 20 bits wide.
    """

    if size == 4:
        return ADDR_MASK
    return (1 << (size * 8)) - 1


def bits_for_size(size: int) -> int:
    return 20 if size == 4 else size * 8


def autoinc_step(reg: int, size: int) -> int:
    """Return the byte increment applied after an indirect operand read.

    A 20-bit address-word consumes two words and advances four bytes. Byte
    operands normally advance one byte, but ``@SP+`` advances two bytes so the
    stack pointer remains even-aligned; word operands also advance two bytes.
    """

    if size == 4:
        return 4
    if reg == 1:
        return 2
    return 1 if size == 1 else 2


def mk_reg(reg: int) -> Operand:
    return Operand("reg", reg=reg, text=reg_name(reg))


def mk_imm(value: int) -> Operand:
    value &= ADDR_MASK
    return Operand("imm", value=value, text=f"#{value:#x}")


def mk_mem(addr: int, absolute: bool = False) -> Operand:
    addr &= ADDR_MASK
    return Operand("mem", text=f"&{addr:#x}" if absolute else f"{addr:#x}", addr=addr)


def mk_indexed(reg: int, offset: int) -> Operand:
    offset = s16(offset)
    return Operand("indexed", reg=reg, value=offset, text=f"{offset:#x}({reg_name(reg)})")


def mk_indirect(reg: int, autoinc: bool = False) -> Operand:
    return Operand("indirect", reg=reg, text=f"@{reg_name(reg)}{'+' if autoinc else ''}", autoinc=autoinc)


def is_ext_word(word: int) -> bool:
    return (word & 0xF800) == 0x1800


def ext_src_hi(ext: Optional[int]) -> int:
    return ((ext >> 7) & 0xF) if ext is not None else 0


def ext_dst_hi(ext: Optional[int]) -> int:
    return (ext & 0xF) if ext is not None else 0


def ext_index_offset(ext: Optional[int], hi: int, low: int) -> int:
    if ext is None:
        return s16(low)
    return s20((hi << 16) | low)


def ext_zero_carry(ext: Optional[int]) -> bool:
    return bool(ext is not None and (ext & 0x0100))


def ext_repeat_count(ext: Optional[int]) -> Optional[int]:
    if ext is None or (ext & 0x0080):
        return None
    count = (ext & 0xF) + 1
    return count if count > 1 else None


def ext_repeat_reg(ext: Optional[int]) -> Optional[int]:
    if ext is None or not (ext & 0x0080):
        return None
    return ext & 0xF


def supports_repeat_prefix(src: Operand, dst: Operand) -> bool:
    """Return whether repeat lifting supports this operand pairing."""

    return dst.kind == "reg" and src.kind in (
        "imm",
        "mem",
        "indexed",
        "reg",
        "indirect",
    )


def records_double_repeat_prefix(
    src: Operand, dst: Operand, ext: Optional[int]
) -> bool:
    """Distinguish repeat bits from high-address bits in an extension word."""

    if dst.kind != "reg":
        return False
    if src.kind == "reg" or (src.kind == "indirect" and src.autoinc):
        return True
    if src.kind == "indirect":
        return True
    if src.kind in ("imm", "mem", "indexed"):
        return ext_repeat_count(ext) is not None and ext_src_hi(ext) == 0
    return False


def is_all_ones_immediate(op: Operand, size: int) -> bool:
    return op.kind == "imm" and (op.value & mask_for_size(size)) == mask_for_size(size)


def ext_size(ext: Optional[int], bw: int) -> int:
    """Decode extension-word A/L and opcode B/W bits into an IL byte width."""

    if ext is None:
        return 1 if bw else 2
    al = (ext >> 6) & 1
    if al == 0 and bw == 1:
        return 4
    if al == 1 and bw == 0:
        return 2
    if al == 1 and bw == 1:
        return 1
    return 2


def single_operand_size(ext: Optional[int], bw: int, op: int) -> int:
    if ext is not None and op in (1, 3) and bw == 0:
        return 4 if ((ext >> 6) & 1) == 0 else 2
    return ext_size(ext, bw)


def reg_name(reg: int) -> str:
    return REG_NAMES[reg & 0xF]


def needs_source_word(reg: int, as_bits: int) -> bool:
    if reg == 2 and as_bits in (1,):
        return True
    if reg == 0 and as_bits in (1, 3):
        return True
    if reg == 3:
        return False
    return as_bits == 1


def needs_dest_word(reg: int, ad: int) -> bool:
    return ad == 1


def source_operand(
    words: List[int],
    idx: int,
    instr_addr: int,
    reg: int,
    as_bits: int,
    ext: Optional[int],
) -> Tuple[Operand, int]:
    """Decode a Format I/II source operand and return its next word index."""

    hi = ext_src_hi(ext)

    if reg == 3:
        constants = {0: 0, 1: 1, 2: 2, 3: -1}
        value = constants[as_bits] & 0xFFFFFFFF
        return Operand("imm", value=value, text=f"#{constants[as_bits]}"), idx

    if reg == 2 and as_bits == 2:
        return Operand("imm", value=4, text="#4"), idx
    if reg == 2 and as_bits == 3:
        return Operand("imm", value=8, text="#8"), idx

    if as_bits == 0:
        return Operand("reg", reg=reg, text=reg_name(reg)), idx

    if as_bits == 1:
        if idx >= len(words):
            return Operand("bad", text="<?>"), idx
        low = words[idx]
        value = ((hi << 16) | low) & 0xFFFFF
        offset = ext_index_offset(ext, hi, low)
        idx += 1
        if reg == 0:
            addr = (instr_addr + 2 * idx + offset) & 0xFFFFF
            return Operand("mem", text=f"{addr:#x}", addr=addr), idx
        if reg == 2:
            return Operand("mem", text=f"&{value:#x}", addr=value), idx
        return Operand("indexed", reg=reg, value=offset, text=f"{offset:#x}({reg_name(reg)})"), idx

    if as_bits == 2:
        return Operand("indirect", reg=reg, text=f"@{reg_name(reg)}"), idx

    if as_bits == 3:
        if reg == 0:
            if idx >= len(words):
                return Operand("bad", text="#<?>"), idx
            low = words[idx]
            idx += 1
            value = ((hi << 16) | low) & 0xFFFFF
            return Operand("imm", value=value, text=f"#{value:#x}"), idx
        return Operand("indirect", reg=reg, text=f"@{reg_name(reg)}+", autoinc=True), idx

    return Operand("bad", text="<?>"), idx


def dest_operand(
    words: List[int],
    idx: int,
    instr_addr: int,
    reg: int,
    ad: int,
    ext: Optional[int],
) -> Tuple[Operand, int]:
    """Decode a Format I destination operand and return its next word index."""

    hi = ext_dst_hi(ext)
    if ad == 0:
        return Operand("reg", reg=reg, text=reg_name(reg)), idx
    if idx >= len(words):
        return Operand("bad", text="<?>"), idx
    low = words[idx]
    value = ((hi << 16) | low) & 0xFFFFF
    offset = ext_index_offset(ext, hi, low)
    idx += 1
    if reg == 0:
        addr = (instr_addr + 2 * idx + offset) & 0xFFFFF
        return Operand("mem", text=f"{addr:#x}", addr=addr), idx
    if reg == 2:
        return Operand("mem", text=f"&{value:#x}", addr=value), idx
    return Operand("indexed", reg=reg, value=offset, text=f"{offset:#x}({reg_name(reg)})"), idx


def decode_address_instruction(words: List[int], word: int) -> Optional[Decoded]:
    """Decode CPUX address, compact-shift, and multi-register forms."""

    group = (word >> 12) & 0xF
    mode = (word >> 4) & 0xF
    high = (word >> 8) & 0xF
    low = word & 0xF

    if (word & 0xFF00) in (0x1400, 0x1500, 0x1600, 0x1700):
        # PUSHM/POPM encode their width in the opcode rather than an extension
        # word: .A reserves two stack words per register and .W reserves one.
        ins = Decoded(word)
        ins.fmt = "multi"
        ins.mnemonic = {
            0x14: "pushm.a",
            0x15: "pushm.w",
            0x16: "popm.a",
            0x17: "popm.w",
        }[(word >> 8) & 0xFF]
        count = ((word >> 4) & 0xF) + 1
        reg = low
        if ins.mnemonic.startswith("popm"):
            reg = (low + count - 1) & 0xF
        ins.src = Operand("imm", value=count, text=f"#{count}")
        ins.dst = mk_reg(reg)
        ins.size = 4 if ins.mnemonic.endswith(".a") else 2
        ins.length = 2
        return ins

    if group != 0:
        return None

    ins = Decoded(word)
    ins.fmt = "double"
    ins.size = 4

    if mode == 0x4 and high == 0xE and len(words) >= 2:
        next_word = words[1]
        next_group = (next_word >> 12) & 0xF
        next_mode = (next_word >> 4) & 0xF
        next_high = (next_word >> 8) & 0xF
        next_low = next_word & 0xF
        if next_group == 0 and next_mode == 0x4 and next_high == 0xD and next_low == low:
            ins.fmt = "multi"
            ins.mnemonic = "sext20.w"
            ins.src = mk_reg(low)
            ins.dst = mk_reg(low)
            ins.length = 4
            return ins

    if mode in (0x4, 0x5):
        op = high & 0x3
        count = ((high >> 2) & 0x3) + 1
        suffix = "a" if mode == 0x4 else "w"
        ins.fmt = "multi"
        ins.mnemonic = f"{COMPACT_SHIFT_OPS[op]}.{suffix}"
        ins.src = Operand("imm", value=count, text=f"#{count}")
        ins.dst = mk_reg(low)
        ins.size = 4 if mode == 0x4 else 2
        return ins

    if mode == 0x0:
        ins.mnemonic = "mova"
        ins.src = mk_indirect(high)
        ins.dst = mk_reg(low)
        return ins
    if mode == 0x1:
        ins.mnemonic = "mova"
        ins.src = mk_indirect(high, autoinc=True)
        ins.dst = mk_reg(low)
        if high == 1 and low == 0:
            ins.mnemonic = "reta"
            ins.fmt = "single"
        return ins
    if mode == 0x2 and len(words) >= 2:
        ins.mnemonic = "mova"
        ins.src = mk_mem((high << 16) | words[1], absolute=True)
        ins.dst = mk_reg(low)
        ins.length = 4
        return ins
    if mode == 0x3 and len(words) >= 2:
        ins.mnemonic = "mova"
        ins.src = mk_indexed(high, words[1])
        ins.dst = mk_reg(low)
        ins.length = 4
        return ins
    if mode == 0x6 and len(words) >= 2:
        ins.mnemonic = "mova"
        ins.src = mk_reg(high)
        ins.dst = mk_mem((low << 16) | words[1], absolute=True)
        ins.length = 4
        return ins
    if mode == 0x7 and len(words) >= 2:
        ins.mnemonic = "mova"
        ins.src = mk_reg(high)
        ins.dst = mk_indexed(low, words[1])
        ins.length = 4
        return ins
    if mode in (0x8, 0x9, 0xA, 0xB) and len(words) >= 2:
        ins.mnemonic = {0x8: "mova", 0x9: "cmpa", 0xA: "adda", 0xB: "suba"}[mode]
        ins.src = mk_imm((high << 16) | words[1])
        ins.dst = mk_reg(low)
        ins.length = 4
        return ins
    if mode in (0xC, 0xD, 0xE, 0xF):
        ins.mnemonic = {0xC: "mova", 0xD: "cmpa", 0xE: "adda", 0xF: "suba"}[mode]
        ins.src = mk_reg(high)
        ins.dst = mk_reg(low)
        return ins

    return None


def decode_scaled_index_sign_extend(words: List[int], word: int) -> Optional[Decoded]:
    """Recognize the compiler's signed scale-by-six table-index sequence.

    Folding the sequence avoids unreadable 20-bit carry and mask algebra in
    decompiler output.
    """

    if len(words) < 8:
        return None

    mode = (word >> 4) & 0xF
    src_reg = (word >> 8) & 0xF
    dst_reg = word & 0xF
    bias = words[5]
    if (
        (word >> 12) != 0
        or mode != 0xC
        or src_reg == dst_reg
        or words[1] != (0x0650 | dst_reg)
        or words[2] != (0x0250 | src_reg)
        or words[3] != (0x5000 | (src_reg << 8) | dst_reg)
        or words[4] != (0x5030 | dst_reg)
        or words[6] != (0x0E40 | dst_reg)
        or words[7] != (0x0D40 | dst_reg)
    ):
        return None

    ins = Decoded(word)
    ins.fmt = "multi"
    ins.mnemonic = "sxtidx6.w"
    ins.src = mk_reg(src_reg)
    ins.dst = mk_reg(dst_reg)
    ins.imm = bias
    ins.length = 16
    ins.size = 4
    return ins


def decode_unsigned_scaled_index(words: List[int], word: int) -> Optional[Decoded]:
    """Recognize the compiler's unsigned scale-by-six table-index sequence.

    The following address add is included in the match because it overwrites
    flags, preserving the side effects of the original instruction sequence.
    """

    if len(words) < 17:
        return None
    if words[15] != 0x00AC:
        return None
    if (
        word != 0x430C
        or words[1] != 0x0FCD
        or words[2] != 0x0CCE
        or words[3] != 0x025D
        or words[4] != 0x6E0E
        or words[5] != 0x025F
        or words[6] != 0x6C0C
        or words[7] != 0x025F
        or words[8] != 0x6C0C
        or words[9] != 0x5D0F
        or words[10] != 0x6E0C
        or words[11] != 0x180F
        or words[12] != 0x5C4C
        or words[13] != 0x1800
        or words[14] != 0xDF4C
    ):
        return None

    ins = Decoded(word)
    ins.fmt = "multi"
    ins.mnemonic = "idx6.w"
    ins.src = mk_reg(15)
    ins.dst = mk_reg(12)
    ins.length = 30
    ins.size = 4
    return ins


def decode_wordpair20_load(words: List[int], word: int) -> Optional[Decoded]:
    """Recognize a 20-bit pointer load stored as a low word plus high nibble."""

    if len(words) < 6 or (word & 0xF0F0) != 0x4030:
        return None

    base_reg = (word >> 8) & 0xF
    low_reg = word & 0xF
    dst_reg = words[1] & 0xF
    if (
        words[1] != (0x4030 | (base_reg << 8) | dst_reg)
        or words[2] != 0x180F
        or words[3] != (0x5040 | (dst_reg << 8) | dst_reg)
        or words[4] != 0x1800
        or words[5] != (0xD040 | (low_reg << 8) | dst_reg)
        or low_reg == dst_reg
    ):
        return None

    ins = Decoded(word)
    ins.fmt = "multi"
    ins.mnemonic = "ld20.w"
    ins.src = mk_indirect(base_reg, autoinc=True)
    ins.dst = mk_reg(dst_reg)
    ins.imm = low_reg
    ins.length = 12
    ins.size = 4
    return ins


def decode_repeated_wordpair_shift(
    words: List[int],
    word: int,
    pattern: Tuple[int, int],
    mnemonic: str,
) -> Optional[Decoded]:
    """Collapse a repeated two-word R13:R12 shift ladder into one pseudo."""
    if len(words) < 4 or word != pattern[0]:
        return None

    count = 0
    index = 0
    while index + 1 < len(words) and (words[index], words[index + 1]) == pattern:
        count += 1
        index += 2

    if count < 2:
        return None

    ins = Decoded(word)
    ins.fmt = "multi"
    ins.mnemonic = mnemonic
    ins.src = mk_imm(count)
    ins.dst = mk_reg(12)
    ins.imm = count
    ins.length = count * 4
    ins.size = 4
    return ins


def decode_wordpair_logical_right_shift(
    words: List[int], word: int
) -> Optional[Decoded]:
    """Recognize repeated logical-right shifts across the R13:R12 word pair."""

    return decode_repeated_wordpair_shift(words, word, (0x035D, 0x005C), "lsr32.w")


def decode_wordpair_logical_left_shift(
    words: List[int], word: int
) -> Optional[Decoded]:
    """Recognize repeated logical-left shifts across the R13:R12 word pair."""

    return decode_repeated_wordpair_shift(words, word, (0x025C, 0x6D0D), "lsl32.w")


def decode_msb_mask(words: List[int], word: int) -> Optional[Decoded]:
    """Recognize the sequence that expands a word sign bit into a full mask."""

    if len(words) < 5 or (word & 0xF0F0) != 0x00C0:
        return None

    src_reg = (word >> 8) & 0xF
    scratch_reg = word & 0xF
    dst_reg = words[3] & 0xF
    if (
        words[1] != (0xB030 | scratch_reg)
        or words[2] != 0x8000
        or words[3] != (0x7000 | (dst_reg << 8) | dst_reg)
        or words[4] != (0xE330 | dst_reg)
    ):
        return None

    ins = Decoded(word)
    ins.fmt = "multi"
    ins.mnemonic = "msbmask.w"
    ins.src = mk_reg(src_reg)
    ins.dst = mk_reg(dst_reg)
    ins.imm = scratch_reg
    ins.length = 10
    ins.size = 2
    return ins


def decode_aligned_signed_advance(words: List[int], word: int) -> Optional[Decoded]:
    """Recognize signed 20-bit pointer advance followed by even alignment."""

    if len(words) < 9 or (word & 0xFFF0) != 0x0E40:
        return None

    offset_reg = word & 0xF
    base_reg = words[2] & 0xF
    dst_reg = words[3] & 0xF
    if (
        words[1] != (0x0D40 | offset_reg)
        or words[2] != ((offset_reg << 8) | 0x00E0 | base_reg)
        or words[3] != (0x00C0 | (base_reg << 8) | dst_reg)
        or words[4] != (0x00A0 | dst_reg)
        or words[5] != 0x0001
        or words[6] != 0x1F80
        or words[7] != (0xF070 | dst_reg)
        or words[8] != 0xFFFE
    ):
        return None

    ins = Decoded(word)
    ins.fmt = "multi"
    ins.mnemonic = "advptr20.w"
    ins.src = mk_reg(base_reg)
    ins.dst = mk_reg(dst_reg)
    ins.imm = offset_reg
    ins.length = 18
    ins.size = 4
    return ins


def is_probable_switch_target(addr: int) -> bool:
    if addr in (0x0000, 0xFFFF) or addr & 1:
        return False
    return 0x5C00 <= addr < 0x100000


def decode_indexed_bra_jump_table(words: List[int], word: int, addr: int) -> Optional[Decoded]:
    """Recognize an indexed 20-bit switch dispatch and collect its case targets.

    Treating the sequence as one indirect branch lets Binary Ninja seed the
    recovered targets instead of analyzing the table as code.
    """

    if len(words) < 11:
        return None
    if (word & 0xFFF0) != 0x0E40:
        return None

    reg = word & 0xF
    ext = words[2]
    if (
        words[1] != (0x0540 | reg)
        or not is_ext_word(ext)
        or ext_size(ext, 1) != 4
        or words[3] != (0x4050 | (reg << 8))
    ):
        return None

    table_addr = ((ext_src_hi(ext) << 16) | words[4]) & ADDR_MASK
    if table_addr < addr + 10 or ((table_addr - addr) & 1):
        return None

    table_word_offset = (table_addr - addr) // 2
    targets = []
    index = table_word_offset
    while index + 1 < len(words):
        target = words[index] | ((words[index + 1] & 0xF) << 16)
        if not is_probable_switch_target(target):
            break
        targets.append(target)
        index += 2

    if len(targets) < 3:
        return None

    ins = Decoded(word)
    ins.fmt = "multi"
    ins.mnemonic = "brajt.a"
    ins.src = mk_reg(reg)
    ins.dst = Operand("indexed", reg=reg, value=table_addr, text=f"{table_addr:#x}({reg_name(reg)})")
    ins.imm = table_addr
    ins.targets = tuple(targets)
    ins.length = 10
    ins.size = 4
    return ins


def decode_calla_instruction(words: List[int], word: int, addr: int) -> Optional[Decoded]:
    """Decode CALLA operand forms, including 20-bit PC-relative targets."""

    if (word & 0xFF00) != 0x1300:
        return None

    mode = (word >> 4) & 0xF
    low = word & 0xF
    if mode not in (0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xB):
        return None

    ins = Decoded(word)
    ins.mnemonic = "calla"
    ins.fmt = "single"
    ins.size = 4

    if mode == 0x4:
        ins.src = mk_reg(low)
    elif mode == 0x5:
        if len(words) < 2:
            return None
        ins.src = mk_indexed(low, words[1])
        ins.length = 4
    elif mode == 0x6:
        ins.src = mk_indirect(low)
    elif mode == 0x7:
        ins.src = mk_indirect(low, autoinc=True)
    elif mode == 0x8:
        if len(words) < 2:
            return None
        ins.src = mk_mem((low << 16) | words[1], absolute=True)
        ins.length = 4
    elif mode == 0x9:
        if len(words) < 2:
            return None
        disp = ((low << 16) | words[1]) & ADDR_MASK
        ins.src = mk_mem((addr + 4 + s20(disp)) & ADDR_MASK)
        ins.length = 4
    elif mode == 0xB:
        if len(words) < 2:
            return None
        ins.src = mk_imm((low << 16) | words[1])
        ins.length = 4

    ins.dst = ins.src
    return ins


# Precedence matters: longer, more specific compiler idioms must be recognized
# before their first word is decoded as an ordinary instruction.
PSEUDO_DECODERS = (
    decode_unsigned_scaled_index,
    decode_scaled_index_sign_extend,
    decode_wordpair20_load,
    decode_wordpair_logical_right_shift,
    decode_wordpair_logical_left_shift,
    decode_msb_mask,
    decode_aligned_signed_advance,
)


def decode(data: bytes, addr: int) -> Optional[Decoded]:
    """Decode one instruction or recognized compiler idiom at ``addr``.

    Compiler idioms are checked before ordinary opcodes because their first
    instruction is valid on its own. The order of those recognizers is part of
    the decode policy: more specific, longer patterns take precedence.
    """

    if len(data) < 2:
        return None

    first = u16(data, 0)
    if first is None:
        return None

    ext = None
    word_off = 0
    if is_ext_word(first) and len(data) >= 4:
        ext = first
        word_off = 2

    word = u16(data, word_off)
    if word is None:
        return None

    if ext is not None and word == 0:
        return None

    words = []
    for off in range(word_off, min(len(data), word_off + MAX_INSTR_LENGTH), 2):
        maybe = u16(data, off)
        if maybe is not None:
            words.append(maybe)

    ins = Decoded(word)
    ins.ext = ext
    base_len = 2 + (2 if ext is not None else 0)

    if ext is None:
        for pseudo_decoder in PSEUDO_DECODERS:
            pseudo = pseudo_decoder(words, word)
            if pseudo is not None:
                return pseudo

        indexed_bra_jump_table_ins = decode_indexed_bra_jump_table(words, word, addr)
        if indexed_bra_jump_table_ins is not None:
            return indexed_bra_jump_table_ins

        address_ins = decode_address_instruction(words, word)
        if address_ins is not None:
            return address_ins

    if (word & 0xE000) == 0x2000:
        cond = (word >> 10) & 0x7
        mnemonic, sem = JUMP_CONDS[cond]
        target = (addr + 2 + (2 * s10(word))) & 0xFFFFF
        ins.mnemonic = mnemonic
        ins.fmt = "jump"
        ins.length = 2
        ins.target = target
        ins.cond = sem
        return ins

    opcode = (word >> 12) & 0xF
    if opcode >= 4:
        src_reg = (word >> 8) & 0xF
        ad = (word >> 7) & 1
        bw = (word >> 6) & 1
        as_bits = (word >> 4) & 0x3
        dst_reg = word & 0xF
        idx = 1
        src, idx = source_operand(words, idx, addr + (2 if ext is not None else 0), src_reg, as_bits, ext)
        dst, idx = dest_operand(words, idx, addr + (2 if ext is not None else 0), dst_reg, ad, ext)
        ins.mnemonic = DOUBLE_OPS[opcode]
        ins.fmt = "double"
        ins.opcode = opcode
        ins.bw = bw
        ins.size = ext_size(ext, bw)
        ins.src = src
        ins.dst = dst
        ins.length = base_len + 2 * (idx - 1)
        register_mode_ext = ext is not None and ad == 0 and as_bits == 0
        # ZC is bit 8 only in a register/register extension word.  In the
        # non-register form that same bit belongs to the source high nibble.
        if ins.mnemonic == "subc" and register_mode_ext:
            ins.subc_zero_carry = ext_zero_carry(ext)
        # Use the encoded modes as well as normalized operands: R3/As=0 is a
        # register-mode constant-generator source even though it becomes #0.
        if ext is not None and (register_mode_ext or records_double_repeat_prefix(src, dst, ext)):
            ins.rpt_count = ext_repeat_count(ext)
            ins.rpt_reg = ext_repeat_reg(ext)
        return ins

    if ext is None:
        calla_ins = decode_calla_instruction(words, word, addr)
        if calla_ins is not None:
            return calla_ins

    if (word & 0xFC00) == 0x1000:
        op = (word >> 7) & 0x7
        bw = (word >> 6) & 1
        as_bits = (word >> 4) & 0x3
        reg = word & 0xF
        ins.mnemonic = SINGLE_OPS.get(op, "???")
        if ext is not None:
            if op == 0:
                ins.mnemonic = "rrux" if ext_zero_carry(ext) else "rrcx"
            elif op == 2:
                ins.mnemonic = "rrax"
        ins.fmt = "single"
        ins.opcode = op
        ins.bw = bw
        ins.size = single_operand_size(ext, bw, op)
        if op == 6:
            ins.length = 2
            return ins
        operand, idx = source_operand(words, 1, addr + (2 if ext is not None else 0), reg, as_bits, ext)
        ins.src = operand
        ins.dst = operand
        ins.length = base_len + 2 * (idx - 1)
        if ext is not None and ins.mnemonic in ("rrcx", "rrax", "rrux"):
            ins.rpt_count = ext_repeat_count(ext)
            ins.rpt_reg = ext_repeat_reg(ext)
        return ins

    ins.fmt = "cpux"
    ins.length = 2
    return ins


def tt(kind, text, value=None):
    """Create a Binary Ninja token from the decoder's compact token kind."""

    token_type = {
        "inst": InstructionTextTokenType.InstructionToken,
        "text": InstructionTextTokenType.TextToken,
        "reg": InstructionTextTokenType.RegisterToken,
        "sep": InstructionTextTokenType.OperandSeparatorToken,
        "addr": InstructionTextTokenType.PossibleAddressToken,
        "int": InstructionTextTokenType.IntegerToken,
    }[kind]
    if value is None:
        return InstructionTextToken(token_type, text)
    return InstructionTextToken(token_type, text, value=value)


def operand_tokens(op: Operand) -> List[InstructionTextToken]:
    """Render one normalized operand as Binary Ninja disassembly tokens."""

    if op is None:
        return []
    if op.kind == "reg":
        return [tt("reg", op.text)]
    if op.kind == "imm":
        text = op.text[1:] if op.text.startswith("#") else f"{op.value:#x}"
        return [tt("text", "#"), tt("int", text, op.value)]
    if op.kind == "mem":
        return [tt("addr", op.text, op.addr)]
    if op.kind == "indexed":
        return [tt("int", f"{op.value:#x}", op.value), tt("text", "("), tt("reg", reg_name(op.reg)), tt("text", ")")]
    if op.kind == "indirect":
        return [tt("text", "@"), tt("reg", reg_name(op.reg)), tt("text", "+" if op.autoinc else "")]
    return [tt("text", op.text or "<?>")]


def repeat_prefix_tokens(ins: Decoded) -> List[InstructionTextToken]:
    """Render the optional CPUX repeat prefix attached to an instruction."""

    prefix = "rptz" if ins.subc_zero_carry else "rpt"
    if ins.rpt_count is not None or (ins.subc_zero_carry and ins.rpt_reg is None):
        count = ins.rpt_count or 1
        return [
            tt("inst", prefix),
            tt("text", " "),
            tt("text", "#"),
            tt("int", f"{count}", count),
            tt("text", "; "),
        ]
    if ins.rpt_reg is not None:
        return [
            tt("inst", prefix),
            tt("text", " "),
            tt("reg", reg_name(ins.rpt_reg)),
            tt("text", "; "),
        ]
    return []


def is_bra_alias(ins: Decoded) -> bool:
    return (
        ins.fmt == "double"
        and ins.dst is not None
        and ins.dst.kind == "reg"
        and ins.dst.reg == 0
        and ins.size == 4
        and (ins.mnemonic == "mova" or (ins.ext is not None and ins.mnemonic == "mov"))
    )


def is_br_alias(ins: Decoded) -> bool:
    return (
        ins.fmt == "double"
        and ins.src is not None
        and ins.dst is not None
        and ins.dst.kind == "reg"
        and ins.dst.reg == 0
        and ins.size == 2
        and ins.ext is None
        and ins.mnemonic == "mov"
        and not is_ret_alias(ins)
    )


def is_reta_alias(ins: Decoded) -> bool:
    return (
        ins.fmt == "double"
        and ins.src is not None
        and ins.src.kind == "indirect"
        and ins.src.reg == 1
        and ins.src.autoinc
        and ins.dst is not None
        and ins.dst.kind == "reg"
        and ins.dst.reg == 0
        and ins.size == 4
        and (ins.mnemonic == "mova" or (ins.ext is not None and ins.mnemonic == "mov"))
    )


def is_ret_alias(ins: Decoded) -> bool:
    return (
        ins.fmt == "double"
        and ins.src is not None
        and ins.src.kind == "indirect"
        and ins.src.reg == 1
        and ins.src.autoinc
        and ins.dst is not None
        and ins.dst.kind == "reg"
        and ins.dst.reg == 0
        and ins.size == 2
        and ins.ext is None
        and ins.mnemonic == "mov"
    )


def is_popx_alias(ins: Decoded) -> bool:
    return (
        ins.fmt == "double"
        and ins.ext is not None
        and ins.mnemonic == "mov"
        and ins.src is not None
        and ins.src.kind == "indirect"
        and ins.src.reg == 1
        and ins.src.autoinc
        and ins.dst is not None
        and ins.dst.kind in ("reg", "mem", "indexed")
        and not (ins.dst.kind == "reg" and ins.dst.reg == 0)
    )


def is_pushx_alias(ins: Decoded) -> bool:
    return ins.fmt == "single" and ins.ext is not None and ins.mnemonic == "push"


def decoded_branch_edges(ins: Decoded, addr: int) -> Tuple[DecodedBranch, ...]:
    """Return normalized branch edges for a decoded instruction.

    Keeping this independent of Binary Ninja's ``InstructionInfo`` lets
    conservative loader-side analysis use exactly the same control-flow rules
    as the architecture implementation.
    """

    if ins.fmt == "jump":
        if ins.cond == "al":
            return (("unconditional", ins.target),)
        return (("true", ins.target), ("false", addr + ins.length))
    if ins.fmt == "single" and ins.mnemonic in ("call", "calla"):
        target = ins.src.value if ins.src and ins.src.kind == "imm" else None
        return (("call", target),)
    if ins.fmt == "single" and ins.mnemonic in ("reta", "reti"):
        return (("return", None),)
    if ins.fmt == "multi" and ins.mnemonic == "brajt.a":
        return (("indirect", None),)
    if ins.fmt == "double" and ins.dst and ins.dst.kind == "reg" and ins.dst.reg == 0:
        if is_reta_alias(ins) or is_ret_alias(ins):
            return (("return", None),)
        if (
            ins.src
            and ins.src.kind == "imm"
            and (is_bra_alias(ins) or is_br_alias(ins))
        ):
            return (("unconditional_pc", ins.src.value),)
        return (("indirect", None),)
    return ()


class MSP430XCallingConvention(CallingConvention):
    """Conservative register convention used when firmware lacks type data."""

    caller_saved_regs = ["r11", "r12", "r13", "r14", "r15"]
    callee_saved_regs = ["r4", "r5", "r6", "r7", "r8", "r9", "r10"]
    int_arg_regs = ["r12", "r13", "r14", "r15"]
    # IAR/GCC place unnamed variadic arguments on the stack rather than using
    # the remaining ordinary argument registers.
    arg_regs_for_varargs = False
    int_return_reg = "r12"
    high_int_return_reg = "r13"


class MSP430XArchitecture(Architecture):
    """Binary Ninja architecture definition for classic MSP430 and MSP430X."""

    name = "msp430x"
    endianness = Endianness.LittleEndian
    address_size = 4
    default_int_size = 2
    instr_alignment = 2
    max_instr_length = MAX_INSTR_LENGTH
    opcode_display_length = OPCODE_DISPLAY_LENGTH
    intrinsics = {
        "sra20": IntrinsicInfo(
            [IntrinsicInput(Type.int(4, False), "value"), IntrinsicInput(Type.int(4, False), "count")],
            [Type.int(4, False)],
        ),
        "sext20w": IntrinsicInfo([IntrinsicInput(Type.int(4, False), "value")], [Type.int(4, False)]),
        "swpb20": IntrinsicInfo([IntrinsicInput(Type.int(4, False), "value")], [Type.int(4, False)]),
        "swpbw": IntrinsicInfo([IntrinsicInput(Type.int(2, False), "value")], [Type.int(2, False)]),
        "idx6w": IntrinsicInfo([IntrinsicInput(Type.int(4, False), "value")], [Type.int(4, False)]),
        "sxtidx6w": IntrinsicInfo(
            [IntrinsicInput(Type.int(4, False), "value"), IntrinsicInput(Type.int(4, False), "bias")],
            [Type.int(4, False)],
        ),
        "wordpair20w": IntrinsicInfo(
            [IntrinsicInput(Type.int(4, False), "low"), IntrinsicInput(Type.int(4, False), "high")],
            [Type.int(4, False)],
        ),
        "lsr32w": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(4, False), "low"),
                IntrinsicInput(Type.int(4, False), "high"),
                IntrinsicInput(Type.int(4, False), "count"),
            ],
            [Type.int(4, False)],
        ),
        "lsl32w": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(4, False), "low"),
                IntrinsicInput(Type.int(4, False), "high"),
                IntrinsicInput(Type.int(4, False), "count"),
            ],
            [Type.int(4, False)],
        ),
        "load20": IntrinsicInfo([IntrinsicInput(Type.int(4, False), "addr")], [Type.int(4, False)]),
        "store20": IntrinsicInfo(
            [IntrinsicInput(Type.int(4, False), "addr"), IntrinsicInput(Type.int(4, False), "value")],
            [],
        ),
        "msbmaskw": IntrinsicInfo([IntrinsicInput(Type.int(2, False), "value")], [Type.int(2, False)]),
        "align2_20": IntrinsicInfo([IntrinsicInput(Type.int(4, False), "value")], [Type.int(4, False)]),
        "daddb": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(1, False), "lhs"),
                IntrinsicInput(Type.int(1, False), "rhs"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(1, False), Type.int(1, False)],
        ),
        "daddw": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(2, False), "lhs"),
                IntrinsicInput(Type.int(2, False), "rhs"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(2, False), Type.int(1, False)],
        ),
        "dadd20": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(4, False), "lhs"),
                IntrinsicInput(Type.int(4, False), "rhs"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(4, False), Type.int(1, False)],
        ),
        "rpt_dadd20": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(4, False), "lhs"),
                IntrinsicInput(Type.int(4, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(4, False), Type.int(1, False)],
        ),
        "rpt_daddw": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(2, False), "lhs"),
                IntrinsicInput(Type.int(2, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(2, False), Type.int(1, False)],
        ),
        "rpt_daddb": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(1, False), "lhs"),
                IntrinsicInput(Type.int(1, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_rrcx20": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(4, False), "value"),
                IntrinsicInput(Type.int(4, False), "count"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(4, False), Type.int(1, False)],
        ),
        "rpt_rrcxw": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(2, False), "value"),
                IntrinsicInput(Type.int(4, False), "count"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(2, False), Type.int(1, False)],
        ),
        "rpt_rrcxb": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(1, False), "value"),
                IntrinsicInput(Type.int(4, False), "count"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_rrax20": IntrinsicInfo(
            [IntrinsicInput(Type.int(4, False), "value"), IntrinsicInput(Type.int(4, False), "count")],
            [Type.int(4, False), Type.int(1, False)],
        ),
        "rpt_rraxw": IntrinsicInfo(
            [IntrinsicInput(Type.int(2, False), "value"), IntrinsicInput(Type.int(4, False), "count")],
            [Type.int(2, False), Type.int(1, False)],
        ),
        "rpt_rraxb": IntrinsicInfo(
            [IntrinsicInput(Type.int(1, False), "value"), IntrinsicInput(Type.int(4, False), "count")],
            [Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_rrux20": IntrinsicInfo(
            [IntrinsicInput(Type.int(4, False), "value"), IntrinsicInput(Type.int(4, False), "count")],
            [Type.int(4, False), Type.int(1, False)],
        ),
        "rpt_rruxw": IntrinsicInfo(
            [IntrinsicInput(Type.int(2, False), "value"), IntrinsicInput(Type.int(4, False), "count")],
            [Type.int(2, False), Type.int(1, False)],
        ),
        "rpt_rruxb": IntrinsicInfo(
            [IntrinsicInput(Type.int(1, False), "value"), IntrinsicInput(Type.int(4, False), "count")],
            [Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_selfadd20": IntrinsicInfo(
            [IntrinsicInput(Type.int(4, False), "value"), IntrinsicInput(Type.int(4, False), "count")],
            [Type.int(4, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_selfaddw": IntrinsicInfo(
            [IntrinsicInput(Type.int(2, False), "value"), IntrinsicInput(Type.int(4, False), "count")],
            [Type.int(2, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_selfaddb": IntrinsicInfo(
            [IntrinsicInput(Type.int(1, False), "value"), IntrinsicInput(Type.int(4, False), "count")],
            [Type.int(1, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_add20": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(4, False), "lhs"),
                IntrinsicInput(Type.int(4, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
            ],
            [Type.int(4, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_addw": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(2, False), "lhs"),
                IntrinsicInput(Type.int(2, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
            ],
            [Type.int(2, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_addb": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(1, False), "lhs"),
                IntrinsicInput(Type.int(1, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
            ],
            [Type.int(1, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_addc20": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(4, False), "lhs"),
                IntrinsicInput(Type.int(4, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(4, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_addcw": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(2, False), "lhs"),
                IntrinsicInput(Type.int(2, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(2, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_addcb": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(1, False), "lhs"),
                IntrinsicInput(Type.int(1, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(1, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_sub20": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(4, False), "lhs"),
                IntrinsicInput(Type.int(4, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
            ],
            [Type.int(4, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_subc20": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(4, False), "lhs"),
                IntrinsicInput(Type.int(4, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(4, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_subcw": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(2, False), "lhs"),
                IntrinsicInput(Type.int(2, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(2, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_subcb": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(1, False), "lhs"),
                IntrinsicInput(Type.int(1, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
                IntrinsicInput(Type.int(1, False), "carry"),
            ],
            [Type.int(1, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_subw": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(2, False), "lhs"),
                IntrinsicInput(Type.int(2, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
            ],
            [Type.int(2, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_subb": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(1, False), "lhs"),
                IntrinsicInput(Type.int(1, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
            ],
            [Type.int(1, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_xor20": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(4, False), "lhs"),
                IntrinsicInput(Type.int(4, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
            ],
            [Type.int(4, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_xorw": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(2, False), "lhs"),
                IntrinsicInput(Type.int(2, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
            ],
            [Type.int(2, False), Type.int(1, False), Type.int(1, False)],
        ),
        "rpt_xorb": IntrinsicInfo(
            [
                IntrinsicInput(Type.int(1, False), "lhs"),
                IntrinsicInput(Type.int(1, False), "rhs"),
                IntrinsicInput(Type.int(4, False), "count"),
            ],
            [Type.int(1, False), Type.int(1, False), Type.int(1, False)],
        ),
    }

    regs = {name: RegisterInfo(name, 4) for name in REG_NAMES}
    stack_pointer = "sp"
    flags = ["c", "z", "n", "v"]
    flag_roles = {
        "c": FlagRole.CarryFlagRole,
        "z": FlagRole.ZeroFlagRole,
        "n": FlagRole.NegativeSignFlagRole,
        "v": FlagRole.OverflowFlagRole,
    }

    def get_instruction_info(self, data: bytes, addr: int) -> Optional[InstructionInfo]:
        """Describe instruction length and control-flow edges to Binary Ninja."""

        ins = decode(data, addr)
        if ins is None:
            return None
        result = InstructionInfo()
        result.length = ins.length
        branch_types = {
            "unconditional": BranchType.UnconditionalBranch,
            "unconditional_pc": BranchType.UnconditionalBranch,
            "true": BranchType.TrueBranch,
            "false": BranchType.FalseBranch,
            "call": BranchType.CallDestination,
            "return": BranchType.FunctionReturn,
            "indirect": BranchType.IndirectBranch,
        }
        for kind, target in decoded_branch_edges(ins, addr):
            # LLIL carries the target and call semantics for indirect calls.
            # Adding a targetless CallDestination can seed address zero as a
            # phantom callee, while IndirectBranch incorrectly kills fallthrough.
            if kind == "call" and target is None:
                continue
            branch_type = branch_types[kind]
            if target is None:
                result.add_branch(branch_type)
            else:
                result.add_branch(branch_type, target)
        return result

    def get_instruction_text(self, data: bytes, addr: int):
        """Render one decoded instruction using structured disassembly tokens."""

        ins = decode(data, addr)
        if ins is None:
            return None
        suffix = ""
        if ins.ext is not None:
            suffix = ".a" if ins.size == 4 else ".w" if ins.size == 2 else ".b"
        elif ins.bw:
            suffix = ".b"

        if ins.fmt == "jump":
            return [tt("inst", ins.mnemonic), tt("text", " "), tt("addr", f"{ins.target:#x}", ins.target)], ins.length
        if ins.fmt == "double":
            tokens = repeat_prefix_tokens(ins)
            if is_reta_alias(ins):
                tokens.append(tt("inst", "reta"))
                return tokens, ins.length
            if is_ret_alias(ins):
                tokens.append(tt("inst", "ret"))
                return tokens, ins.length
            if is_br_alias(ins):
                tokens.extend([tt("inst", "br"), tt("text", " ")])
                tokens.extend(operand_tokens(ins.src))
                return tokens, ins.length
            if is_bra_alias(ins):
                tokens.extend([tt("inst", "bra"), tt("text", " ")])
                tokens.extend(operand_tokens(ins.src))
                return tokens, ins.length
            if is_popx_alias(ins):
                tokens.extend([tt("inst", "popx" + suffix), tt("text", " ")])
                tokens.extend(operand_tokens(ins.dst))
                return tokens, ins.length
            mnemonic = DOUBLE_OPS_X.get(ins.mnemonic, ins.mnemonic) if ins.ext is not None else ins.mnemonic
            tokens.extend([tt("inst", mnemonic + suffix), tt("text", " ")])
            tokens.extend(operand_tokens(ins.src))
            tokens.append(tt("sep", ", "))
            tokens.extend(operand_tokens(ins.dst))
            return tokens, ins.length
        if ins.fmt == "single":
            tokens = repeat_prefix_tokens(ins)
            if is_pushx_alias(ins):
                mnemonic = "pushx"
            elif ins.ext is not None and ins.mnemonic == "swpb":
                mnemonic = "swpbx"
            elif ins.ext is not None and ins.mnemonic == "sxt":
                mnemonic = "sxtx"
            else:
                mnemonic = ins.mnemonic
            tokens.append(tt("inst", mnemonic + suffix))
            if ins.mnemonic not in ("reta", "reti"):
                tokens.append(tt("text", " "))
                tokens.extend(operand_tokens(ins.src))
            return tokens, ins.length
        if ins.fmt == "multi":
            if ins.mnemonic == "brajt.a":
                return [
                    tt("inst", "bra"),
                    tt("text", " "),
                    *operand_tokens(ins.dst),
                ], ins.length
            if ins.mnemonic == "idx6.w":
                return [
                    tt("inst", ins.mnemonic),
                    tt("text", " "),
                    *operand_tokens(ins.src),
                    tt("sep", ", "),
                    *operand_tokens(ins.dst),
                ], ins.length
            if ins.mnemonic == "sxtidx6.w":
                return [
                    tt("inst", ins.mnemonic),
                    tt("text", " "),
                    *operand_tokens(ins.src),
                    tt("sep", ", "),
                    tt("text", "#"),
                    tt("int", f"{ins.imm:#x}", ins.imm),
                    tt("sep", ", "),
                    *operand_tokens(ins.dst),
                ], ins.length
            if ins.mnemonic == "ld20.w":
                return [
                    tt("inst", ins.mnemonic),
                    tt("text", " "),
                    *operand_tokens(ins.src),
                    tt("sep", ", "),
                    *operand_tokens(ins.dst),
                ], ins.length
            if ins.mnemonic in ("lsr32.w", "lsl32.w"):
                return [
                    tt("inst", ins.mnemonic),
                    tt("text", " #"),
                    tt("int", f"{ins.imm:#x}", ins.imm),
                    tt("sep", ", "),
                    tt("reg", "r13"),
                    tt("sep", ":"),
                    tt("reg", "r12"),
                ], ins.length
            if ins.mnemonic == "msbmask.w":
                return [
                    tt("inst", ins.mnemonic),
                    tt("text", " "),
                    *operand_tokens(ins.src),
                    tt("sep", ", "),
                    tt("reg", reg_name(ins.imm)),
                    tt("sep", ", "),
                    *operand_tokens(ins.dst),
                ], ins.length
            if ins.mnemonic == "advptr20.w":
                return [
                    tt("inst", ins.mnemonic),
                    tt("text", " "),
                    *operand_tokens(ins.src),
                    tt("sep", ", "),
                    tt("reg", reg_name(ins.imm)),
                    tt("sep", ", "),
                    *operand_tokens(ins.dst),
                ], ins.length
            if ins.mnemonic == "sext20.w":
                return [tt("inst", ins.mnemonic), tt("text", " "), *operand_tokens(ins.dst)], ins.length
            tokens = [tt("inst", ins.mnemonic), tt("text", " ")]
            tokens.extend(operand_tokens(ins.src))
            tokens.append(tt("sep", ", "))
            tokens.extend(operand_tokens(ins.dst))
            return tokens, ins.length
        return [tt("inst", "cpux"), tt("text", f" {ins.word:#06x}")], ins.length

    def _reg(self, il, reg: int):
        return il.reg(4, reg_name(reg))

    def _mask_expr(self, il, size: int, value):
        # Keep normal data-flow readable. Only flag calculations need explicit 20-bit canonicalization.
        return value

    def _flag_mask_expr(self, il, size: int, value):
        if size == 4:
            return il.and_expr(4, value, il.const(4, ADDR_MASK))
        return value

    def _flag_mask_temp(self, il, size: int, temp_id: int, value):
        value = self._flag_mask_expr(il, size, value)
        if size == 4:
            return self._temp_value(il, size, temp_id, value)
        return value

    def _reg_value(self, il, reg: int, size: int):
        """Read a register value, merging Binary Ninja flag state into SR.

        R2 is a 16-bit register in valid register-mode instructions; its other
        addressing encodings select the constant generator during decoding.
        Centralizing reconstruction here also makes a PUSHM list containing R2
        observe the current C, Z, N, and V flags.
        """

        if reg == 3:
            return il.const(size, 0)
        value = self._sr_value_from_flags(il) if reg == 2 else self._reg(il, reg)
        if size < 4:
            return il.low_part(size, value)
        return self._mask_expr(il, size, value)

    def _write_reg_value(self, il, reg: int, size: int, value) -> None:
        """Write a register and keep Binary Ninja's split SR flags coherent.

        Architecturally valid direct SR operands are 16-bit word operations.
        TI documents writes of 20-bit values to SR as unpredictable; callers
        must not interpret this helper's uniform four-byte register container
        as making such an instruction well-defined.
        """

        if reg == 3:
            return
        full = self._mask_expr(il, size, value) if size == 4 else il.zero_extend(4, value)
        il.append(il.set_reg(4, reg_name(reg), full))
        if reg == 2:
            self._sync_flags_from_sr_value(il, full)

    def _addr_expr(self, il, op: Operand):
        if op.kind == "mem":
            return il.const(4, op.addr)
        if op.kind == "indexed":
            return self._mask_expr(il, 4, il.add(4, self._reg(il, op.reg), il.const(4, op.value & 0xFFFFFFFF)))
        if op.kind == "indirect":
            return self._mask_expr(il, 4, self._reg(il, op.reg))
        return il.const(4, op.value & 0xFFFFF)

    def _load_from_addr(self, il, size: int, addr, temp_id: int):
        if size == 4:
            temp = LLIL_TEMP(temp_id)
            il.append(il.intrinsic([temp], "load20", [addr]))
            return il.reg(4, temp)
        return self._mask_expr(il, size, il.load(size, addr))

    def _store_to_addr(self, il, size: int, addr, value) -> None:
        value = self._mask_expr(il, size, value)
        if size == 4:
            il.append(il.intrinsic([], "store20", [addr, value]))
            return
        il.append(il.store(size, addr, value))

    def _read_operand(self, il, op: Operand, size: int, temp_base: int = 0):
        """Lift an operand read, applying autoincrement exactly once."""

        if op.kind == "imm":
            return il.const(size, op.value & mask_for_size(size))
        if op.kind == "reg":
            return self._reg_value(il, op.reg, size)
        if op.kind in ("mem", "indexed"):
            return self._load_from_addr(il, size, self._addr_expr(il, op), 37 + temp_base)
        if op.kind == "indirect":
            if not op.autoinc:
                return self._load_from_addr(il, size, self._reg(il, op.reg), 37 + temp_base)
            temp = LLIL_TEMP(temp_base)
            il.append(il.set_reg(4, temp, self._reg(il, op.reg)))
            step = autoinc_step(op.reg, size)
            value = self._mask_expr(
                il,
                4,
                il.add(4, self._reg(il, op.reg), il.const(4, step)),
            )
            il.append(il.set_reg(4, reg_name(op.reg), value))
            return self._load_from_addr(il, size, il.reg(4, temp), 37 + temp_base)
        return il.unimplemented()

    def _write_operand(self, il, op: Operand, size: int, value, write_addr=None) -> None:
        """Lift an operand write, treating writes to PC as control flow."""

        if write_addr is not None:
            self._store_to_addr(il, size, write_addr, value)
            return
        if op.kind == "reg":
            if op.reg == 0:
                target = il.zero_extend(4, value) if size < 4 else self._mask_expr(il, 4, value)
                il.append(il.jump(target))
            else:
                self._write_reg_value(il, op.reg, size, value)
            return
        if op.kind in ("mem", "indexed", "indirect"):
            self._store_to_addr(il, size, self._addr_expr(il, op), value)
            return
        il.append(il.unimplemented())

    def _set_flag(self, il, name: str, expr) -> None:
        il.append(il.set_flag(name, expr))

    def _sr_value_from_flags(self, il):
        """Reconstruct the 16-bit SR by overlaying the explicit LLIL flags.

        Only SR.11:0 are status and control state. Bits 15:12 carry PC.19:16
        only in the combined SR word saved in an MSP430X interrupt frame; they
        are separated before this helper is used during RETI.
        """

        value = il.and_expr(4, il.reg(4, "sr"), il.const(4, (~SR_TRACKED_FLAG_MASK) & 0xFFFFFFFF))
        for name, bit in SR_FLAG_BITS.items():
            flag_value = il.zero_extend(4, il.flag(name))
            if bit:
                flag_value = il.shift_left(4, flag_value, il.const(4, bit))
            value = il.or_expr(4, value, flag_value)
        return value

    def _sr_flag_expr(self, il, value, bit: int):
        return il.compare_not_equal(4, il.and_expr(4, value, il.const(4, 1 << bit)), il.const(4, 0))

    def _sync_flags_from_sr_value(self, il, value) -> None:
        """Copy C, Z, N, and V from an SR value into Binary Ninja flag state.

        For RETI, the caller first removes stacked PC.19:16 so those borrowed
        upper bits cannot be mistaken for SR state.
        """

        for name, bit in SR_FLAG_BITS.items():
            self._set_flag(il, name, self._sr_flag_expr(il, value, bit))

    def _set_nz(self, il, size: int, value, *, masked: bool = False) -> None:
        if not masked:
            value = self._flag_mask_expr(il, size, value)
        self._set_flag(il, "z", il.compare_equal(size, value, il.const(size, 0)))
        self._set_flag(
            il,
            "n",
            il.compare_not_equal(
                size,
                il.and_expr(size, value, il.const(size, 1 << (bits_for_size(size) - 1))),
                il.const(size, 0),
            ),
        )

    def _set_logic_flags(self, il, size: int, value, *, masked: bool = False) -> None:
        if not masked:
            value = self._flag_mask_temp(il, size, 18, value)
        self._set_nz(il, size, value, masked=True)
        self._set_flag(il, "c", il.compare_not_equal(size, value, il.const(size, 0)))
        self._set_flag(il, "v", il.const(0, 0))

    def _set_xor_flags(self, il, size: int, lhs, rhs, result) -> None:
        result = self._flag_mask_temp(il, size, 20, result)
        self._set_nz(il, size, result, masked=True)
        self._set_flag(il, "c", il.compare_not_equal(size, result, il.const(size, 0)))
        both_negative = il.and_expr(size, self._sign_mask_expr(il, size, lhs), self._sign_mask_expr(il, size, rhs))
        self._set_flag(il, "v", il.compare_not_equal(size, both_negative, il.const(size, 0)))

    def _set_invert_flags(self, il, size: int, lhs, result) -> None:
        result = self._flag_mask_temp(il, size, 20, result)
        self._set_nz(il, size, result, masked=True)
        self._set_flag(il, "c", il.compare_not_equal(size, result, il.const(size, 0)))
        self._set_flag(il, "v", il.compare_not_equal(size, self._sign_mask_expr(il, size, lhs), il.const(size, 0)))

    def _sign_mask_expr(self, il, size: int, value):
        return il.and_expr(size, value, il.const(size, 1 << (bits_for_size(size) - 1)))

    def _address_arith_shift_right_expr(self, il, value, count: int):
        temp = LLIL_TEMP(23)
        il.append(il.intrinsic([temp], "sra20", [value, il.const(4, count)]))
        return il.reg(4, temp)

    def _repeat_shift_expr(self, il, op: str, size: int, value, count):
        suffix = "20" if size == 4 else "w" if size == 2 else "b"
        value_temp = LLIL_TEMP(46)
        carry_temp = LLIL_TEMP(47)
        params = [value, count]
        if op == "rrcx":
            params.append(il.flag("c"))
        il.append(il.intrinsic([value_temp, carry_temp], f"rpt_{op}{suffix}", params))
        return il.reg(size, value_temp), il.reg(1, carry_temp)

    def _sext20_word_expr(self, il, value):
        temp = LLIL_TEMP(24)
        il.append(il.intrinsic([temp], "sext20w", [value]))
        return il.reg(4, temp)

    def _swpb20_expr(self, il, value):
        temp = LLIL_TEMP(25)
        il.append(il.intrinsic([temp], "swpb20", [value]))
        return il.reg(4, temp)

    def _swpb_word_expr(self, il, value):
        temp = LLIL_TEMP(25)
        il.append(il.intrinsic([temp], "swpbw", [value]))
        return il.reg(2, temp)

    def _idx6_word_expr(self, il, value):
        temp = LLIL_TEMP(27)
        il.append(il.intrinsic([temp], "idx6w", [value]))
        return il.reg(4, temp)

    def _sxtidx6_word_expr(self, il, value, bias: int):
        temp = LLIL_TEMP(26)
        il.append(il.intrinsic([temp], "sxtidx6w", [value, il.const(4, bias & 0xFFFF)]))
        return il.reg(4, temp)

    def _wordpair20_expr(self, il, low, high):
        temp = LLIL_TEMP(30)
        il.append(il.intrinsic([temp], "wordpair20w", [low, high]))
        return il.reg(4, temp)

    def _lsr32_wordpair_expr(self, il, low, high, count: int):
        temp = LLIL_TEMP(40)
        il.append(il.intrinsic([temp], "lsr32w", [low, high, il.const(4, count)]))
        return il.reg(4, temp)

    def _lsl32_wordpair_expr(self, il, low, high, count: int):
        temp = LLIL_TEMP(43)
        il.append(il.intrinsic([temp], "lsl32w", [low, high, il.const(4, count)]))
        return il.reg(4, temp)

    def _msbmask_word_expr(self, il, value):
        temp = LLIL_TEMP(31)
        il.append(il.intrinsic([temp], "msbmaskw", [value]))
        return il.reg(2, temp)

    def _align2_20_expr(self, il, value):
        temp = LLIL_TEMP(32)
        il.append(il.intrinsic([temp], "align2_20", [value]))
        return il.reg(4, temp)

    def _sxt_20_expr(self, il, src):
        low = il.low_part(1, src)
        sign_set = il.compare_not_equal(1, il.and_expr(1, low, il.const(1, 0x80)), il.const(1, 0))
        sign_fill = il.and_expr(
            4,
            il.sub(4, il.const(4, 0), il.zero_extend(4, sign_set)),
            il.const(4, 0xFFF00),
        )
        return il.or_expr(4, il.zero_extend(4, low), sign_fill)

    def _set_add_flags(self, il, size: int, lhs, rhs, result, carry=None, *, rhs_canonical: bool = False) -> None:
        """Set the MSP430 N, Z, C, and V flags for an addition result."""

        lhs = self._flag_mask_temp(il, size, 18, lhs)
        if not rhs_canonical:
            rhs = self._flag_mask_temp(il, size, 19, rhs)
        if size == 4:
            full = il.add(4, lhs, rhs)
            rhs_for_overflow = rhs
            if carry is not None:
                carry_full = il.zero_extend(4, carry)
                full = il.add(4, full, carry_full)
                rhs_for_overflow = self._flag_mask_expr(il, 4, il.add(4, rhs, carry_full))
            self._set_flag(
                il,
                "z",
                il.or_expr(
                    0,
                    il.compare_equal(4, full, il.const(4, 0)),
                    il.compare_equal(4, full, il.const(4, ADDR_MASK + 1)),
                ),
            )
            self._set_flag(il, "n", self._bit_flag_expr(il, 4, full, bits_for_size(4) - 1))
            self._set_flag(il, "c", il.compare_unsigned_greater_than(4, full, il.const(4, ADDR_MASK)))
            overflow_bits = il.and_expr(
                4,
                il.and_expr(4, il.not_expr(4, il.xor_expr(4, lhs, rhs_for_overflow)), il.xor_expr(4, lhs, full)),
                il.const(4, 1 << (bits_for_size(4) - 1)),
            )
            self._set_flag(il, "v", il.compare_not_equal(4, overflow_bits, il.const(4, 0)))
            return
        result = self._flag_mask_temp(il, size, 20, result)
        self._set_nz(il, size, result, masked=True)
        if carry is not None:
            lhs_full = lhs if size == 4 else il.zero_extend(4, lhs)
            rhs_full = rhs if size == 4 else il.zero_extend(4, rhs)
            carry_full = il.zero_extend(4, carry)
            full = il.add(4, il.add(4, lhs_full, rhs_full), carry_full)
            self._set_flag(il, "c", il.compare_unsigned_greater_than(4, full, il.const(4, mask_for_size(size))))
            rhs = self._flag_mask_expr(il, size, il.add(size, rhs, il.zero_extend(size, carry)))
        elif size == 4:
            full = il.add(4, lhs, rhs)
            self._set_flag(il, "c", il.compare_unsigned_greater_than(4, full, il.const(4, ADDR_MASK)))
        else:
            self._set_flag(il, "c", il.compare_unsigned_less_than(size, result, lhs))
        overflow_bits = il.and_expr(
            size,
            il.and_expr(size, il.not_expr(size, il.xor_expr(size, lhs, rhs)), il.xor_expr(size, lhs, result)),
            il.const(size, 1 << (bits_for_size(size) - 1)),
        )
        self._set_flag(il, "v", il.compare_not_equal(size, overflow_bits, il.const(size, 0)))

    def _set_sub_flags(
        self,
        il,
        size: int,
        lhs,
        rhs,
        result,
        *,
        rhs_canonical: bool = False,
    ) -> None:
        """Set the MSP430 N, Z, C, and V flags for subtraction or comparison."""

        lhs = self._flag_mask_temp(il, size, 18, lhs)
        if not rhs_canonical:
            rhs = self._flag_mask_temp(il, size, 19, rhs)
        if size == 4:
            diff = il.sub(4, lhs, rhs)
            self._set_flag(il, "z", il.compare_equal(4, lhs, rhs))
            self._set_flag(il, "n", self._bit_flag_expr(il, 4, diff, bits_for_size(4) - 1))
            self._set_flag(il, "c", il.compare_unsigned_greater_equal(4, lhs, rhs))
            overflow_bits = il.and_expr(
                4,
                il.and_expr(4, il.xor_expr(4, lhs, rhs), il.xor_expr(4, lhs, diff)),
                il.const(4, 1 << (bits_for_size(4) - 1)),
            )
            self._set_flag(il, "v", il.compare_not_equal(4, overflow_bits, il.const(4, 0)))
            return
        result = self._flag_mask_temp(il, size, 20, result)
        self._set_nz(il, size, result, masked=True)
        self._set_flag(il, "c", il.compare_unsigned_greater_equal(size, lhs, rhs))
        overflow_bits = il.and_expr(
            size,
            il.and_expr(size, il.xor_expr(size, lhs, rhs), il.xor_expr(size, lhs, result)),
            il.const(size, 1 << (bits_for_size(size) - 1)),
        )
        self._set_flag(il, "v", il.compare_not_equal(size, overflow_bits, il.const(size, 0)))

    def _set_subc_flags(self, il, size: int, lhs, rhs, result, full_result) -> None:
        """Set SUBC flags from cached inputs and its untruncated addition.

        MSP430 defines SUBC as ``dst + (~src) + C``.  Carry therefore comes
        from the widened addition while signed overflow uses the original
        source, not a width-wrapped ``src + !C`` value.
        """

        self._set_nz(il, size, result, masked=True)
        self._set_flag(
            il,
            "c",
            il.compare_unsigned_greater_than(4, full_result, il.const(4, mask_for_size(size))),
        )
        overflow_bits = il.and_expr(
            size,
            il.and_expr(size, il.xor_expr(size, lhs, rhs), il.xor_expr(size, lhs, result)),
            il.const(size, 1 << (bits_for_size(size) - 1)),
        )
        self._set_flag(il, "v", il.compare_not_equal(size, overflow_bits, il.const(size, 0)))

    def _dadd_expr_and_carry(self, il, size: int, lhs, rhs, carry_in):
        result_temp = LLIL_TEMP(28)
        carry_temp = LLIL_TEMP(29)
        name = "dadd20" if size == 4 else "daddw" if size == 2 else "daddb"
        il.append(il.intrinsic([result_temp, carry_temp], name, [lhs, rhs, il.zero_extend(1, carry_in)]))
        carry = il.compare_not_equal(1, il.reg(1, carry_temp), il.const(1, 0))
        return il.reg(size, result_temp), carry

    def _lift_dadd(self, il, ins: Decoded, size: int, dst, src, dst_write_addr=None) -> None:
        value, carry = self._dadd_expr_and_carry(il, size, dst, src, il.flag("c"))
        self._set_nz(il, size, value, masked=True)
        self._set_flag(il, "c", carry)
        self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)

    def _branch_condition(self, il, cond: str):
        if cond == "ne":
            return il.not_expr(0, il.flag("z"))
        if cond == "eq":
            return il.flag("z")
        if cond == "cc":
            return il.not_expr(0, il.flag("c"))
        if cond == "cs":
            return il.flag("c")
        if cond == "mi":
            return il.flag("n")
        if cond == "ge":
            return il.compare_equal(0, il.flag("n"), il.flag("v"))
        if cond == "lt":
            return il.compare_not_equal(0, il.flag("n"), il.flag("v"))
        return il.const(0, 1)

    def _lift_jump(self, il, ins: Decoded, addr: int) -> None:
        if ins.cond == "al":
            il.append(il.jump(il.const(4, ins.target)))
            return

        true_label = il.get_label_for_address(self, ins.target)
        false_label = il.get_label_for_address(self, addr + ins.length)
        true_is_synthetic = true_label is None
        false_is_synthetic = false_label is None

        if true_label is None:
            true_label = LowLevelILLabel()
        if false_label is None:
            false_label = LowLevelILLabel()

        il.append(il.if_expr(self._branch_condition(il, ins.cond), true_label, false_label))
        if true_is_synthetic:
            il.mark_label(true_label)
            il.append(il.jump(il.const(4, ins.target)))
        if false_is_synthetic:
            il.mark_label(false_label)

    def _lift_reta(self, il) -> None:
        """Restore a CALLA return address from two stack words.

        PC.15:0 is at the top of stack and PC.19:16 occupies the low nibble of
        the following word. RETA consumes four bytes and, unlike RETI, leaves
        SR.11:0 untouched.
        """

        pc_low = il.pop(2)
        pc_high = il.and_expr(2, il.pop(2), il.const(2, 0x000F))
        target = il.or_expr(
            4,
            il.zero_extend(4, pc_low),
            il.shift_left(4, il.zero_extend(4, pc_high), il.const(4, 16)),
        )
        il.append(il.ret(self._mask_expr(il, 4, target)))

    def _lift_reti(self, il) -> None:
        """Restore SR and the 20-bit PC from two stack words.

        The top word packs PC.19:16 into bits 15:12 and SR.11:0 into bits
        11:0; the following word contains PC.15:0. Splitting that shared word
        before synchronizing flags prevents the PC nibble from becoming SR
        state, while the two pops advance the even-aligned stack by four bytes.
        """

        sr_pc_high = LLIL_TEMP(8)
        il.append(il.set_reg(2, sr_pc_high, il.pop(2)))
        sr_value = il.and_expr(2, il.reg(2, sr_pc_high), il.const(2, SR_MASK))
        pc_high = il.and_expr(
            2,
            il.logical_shift_right(2, il.reg(2, sr_pc_high), il.const(2, 12)),
            il.const(2, 0x000F),
        )
        pc_low = il.pop(2)
        target = il.or_expr(
            4,
            il.zero_extend(4, pc_low),
            il.shift_left(4, il.zero_extend(4, pc_high), il.const(4, 16)),
        )
        sr_full = il.zero_extend(4, sr_value)
        il.append(il.set_reg(4, "sr", sr_full))
        self._sync_flags_from_sr_value(il, sr_full)
        il.append(il.ret(self._mask_expr(il, 4, target)))

    def _push_stack(self, il, size: int, value) -> None:
        """Push a value while preserving the MSP430X even-aligned stack.

        Byte and word pushes reserve two bytes, even though a byte push stores
        only one byte. A 20-bit address-word occupies two words and therefore
        reserves four bytes.
        """

        push_size = 4 if size == 4 else 2
        new_sp = self._mask_expr(il, 4, il.sub(4, il.reg(4, "sp"), il.const(4, push_size)))
        il.append(il.set_reg(4, "sp", new_sp))
        self._store_to_addr(il, size, il.reg(4, "sp"), value)

    def _bit_flag_expr(self, il, size: int, value, bit: int):
        return il.compare_not_equal(size, il.and_expr(size, value, il.const(size, 1 << bit)), il.const(size, 0))

    def _lift_compact_shift(self, il, ins: Decoded) -> None:
        """Lift compact CPUX shifts and their final architectural flags."""

        op = ins.mnemonic.split(".", 1)[0]
        size = ins.size
        bits = bits_for_size(size)
        count = ins.src.value
        raw_value = self._reg_value(il, ins.dst.reg, size)
        carry = il.flag("c")

        if op == "rlam":
            shifted = il.shift_left(size, raw_value, il.const(size, count))
            self._set_flag(
                il,
                "z",
                il.compare_equal(
                    size,
                    il.and_expr(size, raw_value, il.const(size, mask_for_size(size) >> count)),
                    il.const(size, 0),
                ),
            )
            self._set_flag(il, "n", self._bit_flag_expr(il, size, raw_value, bits - count - 1))
            self._set_flag(il, "c", self._bit_flag_expr(il, size, raw_value, bits - count))
            self._write_operand(il, ins.dst, size, shifted)
            return

        value = self._flag_mask_temp(il, size, 18, raw_value)
        if op == "rram":
            carry = self._bit_flag_expr(il, size, value, count - 1)
            if size == 4:
                value = self._address_arith_shift_right_expr(il, value, count)
            else:
                value = il.arith_shift_right(size, value, il.const(size, count))
        elif op == "rrum":
            carry = self._bit_flag_expr(il, size, value, count - 1)
            value = il.logical_shift_right(size, value, il.const(size, count))
        else:
            for _ in range(count):
                carry_in = carry
                carry = self._bit_flag_expr(il, size, value, 0)
                value = il.or_expr(
                    size,
                    il.logical_shift_right(size, value, il.const(size, 1)),
                    il.shift_left(size, il.zero_extend(size, carry_in), il.const(size, bits - 1)),
                )

        if not (size == 4 and op in ("rram", "rrum")):
            value = self._flag_mask_temp(il, size, 20, value)

        self._write_operand(il, ins.dst, size, value)
        self._set_nz(il, size, value, masked=True)
        self._set_flag(il, "c", carry)
        if op != "rlam":
            self._set_flag(il, "v", il.const(0, 0))

    def _lift_cpux_right_shift(self, il, ins: Decoded, src, write_addr=None, repeat_count: Optional[int] = None) -> None:
        """Lift CPUX right shifts, including repeat-prefix semantics."""

        size = ins.size
        bits = bits_for_size(size)
        op = ins.mnemonic
        value = src
        carry = il.flag("c")
        repeat_count = repeat_count if repeat_count is not None else (ins.rpt_count or 1)

        if repeat_count > 1 and op == "rrcx" and ins.dst is not None:
            value, carry = self._repeat_shift_expr(il, op, size, value, il.const(4, repeat_count))
        elif repeat_count > 1 and op in ("rrax", "rrux"):
            value = self._flag_mask_temp(il, size, 18, value)
            carry = self._bit_flag_expr(il, size, value, repeat_count - 1)
            if op == "rrax":
                if size == 4:
                    value = self._address_arith_shift_right_expr(il, value, repeat_count)
                else:
                    value = il.arith_shift_right(size, value, il.const(size, repeat_count))
            else:
                value = il.logical_shift_right(size, value, il.const(size, repeat_count))
        elif op == "rrax" and size < 4:
            value = self._flag_mask_temp(il, size, 18, value)
            carry = self._bit_flag_expr(il, size, value, 0)
            value = il.arith_shift_right(size, value, il.const(size, 1))
        else:
            value = self._flag_mask_temp(il, size, 18, value)
            for _ in range(repeat_count):
                carry_in = carry
                carry = self._bit_flag_expr(il, size, value, 0)
                shifted = il.logical_shift_right(size, value, il.const(size, 1))

                if op == "rrcx":
                    carry_bit = il.shift_left(size, il.zero_extend(size, carry_in), il.const(size, bits - 1))
                    value = il.or_expr(size, shifted, carry_bit)
                elif op == "rrax":
                    sign = il.and_expr(size, value, il.const(size, 1 << (bits - 1)))
                    value = il.or_expr(size, shifted, sign)
                else:
                    value = shifted
                if size == 4:
                    value = self._temp_value(il, size, 18, value)

        if write_addr is not None:
            self._store_to_addr(il, size, write_addr, value)
        else:
            self._write_operand(il, ins.dst, size, value)
        self._set_nz(il, size, value, masked=True)
        self._set_flag(il, "c", carry)
        self._set_flag(il, "v", il.const(0, 0))

    def _lift_repeat_reg_loop(self, il, ins: Decoded, body) -> None:
        counter = LLIL_TEMP(21)
        loop = LowLevelILLabel()
        done = LowLevelILLabel()
        repeat_value = self._repeat_reg_count_expr(il, ins)
        il.append(il.set_reg(4, counter, repeat_value))
        il.mark_label(loop)
        body()
        il.append(il.set_reg(4, counter, il.sub(4, il.reg(4, counter), il.const(4, 1))))
        il.append(il.if_expr(il.compare_not_equal(4, il.reg(4, counter), il.const(4, 0)), loop, done))
        il.mark_label(done)

    def _repeat_reg_count_expr(self, il, ins: Decoded):
        return il.add(
            4,
            il.and_expr(4, self._reg(il, ins.rpt_reg), il.const(4, 0xF)),
            il.const(4, 1),
        )

    def _lift_repeat_reg_cpux_right_shift(self, il, ins: Decoded) -> None:
        if ins.src is None:
            il.append(il.unimplemented())
            return

        if not (ins.src.kind == "indirect" and ins.src.autoinc):
            repeat_value = self._repeat_reg_count_expr(il, ins)
            src = self._read_operand(il, ins.src, ins.size)
            value, carry = self._repeat_shift_expr(il, ins.mnemonic, ins.size, src, repeat_value)
            self._write_operand(il, ins.dst, ins.size, value)
            self._set_nz(il, ins.size, value, masked=True)
            self._set_flag(il, "c", carry)
            self._set_flag(il, "v", il.const(0, 0))
            return

        def body() -> None:
            write_addr = None
            temp_base = 0
            if ins.src.kind == "indirect" and ins.src.autoinc:
                temp_base = 15
                write_addr = il.reg(4, LLIL_TEMP(temp_base))
            src = self._read_operand(il, ins.src, ins.size, temp_base=temp_base)
            self._lift_cpux_right_shift(il, ins, src, write_addr=write_addr, repeat_count=1)

        self._lift_repeat_reg_loop(il, ins, body)

    def _temp_value(self, il, size: int, temp_id: int, value):
        temp = LLIL_TEMP(temp_id)
        il.append(il.set_reg(size, temp, value))
        return il.reg(size, temp)

    def _lift_double_once(
        self,
        il,
        ins: Decoded,
        size: int,
        src,
        dst,
        *,
        update_flags: bool = True,
        dst_write_addr=None,
    ) -> bool:
        """Lift one double-operand execution, returning ``False`` if unsupported."""

        op = ins.mnemonic

        if op in ("mov", "mova"):
            self._write_operand(il, ins.dst, size, src, write_addr=dst_write_addr)
        elif op in ("add", "adda"):
            value = self._mask_expr(il, size, il.add(size, dst, src))
            if update_flags:
                self._set_add_flags(il, size, dst, src, value, rhs_canonical=ins.src.kind == "imm")
            self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)
        elif op == "addc":
            carry = il.flag("c")
            value = self._mask_expr(il, size, il.add(size, il.add(size, dst, src), il.zero_extend(size, carry)))
            if update_flags:
                self._set_add_flags(il, size, dst, src, value, carry, rhs_canonical=ins.src.kind == "imm")
            self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)
        elif op in ("sub", "cmp", "suba", "cmpa"):
            value = self._mask_expr(il, size, il.sub(size, dst, src))
            if update_flags:
                self._set_sub_flags(il, size, dst, src, value, rhs_canonical=ins.src.kind == "imm")
            if op not in ("cmp", "cmpa"):
                self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)
        elif op == "subc":
            carry_value = il.const(1, 0) if ins.subc_zero_carry else il.zero_extend(1, il.flag("c"))
            carry_in = self._temp_value(il, 1, 51, carry_value)
            lhs = self._temp_value(il, size, 18, self._flag_mask_expr(il, size, dst))
            rhs = self._temp_value(il, size, 19, self._flag_mask_expr(il, size, src))
            complement = il.xor_expr(size, rhs, il.const(size, mask_for_size(size)))
            lhs_full = lhs if size == 4 else il.zero_extend(4, lhs)
            complement_full = complement if size == 4 else il.zero_extend(4, complement)
            full_result = self._temp_value(
                il,
                4,
                52,
                il.add(4, il.add(4, lhs_full, complement_full), il.zero_extend(4, carry_in)),
            )
            result_expr = (
                il.and_expr(4, full_result, il.const(4, ADDR_MASK))
                if size == 4
                else il.low_part(size, full_result)
            )
            value = self._temp_value(il, size, 20, result_expr)
            if update_flags:
                self._set_subc_flags(il, size, lhs, rhs, value, full_result)
            self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)
        elif op == "bit":
            value = self._mask_expr(il, size, il.and_expr(size, dst, src))
            if update_flags:
                self._set_logic_flags(il, size, value, masked=ins.src.kind == "imm")
        elif op == "bic":
            value = self._mask_expr(il, size, il.and_expr(size, dst, il.not_expr(size, src)))
            self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)
        elif op == "bis":
            value = self._mask_expr(il, size, il.or_expr(size, dst, src))
            self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)
        elif op == "xor":
            inverted = is_all_ones_immediate(ins.src, size)
            value = self._mask_expr(il, size, il.not_expr(size, dst) if inverted else il.xor_expr(size, dst, src))
            if update_flags:
                if inverted:
                    self._set_invert_flags(il, size, dst, value)
                else:
                    self._set_xor_flags(il, size, dst, src, value)
            self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)
        elif op == "and":
            value = self._mask_expr(il, size, il.and_expr(size, dst, src))
            if update_flags:
                self._set_logic_flags(il, size, value, masked=ins.src.kind == "imm")
            self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)
        elif op == "dadd":
            self._lift_dadd(il, ins, size, dst, src, dst_write_addr=dst_write_addr)
        else:
            return False
        return True

    def _repeat_dst_alias_addr(self, ins: Decoded) -> bool:
        return (
            ins.src is not None
            and ins.dst is not None
            and ins.src.kind == "indirect"
            and ins.src.autoinc
            and ins.dst.kind == "indexed"
            and ins.src.reg == ins.dst.reg
        )

    def _read_repeated_double_operands(self, il, ins: Decoded, size: int):
        src = self._temp_value(il, size, 16, self._read_operand(il, ins.src, size))
        dst_write_addr = None
        if self._repeat_dst_alias_addr(ins):
            dst_addr_temp = LLIL_TEMP(22)
            il.append(il.set_reg(4, dst_addr_temp, self._addr_expr(il, ins.dst)))
            dst_write_addr = il.reg(4, dst_addr_temp)
            dst = self._temp_value(il, size, 17, self._load_from_addr(il, size, dst_write_addr, 39))
        else:
            dst = self._temp_value(il, size, 17, self._read_operand(il, ins.dst, size))
        return src, dst, dst_write_addr

    def _can_fold_repeat_reg_add(self, ins: Decoded) -> bool:
        if ins.mnemonic not in ("add", "adda") or ins.src is None or ins.dst is None:
            return False
        if ins.src.kind == "indirect" and ins.src.autoinc:
            return False
        if self._repeat_dst_alias_addr(ins):
            return False
        if ins.src.kind == "imm":
            return True
        if ins.src.kind != "reg":
            return False
        return not (ins.dst.kind == "reg" and ins.dst.reg == ins.src.reg)

    def _can_fold_immediate_repeat_self_add(self, ins: Decoded) -> bool:
        return (
            ins.rpt_count is not None
            and ins.mnemonic in ("add", "adda")
            and ins.src is not None
            and ins.dst is not None
            and ins.src.kind == "reg"
            and ins.dst.kind == "reg"
            and ins.src.reg == ins.dst.reg
            and ins.dst.reg not in (0, 2, 3)
        )

    def _can_fold_repeat_reg_sub(self, ins: Decoded) -> bool:
        if ins.mnemonic not in ("sub", "suba") or ins.src is None or ins.dst is None:
            return False
        if ins.src.kind == "indirect" and ins.src.autoinc:
            return False
        if self._repeat_dst_alias_addr(ins):
            return False
        if ins.src.kind == "imm":
            return True
        if ins.src.kind != "reg":
            return False
        return not (ins.dst.kind == "reg" and ins.dst.reg == ins.src.reg)

    def _can_fold_repeat_reg_carry_chain(self, ins: Decoded) -> bool:
        if ins.mnemonic not in ("addc", "subc") or ins.src is None or ins.dst is None:
            return False
        # ZC forces carry-in to zero for every repetition.  The compact SUBC
        # intrinsic models a normal carry chain, so preserve ZC exactly with
        # the existing unrolled/dynamic-loop path instead.
        if ins.mnemonic == "subc" and ins.subc_zero_carry:
            return False
        if ins.src.kind == "reg" and ins.src.reg == 2:
            return False
        if ins.dst.kind == "reg" and ins.dst.reg in (2, 3):
            return False
        if ins.src.kind == "indirect" and ins.src.autoinc:
            return False
        if self._repeat_dst_alias_addr(ins):
            return False
        if ins.src.kind == "imm":
            return True
        if ins.src.kind != "reg":
            return False
        return not (ins.dst.kind == "reg" and ins.dst.reg == ins.src.reg)

    def _can_fold_repeat_reg_dadd(self, ins: Decoded) -> bool:
        if ins.mnemonic != "dadd" or ins.src is None or ins.dst is None:
            return False
        if ins.src.kind == "indirect" and ins.src.autoinc:
            return False
        if self._repeat_dst_alias_addr(ins):
            return False
        if ins.src.kind == "imm":
            return True
        if ins.src.kind != "reg":
            return False
        return not (ins.dst.kind == "reg" and ins.dst.reg == ins.src.reg)

    def _can_fold_repeat_reg_xor(self, ins: Decoded) -> bool:
        if ins.mnemonic != "xor" or ins.src is None or ins.dst is None:
            return False
        if ins.dst.kind != "reg" or ins.dst.reg in (0, 2):
            return False
        if ins.src.kind == "imm":
            return True
        if ins.src.kind != "reg" or ins.src.reg in (0, 2):
            return False
        return ins.src.reg != ins.dst.reg

    def _can_fold_repeat_reg_idempotent(self, ins: Decoded) -> bool:
        if ins.mnemonic not in ("mov", "mova", "bit", "bic", "bis", "cmp", "cmpa", "and"):
            return False
        if ins.src is None or ins.dst is None:
            return False
        if self._repeat_dst_alias_addr(ins):
            return False
        if ins.dst.kind != "reg" or ins.dst.reg in (0, 2):
            return False
        if ins.src.kind == "imm":
            return True
        return ins.src.kind == "reg" and ins.src.reg not in (0, 2)

    def _rpt_add_expr_and_flags(self, il, size: int, lhs, rhs, count):
        suffix = "20" if size == 4 else "w" if size == 2 else "b"
        value_temp = LLIL_TEMP(48)
        carry_temp = LLIL_TEMP(49)
        overflow_temp = LLIL_TEMP(50)
        il.append(il.intrinsic([value_temp, carry_temp, overflow_temp], f"rpt_add{suffix}", [lhs, rhs, count]))
        return il.reg(size, value_temp), il.reg(1, carry_temp), il.reg(1, overflow_temp)

    def _rpt_selfadd_expr_and_flags(self, il, size: int, value, count):
        suffix = "20" if size == 4 else "w" if size == 2 else "b"
        value_temp = LLIL_TEMP(48)
        carry_temp = LLIL_TEMP(49)
        overflow_temp = LLIL_TEMP(50)
        il.append(il.intrinsic([value_temp, carry_temp, overflow_temp], f"rpt_selfadd{suffix}", [value, count]))
        return il.reg(size, value_temp), il.reg(1, carry_temp), il.reg(1, overflow_temp)

    def _rpt_sub_expr_and_flags(self, il, size: int, lhs, rhs, count):
        suffix = "20" if size == 4 else "w" if size == 2 else "b"
        value_temp = LLIL_TEMP(48)
        carry_temp = LLIL_TEMP(49)
        overflow_temp = LLIL_TEMP(50)
        il.append(il.intrinsic([value_temp, carry_temp, overflow_temp], f"rpt_sub{suffix}", [lhs, rhs, count]))
        return il.reg(size, value_temp), il.reg(1, carry_temp), il.reg(1, overflow_temp)

    def _rpt_xor_expr_and_flags(self, il, size: int, lhs, rhs, count):
        suffix = "20" if size == 4 else "w" if size == 2 else "b"
        value_temp = LLIL_TEMP(48)
        carry_temp = LLIL_TEMP(49)
        overflow_temp = LLIL_TEMP(50)
        il.append(il.intrinsic([value_temp, carry_temp, overflow_temp], f"rpt_xor{suffix}", [lhs, rhs, count]))
        return il.reg(size, value_temp), il.reg(1, carry_temp), il.reg(1, overflow_temp)

    def _rpt_carry_chain_expr_and_flags(self, il, mnemonic: str, size: int, lhs, rhs, count):
        suffix = "20" if size == 4 else "w" if size == 2 else "b"
        value_temp = LLIL_TEMP(48)
        carry_temp = LLIL_TEMP(49)
        overflow_temp = LLIL_TEMP(50)
        il.append(
            il.intrinsic(
                [value_temp, carry_temp, overflow_temp],
                f"rpt_{mnemonic}{suffix}",
                [lhs, rhs, count, il.flag("c")],
            )
        )
        return il.reg(size, value_temp), il.reg(1, carry_temp), il.reg(1, overflow_temp)

    def _rpt_dadd_expr_and_carry(self, il, size: int, lhs, rhs, count):
        suffix = "20" if size == 4 else "w" if size == 2 else "b"
        value_temp = LLIL_TEMP(48)
        carry_temp = LLIL_TEMP(49)
        il.append(
            il.intrinsic(
                [value_temp, carry_temp],
                f"rpt_dadd{suffix}",
                [lhs, rhs, count, il.zero_extend(1, il.flag("c"))],
            )
        )
        carry = il.compare_not_equal(1, il.reg(1, carry_temp), il.const(1, 0))
        return il.reg(size, value_temp), carry

    def _repeat_count_value(self, il, ins: Decoded, count=None):
        if count is not None:
            return count
        return self._temp_value(il, 4, 21, self._repeat_reg_count_expr(il, ins))

    def _lift_repeat_reg_add(self, il, ins: Decoded, size: int, count=None) -> None:
        src, dst, dst_write_addr = self._read_repeated_double_operands(il, ins, size)
        count = self._repeat_count_value(il, ins, count)
        value, carry, overflow = self._rpt_add_expr_and_flags(il, size, dst, src, count)
        self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)
        self._set_nz(il, size, value, masked=True)
        self._set_flag(il, "c", carry)
        self._set_flag(il, "v", overflow)

    def _lift_immediate_repeat_self_add(self, il, ins: Decoded, size: int) -> None:
        src = self._read_operand(il, ins.src, size)
        count = il.const(4, ins.rpt_count or 1)
        value, carry, overflow = self._rpt_selfadd_expr_and_flags(il, size, src, count)
        self._write_operand(il, ins.dst, size, value)
        self._set_nz(il, size, value, masked=True)
        self._set_flag(il, "c", carry)
        self._set_flag(il, "v", overflow)

    def _lift_repeat_reg_sub(self, il, ins: Decoded, size: int, count=None) -> None:
        src, dst, dst_write_addr = self._read_repeated_double_operands(il, ins, size)
        count = self._repeat_count_value(il, ins, count)
        value, carry, overflow = self._rpt_sub_expr_and_flags(il, size, dst, src, count)
        self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)
        self._set_nz(il, size, value, masked=True)
        self._set_flag(il, "c", carry)
        self._set_flag(il, "v", overflow)

    def _lift_repeat_reg_xor(self, il, ins: Decoded, size: int, count=None) -> None:
        src, dst, _ = self._read_repeated_double_operands(il, ins, size)
        count = self._repeat_count_value(il, ins, count)
        value, carry, overflow = self._rpt_xor_expr_and_flags(il, size, dst, src, count)
        self._write_operand(il, ins.dst, size, value)
        self._set_nz(il, size, value, masked=True)
        self._set_flag(il, "c", carry)
        self._set_flag(il, "v", overflow)

    def _lift_repeat_reg_carry_chain(self, il, ins: Decoded, size: int, count=None) -> None:
        src, dst, dst_write_addr = self._read_repeated_double_operands(il, ins, size)
        count = self._repeat_count_value(il, ins, count)
        value, carry, overflow = self._rpt_carry_chain_expr_and_flags(il, ins.mnemonic, size, dst, src, count)
        self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)
        self._set_nz(il, size, value, masked=True)
        self._set_flag(il, "c", carry)
        self._set_flag(il, "v", overflow)

    def _lift_repeat_reg_dadd(self, il, ins: Decoded, size: int, count=None) -> None:
        src, dst, dst_write_addr = self._read_repeated_double_operands(il, ins, size)
        count = self._repeat_count_value(il, ins, count)
        value, carry = self._rpt_dadd_expr_and_carry(il, size, dst, src, count)
        self._write_operand(il, ins.dst, size, value, write_addr=dst_write_addr)
        self._set_nz(il, size, value, masked=True)
        self._set_flag(il, "c", carry)

    def _lift_repeated_double_operation(self, il, ins: Decoded, size: int) -> None:
        """Lift repeated double-operand forms without duplicating side effects."""

        if (
            ins.src is None
            or ins.dst is None
            or not supports_repeat_prefix(ins.src, ins.dst)
            or (ins.dst.reg == 0 and ins.mnemonic not in ("cmp", "cmpa", "bit"))
        ):
            il.append(il.unimplemented())
            return

        flag_chain_ops = {"addc", "subc", "dadd"}
        if ins.rpt_reg is not None:
            if self._can_fold_repeat_reg_add(ins):
                self._lift_repeat_reg_add(il, ins, size)
                return
            if self._can_fold_repeat_reg_sub(ins):
                self._lift_repeat_reg_sub(il, ins, size)
                return
            if self._can_fold_repeat_reg_xor(ins):
                self._lift_repeat_reg_xor(il, ins, size)
                return
            if self._can_fold_repeat_reg_carry_chain(ins):
                self._lift_repeat_reg_carry_chain(il, ins, size)
                return
            if self._can_fold_repeat_reg_dadd(ins):
                self._lift_repeat_reg_dadd(il, ins, size)
                return
            if self._can_fold_repeat_reg_idempotent(ins):
                src, dst, _ = self._read_repeated_double_operands(il, ins, size)
                if not self._lift_double_once(il, ins, size, src, dst, update_flags=True):
                    il.append(il.unimplemented())
                return

            def body() -> None:
                src, dst, dst_write_addr = self._read_repeated_double_operands(il, ins, size)
                if not self._lift_double_once(
                    il, ins, size, src, dst, update_flags=True, dst_write_addr=dst_write_addr
                ):
                    il.append(il.unimplemented())

            self._lift_repeat_reg_loop(il, ins, body)
            return

        repeat_count = ins.rpt_count or 1
        if self._can_fold_immediate_repeat_self_add(ins):
            self._lift_immediate_repeat_self_add(il, ins, size)
            return

        if repeat_count > 1 and not (ins.dst.kind == "reg" and ins.dst.reg in (0, 2)):
            count = il.const(4, repeat_count)
            if self._can_fold_repeat_reg_add(ins):
                self._lift_repeat_reg_add(il, ins, size, count=count)
                return
            if self._can_fold_repeat_reg_sub(ins):
                self._lift_repeat_reg_sub(il, ins, size, count=count)
                return
            if self._can_fold_repeat_reg_xor(ins):
                self._lift_repeat_reg_xor(il, ins, size, count=count)
                return
            if self._can_fold_repeat_reg_carry_chain(ins):
                self._lift_repeat_reg_carry_chain(il, ins, size, count=count)
                return
            if self._can_fold_repeat_reg_dadd(ins):
                self._lift_repeat_reg_dadd(il, ins, size, count=count)
                return
            if self._can_fold_repeat_reg_idempotent(ins):
                src, dst, _ = self._read_repeated_double_operands(il, ins, size)
                if not self._lift_double_once(il, ins, size, src, dst, update_flags=True):
                    il.append(il.unimplemented())
                return

        for iteration in range(repeat_count):
            src, dst, dst_write_addr = self._read_repeated_double_operands(il, ins, size)
            update_flags = ins.mnemonic in flag_chain_ops or iteration == repeat_count - 1
            if not self._lift_double_once(
                il, ins, size, src, dst, update_flags=update_flags, dst_write_addr=dst_write_addr
            ):
                il.append(il.unimplemented())
                return

    def _lift_multi(self, il, ins: Decoded) -> None:
        """Lift multi-register instructions and readability pseudo-instructions.

        PUSHM.A and POPM.A consume four bytes per 20-bit register; PUSHM.W and
        POPM.W consume two bytes and clear a restored register's upper nibble.
        If a register list reaches R2, the register helpers also synchronize
        the explicitly modeled C, Z, N, and V flags with SR.
        """

        if ins.mnemonic == "brajt.a":
            for mnemonic, count in (("rlam.a", 4), ("rram.a", 2)):
                shift = Decoded(ins.word)
                shift.fmt = "multi"
                shift.mnemonic = mnemonic
                shift.src = Operand("imm", value=count, text=f"#{count}")
                shift.dst = ins.src
                shift.size = 4
                self._lift_compact_shift(il, shift)

            table_addr = il.add(4, il.const(4, ins.imm), self._reg(il, ins.src.reg))
            il.set_indirect_branches([(self, target) for target in ins.targets])
            il.append(il.jump(self._load_from_addr(il, 4, table_addr, 37)))
            return

        if ins.mnemonic == "idx6.w":
            src = self._temp_value(il, 2, 25, self._reg_value(il, ins.src.reg, 2))
            value = self._idx6_word_expr(il, il.zero_extend(4, src))
            self._write_reg_value(il, 13, 2, il.shift_left(2, src, il.const(2, 1)))
            self._write_reg_value(il, 14, 4, il.zero_extend(4, self._bit_flag_expr(il, 2, src, bits_for_size(2) - 1)))
            self._write_reg_value(il, 15, 2, il.low_part(2, value))
            self._write_operand(il, ins.dst, 4, value)
            return

        if ins.mnemonic == "ld20.w":
            base = self._temp_value(il, 4, 33, self._reg(il, ins.src.reg))
            low = self._temp_value(il, 2, 34, il.load(2, base))
            high = self._temp_value(il, 2, 35, il.load(2, il.add(4, base, il.const(4, 2))))
            value = self._wordpair20_expr(il, il.zero_extend(4, low), il.zero_extend(4, high))
            self._write_reg_value(il, ins.imm, 2, low)
            self._write_operand(il, ins.dst, 4, value)
            self._write_reg_value(il, ins.src.reg, 4, il.add(4, base, il.const(4, 4)))
            self._set_logic_flags(il, 4, value, masked=True)
            return

        if ins.mnemonic == "lsr32.w":
            low = self._temp_value(il, 2, 41, self._reg_value(il, 12, 2))
            high = self._temp_value(il, 2, 42, self._reg_value(il, 13, 2))
            combined = il.or_expr(
                4,
                il.zero_extend(4, low),
                il.shift_left(4, il.zero_extend(4, high), il.const(4, 16)),
            )
            value = self._lsr32_wordpair_expr(il, il.zero_extend(4, low), il.zero_extend(4, high), ins.imm)
            low_value = il.low_part(2, value)
            high_value = il.low_part(2, il.logical_shift_right(4, value, il.const(4, 16)))
            self._write_reg_value(il, 12, 2, low_value)
            self._write_reg_value(il, 13, 2, high_value)
            self._set_nz(il, 2, low_value, masked=True)
            self._set_flag(il, "c", self._bit_flag_expr(il, 4, combined, ins.imm - 1))
            self._set_flag(il, "v", il.const(0, 0))
            return

        if ins.mnemonic == "lsl32.w":
            low = self._temp_value(il, 2, 44, self._reg_value(il, 12, 2))
            high = self._temp_value(il, 2, 45, self._reg_value(il, 13, 2))
            combined = il.or_expr(
                4,
                il.zero_extend(4, low),
                il.shift_left(4, il.zero_extend(4, high), il.const(4, 16)),
            )
            value = self._lsl32_wordpair_expr(il, il.zero_extend(4, low), il.zero_extend(4, high), ins.imm)
            low_value = il.low_part(2, value)
            high_value = il.low_part(2, il.logical_shift_right(4, value, il.const(4, 16)))
            self._write_reg_value(il, 12, 2, low_value)
            self._write_reg_value(il, 13, 2, high_value)
            self._set_nz(il, 2, high_value, masked=True)
            self._set_flag(il, "c", self._bit_flag_expr(il, 4, combined, 32 - ins.imm))
            self._set_flag(
                il,
                "v",
                il.compare_not_equal(
                    0,
                    self._bit_flag_expr(il, 4, combined, 32 - ins.imm),
                    self._bit_flag_expr(il, 4, combined, 31 - ins.imm),
                ),
            )
            return

        if ins.mnemonic == "msbmask.w":
            src = self._reg_value(il, ins.src.reg, 2)
            value = self._msbmask_word_expr(il, src)
            self._write_reg_value(il, ins.imm, 4, self._reg(il, ins.src.reg))
            self._write_reg_value(il, ins.dst.reg, 2, value)
            self._set_nz(il, 2, value, masked=True)
            self._set_flag(il, "c", il.compare_not_equal(2, value, il.const(2, 0)))
            self._set_flag(il, "v", il.compare_equal(2, value, il.const(2, 0)))
            return

        if ins.mnemonic == "advptr20.w":
            offset = self._sext20_word_expr(il, il.zero_extend(4, self._reg_value(il, ins.imm, 2)))
            advanced_base = self._temp_value(il, 4, 36, il.add(4, self._reg(il, ins.src.reg), offset))
            aligned = self._align2_20_expr(il, il.add(4, advanced_base, il.const(4, 1)))
            self._write_reg_value(il, ins.imm, 4, offset)
            self._write_reg_value(il, ins.src.reg, 4, advanced_base)
            self._write_operand(il, ins.dst, 4, aligned)
            self._set_logic_flags(il, 4, aligned, masked=True)
            return

        if ins.mnemonic == "sxtidx6.w":
            src = self._temp_value(il, 2, 25, self._reg_value(il, ins.src.reg, 2))
            value = self._sxtidx6_word_expr(il, il.zero_extend(4, src), ins.imm)
            self._set_nz(il, 4, value, masked=True)
            self._set_flag(il, "c", il.const(0, 0))
            self._set_flag(il, "v", il.const(0, 0))
            self._write_reg_value(il, ins.src.reg, 2, il.shift_left(2, src, il.const(2, 1)))
            self._write_operand(il, ins.dst, 4, value)
            return

        if ins.mnemonic == "sext20.w":
            src = il.zero_extend(4, self._reg_value(il, ins.dst.reg, 2))
            value = self._sext20_word_expr(il, src)
            self._write_operand(il, ins.dst, 4, value)
            self._set_nz(il, 4, value, masked=True)
            self._set_flag(il, "c", il.const(0, 0))
            self._set_flag(il, "v", il.const(0, 0))
            return

        if any(ins.mnemonic.startswith(f"{op}.") for op in COMPACT_SHIFT_OPS.values()):
            self._lift_compact_shift(il, ins)
            return

        count = ins.src.value
        size = ins.size

        if ins.mnemonic.startswith("pushm"):
            for i in range(count):
                reg = (ins.dst.reg - i) & 0xF
                il.append(il.push(size, self._reg_value(il, reg, size)))
            return

        if ins.mnemonic.startswith("popm"):
            start = (ins.dst.reg - count + 1) & 0xF
            for i in range(count):
                reg = (start + i) & 0xF
                value = il.pop(size)
                self._write_reg_value(il, reg, size, value)
            return

        il.append(il.unimplemented())

    def get_instruction_low_level_il(self, data: bytes, addr: int, il) -> Optional[int]:
        """Lift one instruction into Binary Ninja LLIL and return its byte length."""

        ins = decode(data, addr)
        if ins is None:
            return None

        if ins.fmt == "jump":
            self._lift_jump(il, ins, addr)
            return ins.length

        if ins.fmt == "cpux":
            il.append(il.unimplemented())
            return ins.length

        if ins.fmt == "multi":
            self._lift_multi(il, ins)
            return ins.length

        size = ins.size

        if ins.fmt == "single":
            if ins.mnemonic == "reti":
                self._lift_reti(il)
                return ins.length

            if ins.mnemonic == "reta":
                self._lift_reta(il)
                return ins.length

            if ins.src is None:
                il.append(il.unimplemented())
                return ins.length

            if ins.mnemonic in ("rrcx", "rrax", "rrux"):
                if ins.rpt_reg is not None:
                    self._lift_repeat_reg_cpux_right_shift(il, ins)
                    return ins.length

                write_addr = None
                temp_base = 0
                if ins.src.kind == "indirect" and ins.src.autoinc:
                    if ins.rpt_count is not None:
                        for _ in range(ins.rpt_count):
                            temp_base = 15
                            write_addr = il.reg(4, LLIL_TEMP(temp_base))
                            src = self._read_operand(il, ins.src, size, temp_base=temp_base)
                            self._lift_cpux_right_shift(il, ins, src, write_addr=write_addr, repeat_count=1)
                        return ins.length
                    temp_base = 15
                    write_addr = il.reg(4, LLIL_TEMP(temp_base))
                src = self._read_operand(il, ins.src, size, temp_base=temp_base)
                self._lift_cpux_right_shift(il, ins, src, write_addr=write_addr)
            elif ins.mnemonic == "rrc":
                src = self._read_operand(il, ins.src, size)
                old_c = il.flag("c")
                new_c = il.compare_not_equal(size, il.and_expr(size, src, il.const(size, 1)), il.const(size, 0))
                wide = il.rotate_right_carry(size, src, il.const(size, 1), old_c)
                self._set_nz(il, size, wide)
                self._set_flag(il, "c", new_c)
                self._set_flag(il, "v", il.const(0, 0))
                self._write_operand(il, ins.dst, size, wide)
            elif ins.mnemonic == "swpb":
                src = self._read_operand(il, ins.src, size)
                if size == 4:
                    value = self._swpb20_expr(il, src)
                    self._write_operand(il, ins.dst, 4, value)
                else:
                    value = self._swpb_word_expr(il, src)
                    self._write_operand(il, ins.dst, 2, value)
            elif ins.mnemonic == "rra":
                src = self._read_operand(il, ins.src, size)
                self._set_flag(
                    il,
                    "c",
                    il.compare_not_equal(size, il.and_expr(size, src, il.const(size, 1)), il.const(size, 0)),
                )
                value = il.arith_shift_right(size, src, il.const(size, 1))
                self._set_nz(il, size, value)
                self._set_flag(il, "v", il.const(0, 0))
                self._write_operand(il, ins.dst, size, value)
            elif ins.mnemonic == "sxt":
                src = self._read_operand(il, ins.src, size)
                if ins.dst.kind == "reg" or size == 4:
                    value = self._sxt_20_expr(il, src)
                    self._set_logic_flags(il, 4, value, masked=True)
                    self._write_operand(il, ins.dst, 4, value)
                else:
                    value = il.sign_extend(2, il.low_part(1, src))
                    self._set_logic_flags(il, 2, value)
                    self._write_operand(il, ins.dst, 2, value)
            elif ins.mnemonic == "push":
                if is_pushx_alias(ins) and size in (2, 4) and ins.src.kind == "reg":
                    il.append(il.push(size, self._reg_value(il, ins.src.reg, size)))
                else:
                    src = self._read_operand(il, ins.src, size)
                    self._push_stack(il, size, src)
            elif ins.mnemonic in ("call", "calla"):
                src = self._read_operand(il, ins.src, size)
                target = src if size == 4 else il.zero_extend(4, src)
                il.append(il.call_stack_adjust(target, 0))
            else:
                il.append(il.unimplemented())
            return ins.length

        if ins.fmt == "double":
            if ins.src is None or ins.dst is None:
                il.append(il.unimplemented())
                return ins.length

            if ins.rpt_count is not None:
                self._lift_repeated_double_operation(il, ins, size)
                return ins.length

            if ins.rpt_reg is not None:
                self._lift_repeated_double_operation(il, ins, size)
                return ins.length

            op = ins.mnemonic
            if is_popx_alias(ins) and size in (2, 4) and ins.dst.kind == "reg":
                self._write_reg_value(il, ins.dst.reg, size, il.pop(size))
                return ins.length

            if is_ret_alias(ins):
                il.append(il.ret(il.zero_extend(4, il.pop(2))))
                return ins.length

            src = self._read_operand(il, ins.src, size)

            if (
                op in ("mov", "mova")
                and ins.dst.kind == "reg"
                and ins.dst.reg == 0
                and ins.src.kind == "indirect"
                and ins.src.reg == 1
                and ins.src.autoinc
            ):
                target = src if size == 4 else il.zero_extend(4, src)
                il.append(il.ret(self._mask_expr(il, 4, target)))
                return ins.length

            dst = None if op in ("mov", "mova") else self._read_operand(il, ins.dst, size, temp_base=2)
            if not self._lift_double_once(il, ins, size, src, dst):
                il.append(il.unimplemented())
            return ins.length

        il.append(il.unimplemented())
        return ins.length


def _ensure_msp430x_calling_convention(arch: Architecture) -> None:
    """Attach the plugin convention across supported Binary Ninja API versions."""

    # Binary Ninja collections have changed across releases. Registration is
    # best-effort so a convention API difference cannot disable the decoder.
    try:
        cc = arch.calling_conventions.get("default")
    except Exception:
        cc = None

    if cc is None:
        try:
            cc = MSP430XCallingConvention(arch, "default")
            arch.register_calling_convention(cc)
        except Exception:
            return

    try:
        arch.default_calling_convention = cc
        arch.cdecl_calling_convention = cc
    except Exception:
        pass

    try:
        platform = arch.standalone_platform
        platform.register_calling_convention(cc)
        platform.default_calling_convention = cc
        platform.cdecl_calling_convention = cc
    except Exception:
        pass


def register_msp430x_architecture() -> Architecture:
    """Register the architecture once and return the active instance."""

    try:
        arch = Architecture["msp430x"]
    except Exception:
        MSP430XArchitecture.register()
        arch = Architecture["msp430x"]
    _ensure_msp430x_calling_convention(arch)
    return arch


register_msp430x_architecture()
