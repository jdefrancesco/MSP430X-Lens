"""MSP430F5438/F5438A raw-firmware BinaryView and analysis helpers. Note ELF works as well."""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import json
import os
import re
from typing import Iterable, Optional, Sequence

from binaryninja import (
    Architecture,
    BinaryView,
    BinaryViewType,
    Endianness,
    PluginCommand,
    SectionSemantics,
    SegmentFlag,
    Settings,
    Symbol,
    SymbolType,
    Type,
    core_version,
    log_info,
    log_warn,
)

# TODO(multi-device): These globals are the default MSP430F5438/F5438A device
# profile. ``DeviceSpec`` already groups variant-specific data, but some loader
# and analysis heuristics still consume these module-level aliases directly.
# Before supporting additional MSP430X devices, make the variant and every
# address range below selectable through a device configuration/profile and
# migrate those remaining consumers away from global constants.
DEVICE_VARIANT = "MSP430F5438"

PERIPHERALS_START = 0x000000
PERIPHERALS_END = 0x000FFF
BSL_START = 0x001000
BSL_END = 0x0017FF
INFO_START = 0x001800
INFO_END = 0x0019FF
TLV_START = 0x001A00
TLV_END = 0x001AFF
FACTORY_BOOT_START = 0x001B00
FACTORY_BOOT_END = 0x001BFF
RAM_START = 0x001C00
RAM_END = 0x005BFF
FLASH_START = 0x005C00
FLASH_END = 0x045BFF
VECTOR_START = 0x00FF80
VECTOR_END = 0x00FFFF
RESET_VECTOR = 0x00FFFE

DEVICE_END = FLASH_END + 1
FLASH_SIZE = FLASH_END - FLASH_START + 1
RAM_SIZE = RAM_END - RAM_START + 1
STACK_TOP = RAM_END
_REGISTERED_PLATFORM_RECOGNIZER = False


@dataclass(frozen=True, slots=True)
class Region:
    """Inclusive device address range and its Binary Ninja mapping policy."""

    name: str
    start: int
    end: int
    flags: SegmentFlag
    semantics: SectionSemantics
    kind: str = ""

    @property
    def length(self) -> int:
        return self.end - self.start + 1


AddressSpan = tuple[int, int]
SymbolDefinition = tuple[str, int]
VectorDefinition = tuple[int, str, str]
AddressJumpTable = tuple[int, int, tuple[int, ...]]
CinitRecordInfo = tuple[int, int, int]
CinitRecord = tuple[int, int, int, int]
CinitCandidate = tuple[int, int, tuple[CinitRecord, ...]]
CpuxFallback = tuple[int, str, str, bytes]


@dataclass(frozen=True, slots=True)
class DeviceSpec:
    """Memory layout, symbols, and vectors for one supported MCU variant."""

    name: str
    aliases: tuple[str, ...]
    ram_start: int
    ram_end: int
    flash_start: int
    flash_end: int
    vector_start: int
    vector_end: int
    reset_vector: int
    regions: tuple[Region, ...]
    symbols: tuple[SymbolDefinition, ...]
    vector_names: tuple[VectorDefinition, ...]

    @property
    def device_end(self) -> int:
        return self.flash_end + 1

    @property
    def flash_size(self) -> int:
        return self.flash_end - self.flash_start + 1

    @property
    def ram_size(self) -> int:
        return self.ram_end - self.ram_start + 1

    @property
    def stack_top(self) -> int:
        return self.ram_end


READ_ONLY_CODE = (
    SegmentFlag.SegmentReadable
    | SegmentFlag.SegmentExecutable
    | SegmentFlag.SegmentContainsCode
    | SegmentFlag.SegmentContainsData
    | SegmentFlag.SegmentDenyWrite
)
READ_ONLY_DATA = (
    SegmentFlag.SegmentReadable
    | SegmentFlag.SegmentContainsData
    | SegmentFlag.SegmentDenyWrite
    | SegmentFlag.SegmentDenyExecute
)
READ_WRITE_DATA = (
    SegmentFlag.SegmentReadable
    | SegmentFlag.SegmentWritable
    | SegmentFlag.SegmentContainsData
    | SegmentFlag.SegmentDenyExecute
)

ERASED_FLASH_MIN_RUN = 32
ERASED_FUNCTION_MIN_BYTES = 8
ASCII_STRING_MIN_LEN = 5
ASCII_STRING_PADDING_MAX_LEN = 4
ASCII_STRING_CLUSTER_MAX_GAP = 0x80
BYTE_LOOKUP_TABLE_MIN_LEN = 16
WORD_LOOKUP_TABLE_MIN_WORDS = 10
ADDRESS_JUMP_TABLE_MIN_ENTRIES = 3
ADDRESS_JUMP_TABLE_MAX_ENTRIES = 64
CINIT_RECORD_HEADER_SIZE = 6
CINIT_TABLE_MIN_RECORDS = 4
CINIT_RECORD_MAX_PAYLOAD = 0x1000
CINIT_TABLE_PADDING_MAX_LEN = 4
MSP430_HEADER_PATHS_ENV = "MSP430_HEADER_PATHS"
LOCAL_MSP430_HEADER_CANDIDATES = (
    "msp430.h",
    "msp430f5438.h",
    "msp430f5438a.h",
    "msp430x54x.h",
)

DEFINE_RE = re.compile(r"^\s*#define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+?)\s*(?://.*)?$")
SFR_RE = re.compile(r"^\s*(?:const_)?sfr[wb]\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([^)]+?)\s*\)\s*;")
VECTOR_COMMENT_RE = re.compile(r"/\*\s*(0x[0-9A-Fa-f]+)")
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
NUMBER_RE = re.compile(r"^(?:0x[0-9A-Fa-f]+|\d+)$")


MAP_REGIONS: tuple[Region, ...] = (
    Region(
        ".peripherals",
        PERIPHERALS_START,
        PERIPHERALS_END,
        READ_WRITE_DATA,
        SectionSemantics.ReadWriteDataSectionSemantics,
    ),
    Region(
        ".bsl0",
        0x001000,
        0x0011FF,
        READ_ONLY_CODE,
        SectionSemantics.ReadOnlyCodeSectionSemantics,
    ),
    Region(
        ".bsl1",
        0x001200,
        0x0013FF,
        READ_ONLY_CODE,
        SectionSemantics.ReadOnlyCodeSectionSemantics,
    ),
    Region(
        ".bsl2",
        0x001400,
        0x0015FF,
        READ_ONLY_CODE,
        SectionSemantics.ReadOnlyCodeSectionSemantics,
    ),
    Region(
        ".bsl3",
        0x001600,
        0x0017FF,
        READ_ONLY_CODE,
        SectionSemantics.ReadOnlyCodeSectionSemantics,
    ),
    Region(
        ".info_d",
        0x001800,
        0x00187F,
        READ_ONLY_DATA,
        SectionSemantics.ReadOnlyDataSectionSemantics,
    ),
    Region(
        ".info_c",
        0x001880,
        0x0018FF,
        READ_ONLY_DATA,
        SectionSemantics.ReadOnlyDataSectionSemantics,
    ),
    Region(
        ".info_b",
        0x001900,
        0x00197F,
        READ_ONLY_DATA,
        SectionSemantics.ReadOnlyDataSectionSemantics,
    ),
    Region(
        ".info_a",
        0x001980,
        0x0019FF,
        READ_ONLY_DATA,
        SectionSemantics.ReadOnlyDataSectionSemantics,
    ),
    Region(
        ".tlv_device_descriptors",
        TLV_START,
        TLV_END,
        READ_ONLY_DATA,
        SectionSemantics.ReadOnlyDataSectionSemantics,
    ),
    Region(
        ".ram_sector0",
        0x001C00,
        0x002BFF,
        READ_WRITE_DATA,
        SectionSemantics.ReadWriteDataSectionSemantics,
    ),
    Region(
        ".ram_sector1",
        0x002C00,
        0x003BFF,
        READ_WRITE_DATA,
        SectionSemantics.ReadWriteDataSectionSemantics,
    ),
    Region(
        ".ram_sector2",
        0x003C00,
        0x004BFF,
        READ_WRITE_DATA,
        SectionSemantics.ReadWriteDataSectionSemantics,
    ),
    Region(
        ".ram_sector3",
        0x004C00,
        0x005BFF,
        READ_WRITE_DATA,
        SectionSemantics.ReadWriteDataSectionSemantics,
    ),
    Region(
        ".flash_bank_a_low",
        0x005C00,
        0x00FF7F,
        READ_ONLY_CODE,
        SectionSemantics.ReadOnlyCodeSectionSemantics,
        "flash",
    ),
    Region(
        ".vectors",
        VECTOR_START,
        VECTOR_END,
        READ_ONLY_DATA,
        SectionSemantics.ReadOnlyDataSectionSemantics,
        "flash",
    ),
    Region(
        ".flash_bank_b",
        0x010000,
        0x01FFFF,
        READ_ONLY_CODE,
        SectionSemantics.ReadOnlyCodeSectionSemantics,
        "flash",
    ),
    Region(
        ".flash_bank_c",
        0x020000,
        0x02FFFF,
        READ_ONLY_CODE,
        SectionSemantics.ReadOnlyCodeSectionSemantics,
        "flash",
    ),
    Region(
        ".flash_bank_d",
        0x030000,
        0x03FFFF,
        READ_ONLY_CODE,
        SectionSemantics.ReadOnlyCodeSectionSemantics,
        "flash",
    ),
    Region(
        ".flash_bank_a_high",
        0x040000,
        FLASH_END,
        READ_ONLY_CODE,
        SectionSemantics.ReadOnlyCodeSectionSemantics,
        "flash",
    ),
)

LEGACY_F5438_ONLY_REGIONS: tuple[Region, ...] = (
    Region(
        ".factory_bootcode",
        FACTORY_BOOT_START,
        FACTORY_BOOT_END,
        READ_ONLY_CODE,
        SectionSemantics.ReadOnlyCodeSectionSemantics,
    ),
)

SYMBOLS: tuple[SymbolDefinition, ...] = (
    ("__msp430f5438_peripherals_start", PERIPHERALS_START),
    ("__msp430f5438_bsl_start", BSL_START),
    ("__msp430f5438_info_start", INFO_START),
    ("__msp430f5438_tlv_start", TLV_START),
    ("__msp430f5438_ram_start", RAM_START),
    ("__msp430f5438_ram_end", RAM_END),
    ("__msp430f5438_stack_top", STACK_TOP),
    ("__msp430f5438_flash_start", FLASH_START),
    ("__msp430f5438_vectors", VECTOR_START),
    ("__msp430f5438_reset_vector", RESET_VECTOR),
    ("__msp430f5438_flash_end", FLASH_END),
)
BOUNDARY_SYMBOL_NAMES = frozenset(name for name, _ in SYMBOLS)

VECTOR_NAMES: tuple[VectorDefinition, ...] = (
    (0xFFFE, "reset", "reset_handler"),
    (0xFFFC, "sys_nmi", "isr_sys_nmi"),
    (0xFFFA, "user_nmi", "isr_user_nmi"),
    (0xFFF8, "tb0_ccr0", "isr_tb0_ccr0"),
    (0xFFF6, "tb0", "isr_tb0"),
    (0xFFF4, "watchdog", "isr_watchdog"),
    (0xFFF2, "usci_a0", "isr_usci_a0"),
    (0xFFF0, "usci_b0", "isr_usci_b0"),
    (0xFFEE, "adc12", "isr_adc12"),
    (0xFFEC, "ta0_ccr0", "isr_ta0_ccr0"),
    (0xFFEA, "ta0", "isr_ta0"),
    (0xFFE8, "usci_a2", "isr_usci_a2"),
    (0xFFE6, "usci_b2", "isr_usci_b2"),
    (0xFFE4, "dma", "isr_dma"),
    (0xFFE2, "ta1_ccr0", "isr_ta1_ccr0"),
    (0xFFE0, "ta1", "isr_ta1"),
    (0xFFDE, "port1", "isr_port1"),
    (0xFFDC, "usci_a1", "isr_usci_a1"),
    (0xFFDA, "usci_b1", "isr_usci_b1"),
    (0xFFD8, "usci_a3", "isr_usci_a3"),
    (0xFFD6, "usci_b3", "isr_usci_b3"),
    (0xFFD4, "port2", "isr_port2"),
    (0xFFD2, "rtc", "isr_rtc"),
)


MSP430F5438_SPEC = DeviceSpec(
    name="MSP430F5438",
    aliases=("F5438",),
    ram_start=RAM_START,
    ram_end=RAM_END,
    flash_start=FLASH_START,
    flash_end=FLASH_END,
    vector_start=VECTOR_START,
    vector_end=VECTOR_END,
    reset_vector=RESET_VECTOR,
    regions=tuple(sorted(MAP_REGIONS + LEGACY_F5438_ONLY_REGIONS, key=lambda r: r.start)),
    symbols=SYMBOLS,
    vector_names=VECTOR_NAMES,
)

MSP430F5438A_SPEC = DeviceSpec(
    name="MSP430F5438A",
    aliases=("F5438A",),
    ram_start=RAM_START,
    ram_end=RAM_END,
    flash_start=FLASH_START,
    flash_end=FLASH_END,
    vector_start=VECTOR_START,
    vector_end=VECTOR_END,
    reset_vector=RESET_VECTOR,
    regions=tuple(sorted(MAP_REGIONS, key=lambda r: r.start)),
    symbols=SYMBOLS,
    vector_names=VECTOR_NAMES,
)

DEVICE_SPECS: tuple[DeviceSpec, ...] = (MSP430F5438_SPEC, MSP430F5438A_SPEC)
DEVICE_SPEC_BY_NAME = {spec.name: spec for spec in DEVICE_SPECS}
DEVICE_SPEC_ALIASES = {
    alias.upper(): spec.name
    for spec in DEVICE_SPECS
    for alias in (spec.name, *spec.aliases)
}
DEFAULT_DEVICE_SPEC = DEVICE_SPEC_BY_NAME[DEVICE_VARIANT]
ALL_KNOWN_MAP_REGIONS = tuple(sorted(MAP_REGIONS + LEGACY_F5438_ONLY_REGIONS, key=lambda r: r.start))


def _raw_length(bv: BinaryView) -> int:
    raw = getattr(getattr(bv, "file", None), "raw", None)
    for candidate in (raw, bv):
        if candidate is None:
            continue
        try:
            return len(candidate)
        except Exception:
            pass
    return max(0, getattr(bv, "end", 0) - getattr(bv, "start", 0))


def _remove_section(bv: BinaryView, name: str) -> None:
    for remover_name in ("remove_user_section", "remove_auto_section"):
        remover = getattr(bv, remover_name, None)
        if remover is None:
            continue
        try:
            remover(name)
        except Exception:
            pass


def _remove_segment_at(bv: BinaryView, addr: int, length: int = 0) -> None:
    for remover_name in ("remove_user_segment", "remove_auto_segment"):
        remover = getattr(bv, remover_name, None)
        if remover is None:
            continue
        try:
            remover(addr, length)
        except TypeError:
            try:
                remover(addr)
            except Exception:
                pass
        except Exception:
            pass


def _remove_previous_map(bv: BinaryView, regions: Iterable[Region]) -> None:
    for region in regions:
        for section_name in _matching_region_section_names(bv, region):
            _remove_section(bv, section_name)
        _remove_segments_in_range(bv, region.start, region.end + 1)


def _matching_region_section_names(bv: BinaryView, region: Region) -> tuple[str, ...]:
    prefix = f"{region.name}."
    return tuple(
        name
        for name in _section_names(bv)
        if name == region.name or name.startswith(prefix)
    )


def _remove_segments_in_range(bv: BinaryView, start: int, end: int) -> None:
    for seg in list(getattr(bv, "segments", [])):
        seg_start = getattr(seg, "start", None)
        seg_length = getattr(seg, "length", None)
        if seg_start is None or seg_length is None:
            continue
        seg_end = seg_start + seg_length
        if seg_start < end and seg_end > start:
            _remove_segment_at(bv, seg_start, seg_length)


def _remove_flat_raw_segment(bv: BinaryView, raw_len: int, image_base: int) -> None:
    raw_starts = {0, image_base}
    for seg in list(getattr(bv, "segments", [])):
        start = getattr(seg, "start", None)
        length = getattr(seg, "length", None)
        data_offset = getattr(seg, "data_offset", 0)
        if start is None or length is None:
            continue
        end = start + length
        looks_like_raw_loader_segment = (
            start in raw_starts
            and data_offset == 0
            and (length == raw_len or end > FLASH_START or length >= min(raw_len, 0x1000))
        )
        if looks_like_raw_loader_segment:
            _remove_segment_at(bv, start, length)


def _file_backing(
    start: int,
    length: int,
    raw_len: int,
    image_base: Optional[int],
) -> AddressSpan:
    """Return the file offset and backed length for a virtual address range."""

    if raw_len <= 0:
        return 0, 0

    if image_base is None:
        if raw_len >= DEVICE_END:
            image_base = 0
        else:
            image_base = FLASH_START

    data_start = max(start, image_base)
    data_end = min(start + length, image_base + raw_len)
    if data_start >= data_end:
        return 0, 0
    if data_start != start:
        return 0, 0
    return data_start - image_base, data_end - data_start


def _read_file_bytes(bv: BinaryView, data_offset: int, data_length: int) -> bytes:
    if data_length <= 0:
        return b""

    for candidate in (getattr(bv, "raw", None), getattr(getattr(bv, "file", None), "raw", None), bv):
        if candidate is None:
            continue
        try:
            data = candidate.read(data_offset, data_length)
            if len(data) == data_length:
                return bytes(data)
        except Exception:
            pass
    return b""


def _read_raw_u16(bv: BinaryView, data_offset: int) -> Optional[int]:
    data = _read_file_bytes(bv, data_offset, 2)
    if len(data) != 2:
        return None
    return data[0] | (data[1] << 8)


def _bytes_look_backed(data: bytes) -> bool:
    return bool(data) and not all(byte == 0xFF for byte in data) and not all(byte == 0x00 for byte in data)


def _is_probable_vector_target(addr: int) -> bool:
    return addr % 2 == 0 and FLASH_START <= addr < VECTOR_START


def _vector_table_base_score(bv: BinaryView, raw_len: int, image_base: int) -> int:
    """Score an image-base candidate by the plausibility of its vectors."""

    vector_offset = VECTOR_START - image_base
    reset_offset = RESET_VECTOR - image_base
    if vector_offset < 0 or reset_offset < 0 or reset_offset + 2 > raw_len:
        return -100000

    score = 0
    reset_target = _read_raw_u16(bv, reset_offset)
    if reset_target is None:
        return -100000

    if _is_probable_vector_target(reset_target):
        score += 80
        target_offset = reset_target - image_base
        if 0 <= target_offset < raw_len:
            target_bytes = _read_file_bytes(bv, target_offset, 8)
            score += 40 if _bytes_look_backed(target_bytes) else -32
    elif reset_target not in (0x0000, 0xFFFF):
        score -= 80

    valid_entries = 0
    bad_entries = 0
    for entry_offset in range(vector_offset, reset_offset + 1, 2):
        entry = _read_raw_u16(bv, entry_offset)
        if entry is None:
            score -= 4
        elif _is_probable_vector_target(entry):
            valid_entries += 1
            score += 2
        elif entry not in (0x0000, 0xFFFF):
            bad_entries += 1
            score -= 3

    if valid_entries >= 4:
        score += 20
    if bad_entries > 32:
        score -= 80
    return score


def _detect_image_base(bv: BinaryView, raw_len: int) -> int:
    """Choose the likely base for a full image or main-flash-only dump."""

    fallback = 0 if raw_len >= DEVICE_END else FLASH_START
    scores = [
        (_vector_table_base_score(bv, raw_len, candidate), candidate)
        for candidate in (0, FLASH_START)
    ]
    best_score, best_base = max(scores, key=lambda item: item[0])
    if best_score > 0:
        return best_base
    return fallback


def _has_probable_msp430_vector_table(bv: BinaryView, raw_len: int) -> bool:
    if not (0x80 <= raw_len <= DEVICE_END):
        return False
    return max(
        _vector_table_base_score(bv, raw_len, 0),
        _vector_table_base_score(bv, raw_len, FLASH_START),
    ) > 0


def _erased_spans(data: bytes, min_run: int = ERASED_FLASH_MIN_RUN) -> tuple[AddressSpan, ...]:
    # Long 0xff runs are erased flash, not tiny `and.b @r15+, -1(r15)`
    # functions. Mark them data before analysis so BN does not grow nonsense CFGs.
    spans = []
    start = None
    for idx, byte in enumerate(data):
        if byte == 0xFF:
            if start is None:
                start = idx
            continue

        if start is not None and idx - start >= min_run:
            spans.append((start, idx))
        start = None

    if start is not None and len(data) - start >= min_run:
        spans.append((start, len(data)))
    return tuple(spans)


def _add_region_chunk(
    bv: BinaryView,
    name: str,
    start: int,
    length: int,
    data_offset: int,
    data_length: int,
    flags: SegmentFlag,
    semantics: SectionSemantics,
    *,
    auto_defined: bool = False,
) -> None:
    if length <= 0:
        return

    add_segment = bv.add_auto_segment if auto_defined else bv.add_user_segment
    add_section = bv.add_auto_section if auto_defined else bv.add_user_section
    add_segment(start, length, data_offset, data_length, flags)
    add_section(name, start, length, semantics)


def _add_region(
    bv: BinaryView,
    region: Region,
    raw_len: int,
    image_base: Optional[int],
    *,
    auto_defined: bool = False,
) -> None:
    """Map one device region, separating backed code from erased flash."""

    data_offset, data_length = _file_backing(
        region.start,
        region.length,
        raw_len,
        image_base,
    )

    if region.kind == "flash" and data_length > 0:
        data = _read_file_bytes(bv, data_offset, data_length)
        erased_spans = _erased_spans(data) if data else ()
        if erased_spans or data_length < region.length:
            cursor = 0
            chunk_index = 0
            for erased_start, erased_end in erased_spans:
                if cursor < erased_start:
                    _add_region_chunk(
                        bv,
                        f"{region.name}.code_{chunk_index}",
                        region.start + cursor,
                        erased_start - cursor,
                        data_offset + cursor,
                        erased_start - cursor,
                        region.flags,
                        region.semantics,
                        auto_defined=auto_defined,
                    )
                    chunk_index += 1
                _add_region_chunk(
                    bv,
                    f"{region.name}.erased_{chunk_index}",
                    region.start + erased_start,
                    erased_end - erased_start,
                    data_offset + erased_start,
                    erased_end - erased_start,
                    READ_ONLY_DATA,
                    SectionSemantics.ReadOnlyDataSectionSemantics,
                    auto_defined=auto_defined,
                )
                chunk_index += 1
                cursor = erased_end

            if cursor < data_length:
                _add_region_chunk(
                    bv,
                    f"{region.name}.code_{chunk_index}",
                    region.start + cursor,
                    data_length - cursor,
                    data_offset + cursor,
                    data_length - cursor,
                    region.flags,
                    region.semantics,
                    auto_defined=auto_defined,
                )
                chunk_index += 1

            if data_length < region.length:
                _add_region_chunk(
                    bv,
                    f"{region.name}.unbacked_{chunk_index}",
                    region.start + data_length,
                    region.length - data_length,
                    0,
                    0,
                    READ_ONLY_DATA,
                    SectionSemantics.ReadOnlyDataSectionSemantics,
                    auto_defined=auto_defined,
                )
            return

    flags = READ_ONLY_DATA if region.kind == "flash" and data_length == 0 else region.flags
    semantics = SectionSemantics.ReadOnlyDataSectionSemantics if flags == READ_ONLY_DATA else region.semantics
    _add_region_chunk(
        bv,
        region.name,
        region.start,
        region.length,
        data_offset,
        data_length,
        flags,
        semantics,
        auto_defined=auto_defined,
    )


def _define_symbol(bv: BinaryView, symbol: Symbol, *, auto_defined: bool = False) -> None:
    try:
        if auto_defined and hasattr(bv, "define_auto_symbol"):
            bv.define_auto_symbol(symbol)
        else:
            bv.define_user_symbol(symbol)
    except Exception:
        if auto_defined:
            bv.define_user_symbol(symbol)
        else:
            raise


def _clean_define_expr(expr: str) -> str:
    expr = re.sub(r"/\*.*?\*/", "", expr).strip()
    while expr.startswith("(") and expr.endswith(")"):
        inner = expr[1:-1].strip()
        if inner.count("(") != inner.count(")"):
            break
        expr = inner
    return expr


def _eval_header_expr(expr: str, constants: dict[str, int]) -> Optional[int]:
    expr = _clean_define_expr(expr).replace(" ", "")
    if NUMBER_RE.match(expr):
        try:
            return int(expr, 16) if expr.lower().startswith("0x") else int(expr, 10)
        except ValueError:
            return None

    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)([+-](?:0x[0-9A-Fa-f]+|\d+))?", expr)
    if not match:
        return None
    base = constants.get(match.group(1))
    if base is None:
        return None
    delta = int(match.group(2) or "0", 0)
    return base + delta


def _is_header_label_address(addr: int) -> bool:
    return (
        PERIPHERALS_START <= addr <= PERIPHERALS_END
        or TLV_START <= addr <= TLV_END
        or VECTOR_START <= addr <= RESET_VECTOR
    )


def _parse_msp430_header_symbols(texts: Sequence[str]) -> tuple[SymbolDefinition, ...]:
    """Extract safe peripheral, TLV, vector, and alias labels from TI headers."""

    defines: list[tuple[str, str, str]] = []
    sfrs: list[tuple[str, str]] = []
    constants: dict[str, int] = {}

    for text in texts:
        for line in text.splitlines():
            define_match = DEFINE_RE.match(line)
            if define_match:
                name, expr = define_match.groups()
                defines.append((name, expr, line))
                value = _eval_header_expr(expr, constants)
                if value is not None:
                    constants[name] = value

            sfr_match = SFR_RE.match(line)
            if sfr_match:
                sfrs.append((sfr_match.group(1), sfr_match.group(2)))

    for _ in range(8):
        changed = False
        for name, expr, _line in defines:
            if name in constants:
                continue
            value = _eval_header_expr(expr, constants)
            if value is None:
                continue
            constants[name] = value
            changed = True
        if not changed:
            break

    labels_by_name: dict[str, int] = {}

    def add_label(name: str, addr: int) -> None:
        if not IDENTIFIER_RE.match(name) or name.startswith("__"):
            return
        if _is_header_label_address(addr):
            labels_by_name.setdefault(name, addr)

    for name, expr in sfrs:
        value = _eval_header_expr(expr, constants)
        if value is not None:
            add_label(name, value)

    for name, expr, line in defines:
        value = _eval_header_expr(expr, constants)
        if value is None:
            continue
        if name.endswith("_BASE"):
            add_label(name, value)
        elif name.startswith("TLV_") and TLV_START <= value <= TLV_END:
            add_label(name, value)
        elif name.endswith("_VECTOR"):
            comment_match = VECTOR_COMMENT_RE.search(line)
            if comment_match:
                add_label(name, int(comment_match.group(1), 0))
            elif 0 <= value <= RESET_VECTOR - VECTOR_START:
                add_label(name, VECTOR_START + value)

    for _ in range(8):
        changed = False
        for name, expr, _line in defines:
            target = _clean_define_expr(expr)
            if not IDENTIFIER_RE.match(target) or name in labels_by_name:
                continue
            addr = labels_by_name.get(target)
            if addr is None:
                continue
            add_label(name, addr)
            changed = True
        if not changed:
            break

    return tuple(sorted(labels_by_name.items(), key=lambda item: (item[1], item[0])))


def _repo_dir() -> str:
    script_path = globals().get("__file__")
    if script_path:
        return os.path.dirname(os.path.realpath(script_path))
    return os.getcwd()


def _default_msp430_header_paths() -> tuple[str, ...]:
    paths: list[str] = []
    env_paths = os.environ.get(MSP430_HEADER_PATHS_ENV, "")
    if env_paths:
        paths.extend(path for path in env_paths.split(os.pathsep) if path)

    inc_dir = os.path.join(_repo_dir(), "inc")
    for candidate in LOCAL_MSP430_HEADER_CANDIDATES:
        paths.append(os.path.join(inc_dir, candidate))
    if os.path.isdir(inc_dir):
        for root, _dirs, files in os.walk(inc_dir):
            for filename in files:
                if filename.endswith(".h"):
                    paths.append(os.path.join(root, filename))

    result = []
    seen = set()
    for path in paths:
        abs_path = os.path.abspath(path)
        if abs_path in seen or not os.path.isfile(abs_path):
            continue
        seen.add(abs_path)
        result.append(abs_path)
    return tuple(result)


def _load_msp430_header_symbols(header_paths: Optional[Sequence[str]] = None) -> tuple[SymbolDefinition, ...]:
    paths = tuple(header_paths) if header_paths is not None else _default_msp430_header_paths()
    texts = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                texts.append(handle.read())
        except OSError as exc:
            log_warn(f"Could not read MSP430 header labels from {path}: {exc}")
    return _parse_msp430_header_symbols(texts)


def _symbol_exists(bv: BinaryView, name: str, addr: int) -> bool:
    getter = getattr(bv, "get_symbols_by_raw_name", None)
    if getter is not None:
        try:
            return any(getattr(symbol, "address", None) == addr for symbol in getter(name))
        except Exception:
            pass

    getter = getattr(bv, "get_symbols", None)
    if getter is not None:
        try:
            return any(
                getattr(symbol, "address", None) == addr and _symbol_raw_name(symbol) == name
                for symbol in getter(addr, 1)
            )
        except Exception:
            pass
    return False


def _set_comment_if_empty(
    bv: BinaryView,
    addr: int,
    comment: str,
    *,
    auto_defined: bool = False,
) -> bool:
    getter = getattr(bv, "get_comment_at", None)
    if getter is not None:
        try:
            existing = getter(addr)
            if existing:
                return False
        except Exception:
            pass

    setter_names = (
        ("set_auto_comment_at", "set_comment_at")
        if auto_defined
        else ("set_comment_at", "set_auto_comment_at")
    )
    for setter_name in setter_names:
        setter = getattr(bv, setter_name, None)
        if setter is None:
            continue
        try:
            setter(addr, comment)
            return True
        except Exception:
            pass
    return False


def _has_function_at(bv: BinaryView, addr: int) -> bool:
    for getter_name in ("get_function_at", "get_functions_at"):
        getter = getattr(bv, getter_name, None)
        if getter is None:
            continue
        try:
            result = getter(addr)
        except Exception:
            continue
        if result:
            return True

    try:
        return any(getattr(func, "start", None) == addr for func in getattr(bv, "functions", []))
    except Exception:
        return False


def _symbol_raw_name(symbol) -> str:
    return str(getattr(symbol, "raw_name", getattr(symbol, "name", "")))


def _remove_symbol(bv: BinaryView, symbol) -> bool:
    for remover_name in ("undefine_user_symbol", "undefine_auto_symbol"):
        remover = getattr(bv, remover_name, None)
        if remover is None:
            continue
        try:
            remover(symbol)
            return True
        except Exception:
            pass
    return False


def _remove_boundary_symbols_at_function_starts(
    bv: BinaryView,
    verbose: bool = False,
    symbols: tuple[SymbolDefinition, ...] = SYMBOLS,
) -> int:
    removed = 0
    for name, addr in symbols:
        if not _has_function_at(bv, addr):
            continue
        existing_symbols = []
        getter = getattr(bv, "get_symbols", None)
        if getter is not None:
            try:
                existing_symbols = list(getter(addr, 1))
            except Exception:
                existing_symbols = []
        if not existing_symbols:
            getter = getattr(bv, "get_symbols_by_raw_name", None)
            if getter is not None:
                try:
                    existing_symbols = [symbol for symbol in getter(name) if getattr(symbol, "address", None) == addr]
                except Exception:
                    existing_symbols = []

        for symbol in existing_symbols:
            if _symbol_raw_name(symbol) != name:
                continue
            if getattr(symbol, "type", None) != SymbolType.DataSymbol:
                continue
            if _remove_symbol(bv, symbol):
                removed += 1

    if verbose and removed:
        print(f"Removed {removed} boundary data symbol(s) that collided with functions.")
    return removed


def _define_symbols(
    bv: BinaryView,
    symbols: Sequence[SymbolDefinition],
    *,
    auto_defined: bool = False,
    skip_function_starts: bool = True,
) -> int:
    boundary_names = frozenset(name for name, _ in symbols)
    if skip_function_starts:
        _remove_boundary_symbols_at_function_starts(bv, symbols=tuple(symbols))
    defined = 0
    for name, addr in symbols:
        if skip_function_starts and name in boundary_names and _has_function_at(bv, addr):
            continue
        if _symbol_exists(bv, name, addr):
            continue
        try:
            _define_symbol(bv, Symbol(SymbolType.DataSymbol, addr, name), auto_defined=auto_defined)
            defined += 1
        except Exception as exc:
            log_warn(f"Could not define {name} at {addr:#x}: {exc}")
    return defined


def apply_msp430_header_labels(
    bv: BinaryView,
    *,
    header_paths: Optional[Sequence[str]] = None,
    auto_defined: bool = False,
    verbose: bool = True,
) -> int:
    """Parse configured TI headers and add labels that are not already present."""

    labels = _load_msp430_header_symbols(header_paths)
    defined = _define_symbols(bv, labels, auto_defined=auto_defined, skip_function_starts=False)
    if verbose:
        if labels:
            print(f"Applied {defined} new MSP430 header label(s) from {len(labels)} parsed label(s).")
        else:
            print(
                "No MSP430 header labels were found. Copy the TI device header into inc/ "
                f"or set {MSP430_HEADER_PATHS_ENV} to one or more header paths."
            )
    return defined


def _find_msp430_arch(preferred_arch: Optional[str]) -> Optional[Architecture]:
    _try_load_local_msp430x_plugin()

    names = []
    if preferred_arch:
        names.append(preferred_arch)
    names.extend(("msp430x", "msp430", "MSP430X", "MSP430"))

    for name in names:
        try:
            return Architecture[name]
        except Exception:
            pass

    try:
        for arch in list(Architecture):
            arch_name = getattr(arch, "name", str(arch))
            if "msp430" in arch_name.lower():
                return arch
    except Exception:
        pass
    return None


def _try_load_local_msp430x_plugin() -> None:
    try:
        Architecture["msp430x"]
        return
    except Exception:
        pass

    package = globals().get("__package__")
    candidates = []
    if package:
        candidates.append(f"{package}.msp430x_arch")
    candidates.append("msp430x_arch")

    seen = set()
    for module_name in candidates:
        if module_name in seen:
            continue
        seen.add(module_name)
        try:
            importlib.import_module(module_name)
            return
        except Exception as exc:
            log_warn(f"Could not import local MSP430X architecture module {module_name}: {exc}")


def _configure_architecture(
    bv: BinaryView,
    preferred_arch: Optional[str],
    verbose: bool,
    *,
    set_platform: bool = False,
) -> Optional[Architecture]:
    """Attach the requested MSP430 architecture and, when safe, its platform."""

    arch = _find_msp430_arch(preferred_arch)
    if arch is None:
        if verbose:
            print("MSP430 architecture was not found in this Binary Ninja install.")
        log_warn("MSP430 architecture was not found; memory map applied without CPU analysis.")
        return None

    try:
        bv.arch = arch
    except Exception as exc:
        log_warn(f"Could not set MSP430 architecture {arch}: {exc}")

    platform = getattr(arch, "standalone_platform", None)
    if set_platform and platform is not None:
        if _default_platform_assignment_is_safe():
            try:
                bv.platform = platform
                log_info(f"Set MSP430 default platform: {platform}")
            except Exception as exc:
                log_warn(f"Could not set MSP430 standalone platform: {exc}")
        else:
            log_info(
                "Skipping MSP430 default platform assignment on this Binary Ninja build; "
                "BNSetDefaultPlatform has crashed in 5.4 dev builds for this Python architecture."
            )

    if verbose:
        print(f"Using architecture: {arch}")
    return arch


def _msp430x_platform_name() -> str:
    arch = _find_msp430_arch("msp430x")
    platform = getattr(arch, "standalone_platform", None) if arch is not None else None
    name = getattr(platform, "name", None)
    return str(name) if name else "msp430x"


def _default_platform_assignment_is_safe() -> bool:
    """Return whether this Binary Ninja build safely accepts platform assignment."""

    try:
        version = core_version()
    except Exception:
        return False

    match = re.match(r"^(\d+)\.(\d+)\.", str(version))
    if match is None:
        return False

    major, minor = (int(match.group(1)), int(match.group(2)))
    return (major, minor) < (5, 4)


def _set_load_setting_default(load_settings: Settings, key: str, value, *, read_only: bool = True) -> None:
    if not load_settings.contains(key):
        group = key.split(".", 1)[0]
        value_type = "number" if isinstance(value, int) else "string"
        properties = {
            "title": key,
            "description": f"MSP430F5438 load setting for {key}.",
            "type": value_type,
            "default": value,
            "readOnly": read_only,
        }
        if value_type == "number":
            properties["minValue"] = 0
        try:
            load_settings.register_group(group, group.title())
            load_settings.register_setting(key, json.dumps(properties))
        except Exception as exc:
            log_warn(f"Could not register load setting {key}: {exc}")
            return
    try:
        load_settings.update_property(key, json.dumps({"default": value, "readOnly": read_only}))
    except Exception as exc:
        log_warn(f"Could not update load setting {key}: {exc}")


def _set_load_setting_value(load_settings: Settings, key: str, value) -> None:
    if not load_settings.contains(key):
        return
    try:
        if isinstance(value, str):
            load_settings.set_string(key, value)
        elif isinstance(value, int):
            load_settings.set_integer(key, value)
    except Exception as exc:
        log_warn(f"Could not set load setting {key}: {exc}")


def _read_u16(bv: BinaryView, addr: int) -> Optional[int]:
    try:
        data = bv.read(addr, 2)
    except Exception:
        return None
    if len(data) != 2:
        return None
    return data[0] | (data[1] << 8)


def _is_probable_code_pointer(addr: int) -> bool:
    if addr in (0x0000, 0xFFFF):
        return False
    if addr & 1:
        return False
    return (FLASH_START <= addr <= VECTOR_END) or (RAM_START <= addr <= RAM_END)


def _uint16_type():
    return Type.int(2, False)


def _char_array_type(length: int):
    try:
        return Type.array(Type.char(), length)
    except Exception:
        return f"char[{length}]"


def _uint8_array_type(length: int):
    try:
        return Type.array(Type.int(1, False), length)
    except Exception:
        return f"uint8_t[{length}]"


def _uint32_array_type(length: int):
    try:
        return Type.array(Type.int(4, False), length)
    except Exception:
        return f"uint32_t[{length}]"


def _vector_handler_type(bv: BinaryView):
    calling_convention = None
    for owner in (getattr(bv, "platform", None), getattr(bv, "arch", None)):
        if owner is None:
            continue
        calling_convention = getattr(owner, "default_calling_convention", None)
        if calling_convention is not None:
            break
    try:
        return Type.function(Type.void(), [], calling_convention=calling_convention)
    except Exception:
        return "void handler(void)"


def _define_vector_data_var(
    bv: BinaryView,
    addr: int,
    name: str,
    *,
    auto_defined: bool = False,
) -> bool:
    try:
        if auto_defined and hasattr(bv, "define_data_var"):
            bv.define_data_var(addr, _uint16_type(), name)
        elif hasattr(bv, "define_user_data_var"):
            bv.define_user_data_var(addr, _uint16_type(), name)
        else:
            _define_symbol(
                bv,
                Symbol(SymbolType.DataSymbol, addr, name),
                auto_defined=auto_defined,
            )
        return True
    except Exception:
        try:
            _define_symbol(
                bv,
                Symbol(SymbolType.DataSymbol, addr, name),
                auto_defined=auto_defined,
            )
            return True
        except Exception as exc:
            log_warn(f"Could not define vector entry {name} at {addr:#06x}: {exc}")
            return False


def _set_vector_handler_type(bv: BinaryView, addr: int, name: str, func=None) -> None:
    if func is None:
        try:
            func = bv.get_function_at(addr)
        except Exception:
            func = None
    if func is None:
        try:
            func = next((candidate for candidate in getattr(bv, "functions", []) if candidate.start == addr), None)
        except Exception:
            func = None
    if func is None:
        return

    try:
        func.name = name
    except Exception:
        pass

    try:
        func.set_user_type(_vector_handler_type(bv))
    except Exception:
        try:
            func.type = _vector_handler_type(bv)
        except Exception as exc:
            log_warn(f"Could not set vector handler type for {name} at {addr:#06x}: {exc}")


def _add_function_symbol(
    bv: BinaryView,
    addr: int,
    name: str,
    *,
    entry: bool = False,
    auto_defined: bool = False,
) -> bool:
    try:
        if entry:
            bv.add_entry_point(addr)
        func = None
        add_function = getattr(bv, "add_function", None)
        if add_function is not None:
            func = add_function(addr)
        _define_symbol(
            bv,
            Symbol(SymbolType.FunctionSymbol, addr, name),
            auto_defined=auto_defined,
        )
        _set_vector_handler_type(bv, addr, name, func)
        return True
    except Exception as exc:
        log_warn(f"Could not add function {name} at {addr:#06x}: {exc}")
        return False


def _vector_name_by_addr(spec: DeviceSpec = DEFAULT_DEVICE_SPEC) -> dict:
    names = {addr: (vector_name, function_name) for addr, vector_name, function_name in spec.vector_names}
    for addr in range(spec.vector_start, spec.vector_end + 1, 2):
        if addr not in names:
            priority = (addr - spec.vector_start) // 2
            names[addr] = (f"reserved_{priority:02d}", f"isr_reserved_{priority:02d}")
    return names


def _seed_interrupt_vectors(
    bv: BinaryView,
    verbose: bool,
    *,
    spec: DeviceSpec = DEFAULT_DEVICE_SPEC,
    auto_defined: bool = False,
    create_functions: bool = True,
) -> int:
    """Define vectors and seed one named function per unique valid target."""

    targets = {}
    vector_count = 0
    for vector_addr, (vector_name, function_name) in sorted(_vector_name_by_addr(spec).items()):
        target = _read_u16(bv, vector_addr)
        _define_vector_data_var(
            bv,
            vector_addr,
            f"vector_{vector_name}",
            auto_defined=auto_defined,
        )

        if target is None:
            continue
        if not _is_probable_code_pointer(target):
            continue

        vector_count += 1
        priority = 0 if vector_addr == spec.reset_vector else 2 if function_name.startswith("isr_reserved_") else 1
        if target not in targets or priority < targets[target][0]:
            targets[target] = (
                priority,
                "reset_handler" if vector_addr == spec.reset_vector else function_name,
                vector_name,
                vector_addr == spec.reset_vector,
            )

    created = 0
    if not create_functions:
        if verbose:
            print(f"Defined vector table data from {vector_count} populated vector(s).")
        return created

    for target, (_, function_name, vector_name, is_entry) in sorted(targets.items()):
        if _add_function_symbol(
            bv,
            target,
            function_name,
            entry=is_entry,
            auto_defined=auto_defined,
        ):
            created += 1
            if verbose:
                print(f"{vector_name:>12} -> {target:#06x} {function_name}")

    if verbose:
        print(f"Seeded {created} unique vector target function(s) from {vector_count} populated vector(s).")
    return created


def _enable_analysis_options(bv: BinaryView, enable_linear_sweep: bool) -> None:
    if not enable_linear_sweep:
        return
    try:
        bv.add_analysis_option("linearsweep")
    except Exception as exc:
        log_warn(f"Could not enable linearsweep analysis option: {exc}")


def _cleanup_peripheral_functions(bv: BinaryView, verbose: bool) -> int:
    removed = 0
    for func in list(getattr(bv, "functions", [])):
        start = getattr(func, "start", None)
        if start is None or start >= PERIPHERALS_END + 1:
            continue
        try:
            bv.remove_function(func)
            removed += 1
        except Exception as exc:
            log_warn(f"Could not remove low peripheral-space function at {start:#x}: {exc}")
    if verbose and removed:
        print(f"Removed {removed} stale function(s) from peripheral space below 0x1000.")
    return removed


def _is_erased_bytes(data: bytes, min_bytes: int = ERASED_FUNCTION_MIN_BYTES) -> bool:
    return len(data) >= min_bytes and all(byte == 0xFF for byte in data[:min_bytes])


def _is_erased_flash_function_start(bv: BinaryView, addr: int) -> bool:
    if addr < FLASH_START or addr > FLASH_END:
        return False
    try:
        return _is_erased_bytes(bytes(bv.read(addr, ERASED_FUNCTION_MIN_BYTES)))
    except Exception:
        return False


def _cleanup_erased_flash_functions(bv: BinaryView, verbose: bool) -> int:
    removed = 0
    for func in list(getattr(bv, "functions", [])):
        start = getattr(func, "start", None)
        if start is None or not _is_erased_flash_function_start(bv, start):
            continue
        try:
            bv.remove_function(func)
            removed += 1
        except Exception as exc:
            log_warn(f"Could not remove erased-flash function at {start:#x}: {exc}")
    if verbose and removed:
        print(f"Removed {removed} stale function(s) that start in erased 0xff flash.")
    return removed


def _is_printable_string_byte(byte: int) -> bool:
    return 0x20 <= byte <= 0x7E


def _ascii_string_spans(data: bytes, base: int = 0, min_len: int = ASCII_STRING_MIN_LEN) -> tuple[AddressSpan, ...]:
    """Find conservative NUL-terminated printable ASCII spans in firmware."""

    spans = []
    cursor = 0
    data_len = len(data)
    while cursor < data_len:
        start = cursor
        has_alpha = False
        while cursor < data_len and _is_printable_string_byte(data[cursor]):
            has_alpha = has_alpha or (0x41 <= data[cursor] <= 0x5A) or (0x61 <= data[cursor] <= 0x7A)
            cursor += 1

        length = cursor - start
        if length >= min_len and has_alpha and cursor < data_len and data[cursor] == 0:
            spans.append((base + start, base + cursor + 1))
            cursor += 1
            continue

        cursor = start + 1 if cursor == start else cursor + 1
    return tuple(spans)


def _merge_spans(spans: Sequence[AddressSpan]) -> tuple[AddressSpan, ...]:
    merged = []
    for start, end in sorted(spans):
        if start >= end:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _ascii_string_padding_spans(
    data: bytes,
    base: int = 0,
    *,
    max_padding: int = ASCII_STRING_PADDING_MAX_LEN,
) -> tuple[AddressSpan, ...]:
    # Small zero runs beside strings are usually alignment/padding. If BN starts
    # them as code they show up as bogus `bra @pc` helpers.
    spans = []
    data_len = len(data)
    for string_start, string_end in _ascii_string_spans(data, base):
        start = string_start - base
        end = string_end - base

        padding_start = start
        while (
            padding_start > 0
            and start - padding_start < max_padding
            and data[padding_start - 1] == 0
        ):
            padding_start -= 1
        if padding_start < start:
            spans.append((base + padding_start, string_start))

        padding_end = end
        while (
            padding_end < data_len
            and padding_end - end < max_padding
            and data[padding_end] == 0
        ):
            padding_end += 1
        if padding_end > end:
            spans.append((string_end, base + padding_end))

    return _merge_spans(spans)


def _looks_like_string_table_gap(data: bytes, start: int, end: int) -> bool:
    if start >= end:
        return False
    gap = data[start:end]
    if 0xFF in gap:
        return False
    has_control_or_nul = any(byte < 0x20 for byte in gap)
    has_alpha = any((0x41 <= byte <= 0x5A) or (0x61 <= byte <= 0x7A) for byte in gap)
    return has_control_or_nul and not has_alpha


def _ascii_string_cluster_spans(
    data: bytes,
    base: int = 0,
    *,
    max_gap: int = ASCII_STRING_CLUSTER_MAX_GAP,
) -> tuple[AddressSpan, ...]:
    """Merge nearby strings across short data-like separator gaps."""

    spans = list(_merge_spans((*_ascii_string_spans(data, base), *_ascii_string_padding_spans(data, base))))
    if not spans:
        return ()

    clusters = [spans[0]]
    for start, end in spans[1:]:
        prev_start, prev_end = clusters[-1]
        gap_start = prev_end - base
        gap_end = start - base
        if (
            0 < start - prev_end <= max_gap
            and 0 <= gap_start <= gap_end <= len(data)
            and _looks_like_string_table_gap(data, gap_start, gap_end)
        ):
            clusters[-1] = (prev_start, end)
        else:
            clusters.append((start, end))
    return tuple(clusters)


def _ascii_string_gap_spans(
    data: bytes,
    base: int = 0,
    *,
    max_gap: int = ASCII_STRING_CLUSTER_MAX_GAP,
) -> tuple[AddressSpan, ...]:
    related = list(_merge_spans((*_ascii_string_spans(data, base), *_ascii_string_padding_spans(data, base))))
    spans = []
    for (_, prev_end), (start, _) in zip(related, related[1:]):
        gap_start = prev_end - base
        gap_end = start - base
        if (
            0 < start - prev_end <= max_gap
            and 0 <= gap_start <= gap_end <= len(data)
            and _looks_like_string_table_gap(data, gap_start, gap_end)
        ):
            spans.append((prev_end, start))
    return tuple(spans)


def _looks_like_byte_lookup_table_run(run: bytes) -> bool:
    # Favor low/control-heavy numeric data and reject alphabetic runs so real
    # text still gets handled by the string scanner.
    if len(run) < BYTE_LOOKUP_TABLE_MIN_LEN or 0xFF in run:
        return False
    if any((0x41 <= byte <= 0x5A) or (0x61 <= byte <= 0x7A) for byte in run):
        return False
    non_padding = [byte for byte in run if byte not in (0x00, 0x20)]
    if len(set(non_padding)) < 6:
        return False
    control_count = sum(1 for byte in run if byte < 0x20)
    return control_count * 3 >= len(run)


def _byte_lookup_table_spans(data: bytes, base: int = 0) -> tuple[AddressSpan, ...]:
    """Find long control-heavy byte runs that are likely lookup tables."""

    spans = []
    cursor = 0
    data_len = len(data)

    def is_table_byte(byte: int) -> bool:
        return byte != 0xFF and byte < 0x40

    while cursor < data_len:
        if not is_table_byte(data[cursor]):
            cursor += 1
            continue

        start = cursor
        while cursor < data_len and is_table_byte(data[cursor]):
            cursor += 1

        if _looks_like_byte_lookup_table_run(data[start:cursor]):
            spans.append((base + start, base + cursor))

    return tuple(spans)


def _s16_from_le(data: bytes, offset: int) -> int:
    value = data[offset] | (data[offset + 1] << 8)
    return value - 0x10000 if value & 0x8000 else value


def _u16_from_le(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def _is_ext_word(word: int) -> bool:
    return (word & 0xF800) == 0x1800


def _ext_src_hi(word: int) -> int:
    return (word >> 7) & 0xF


def _is_address_word_ext(word: int) -> bool:
    return _is_ext_word(word) and ((word >> 6) & 1) == 0


def _monotonic_word_table_spans(
    data: bytes,
    base: int = 0,
    *,
    min_words: int = WORD_LOOKUP_TABLE_MIN_WORDS,
) -> tuple[AddressSpan, ...]:
    """Find sufficiently long monotonic signed-word lookup tables."""

    spans = []
    word_count = len(data) // 2
    values = [_s16_from_le(data, index * 2) for index in range(word_count)]
    index = 0

    while index <= word_count - min_words:
        start = index
        direction = 0
        cursor = index + 1
        last = values[index]

        while cursor < word_count:
            delta = values[cursor] - last
            if delta == 0 or abs(delta) > 0x2000:
                break
            delta_direction = 1 if delta > 0 else -1
            if direction == 0:
                direction = delta_direction
            if delta_direction != direction:
                break
            last = values[cursor]
            cursor += 1

        if cursor - start >= min_words:
            sequence = values[start:cursor]
            if max(sequence) - min(sequence) >= 0x800:
                spans.append((base + start * 2, base + cursor * 2))
                index = cursor
                continue

        index = start + 1

    return tuple(spans)


def _numeric_lookup_table_spans(data: bytes, base: int = 0) -> tuple[AddressSpan, ...]:
    return _merge_spans((
        *_byte_lookup_table_spans(data, base),
        *_monotonic_word_table_spans(data, base),
    ))


def _is_probable_flash_jump_target(addr: int) -> bool:
    if addr % 2 != 0:
        return False
    return (FLASH_START <= addr < VECTOR_START) or (VECTOR_END < addr <= FLASH_END)


def _address_jump_table_entries(data: bytes, table_offset: int) -> tuple[int, ...]:
    targets = []
    cursor = table_offset
    data_len = len(data)
    while (
        len(targets) < ADDRESS_JUMP_TABLE_MAX_ENTRIES
        and cursor + 4 <= data_len
    ):
        target = _u16_from_le(data, cursor) | (
            (_u16_from_le(data, cursor + 2) & 0xF) << 16
        )
        if not _is_probable_flash_jump_target(target):
            break
        targets.append(target)
        cursor += 4
    return tuple(targets)


def _address_jump_tables(data: bytes, base: int = 0) -> tuple[AddressJumpTable, ...]:
    """Find compiler-generated 20-bit indexed branch tables and targets."""

    tables = []
    cursor = 0
    data_len = len(data)

    while cursor + 10 <= data_len:
        first = _u16_from_le(data, cursor)
        if (first & 0xFFF0) != 0x0E40:
            cursor += 2
            continue

        reg = first & 0xF
        ext = _u16_from_le(data, cursor + 4)
        if (
            _u16_from_le(data, cursor + 2) != (0x0540 | reg)
            or not _is_address_word_ext(ext)
            or _u16_from_le(data, cursor + 6) != (0x4050 | (reg << 8))
        ):
            cursor += 2
            continue

        table_addr = ((_ext_src_hi(ext) << 16) | _u16_from_le(data, cursor + 8)) & 0xFFFFF
        table_offset = table_addr - base
        if table_offset < 0 or table_offset + 4 > data_len:
            cursor += 2
            continue

        targets = _address_jump_table_entries(data, table_offset)
        if len(targets) >= ADDRESS_JUMP_TABLE_MIN_ENTRIES:
            tables.append((base + cursor, table_addr, targets))
            cursor = max(cursor + 10, table_offset + len(targets) * 4)
            continue

        cursor += 2

    return tuple(tables)


def _address_jump_table_spans(data: bytes, base: int = 0) -> tuple[AddressSpan, ...]:
    # Address jump tables are 20-bit entries stored as two little-endian words.
    # Defining them as data also gives the indirect branch resolver real targets.
    spans = [
        (table_addr, table_addr + len(targets) * 4)
        for _source_addr, table_addr, targets in _address_jump_tables(data, base)
    ]
    return _merge_spans(spans)


def _cinit_record_next_offset(data: bytes, offset: int) -> Optional[int]:
    # TI/EABI .cinit records encode a payload length and 20-bit RAM destination.
    # We only accept records that fit RAM so random flash bytes do not become data.
    if offset + CINIT_RECORD_HEADER_SIZE > len(data):
        return None

    length = _u16_from_le(data, offset)
    if length == 0 or length > CINIT_RECORD_MAX_PAYLOAD:
        return None

    target = _u16_from_le(data, offset + 2) | ((_u16_from_le(data, offset + 4) & 0xF) << 16)
    target_high = _u16_from_le(data, offset + 4)
    if target_high & ~0xF:
        return None
    if target < RAM_START or target + length > RAM_END + 1:
        return None

    payload_end = offset + CINIT_RECORD_HEADER_SIZE + length
    if payload_end > len(data):
        return None
    return payload_end + (length & 1)


def _cinit_record_info(data: bytes, offset: int) -> Optional[CinitRecordInfo]:
    next_offset = _cinit_record_next_offset(data, offset)
    if next_offset is None:
        return None
    length = _u16_from_le(data, offset)
    target = _u16_from_le(data, offset + 2) | ((_u16_from_le(data, offset + 4) & 0xF) << 16)
    return next_offset, target, length


def _cinit_table_candidate(
    data: bytes,
    offset: int,
    min_records: int,
) -> Optional[CinitCandidate]:
    record_count = 0
    records = []
    cursor = offset
    record_info = _cinit_record_info(data, cursor)
    while record_info is not None:
        next_offset, target, length = record_info
        if next_offset > len(data):
            break
        record_count += 1
        records.append((cursor, next_offset, target, length))
        cursor = next_offset
        record_info = _cinit_record_info(data, cursor)

    if record_count < min_records:
        return None
    return (offset, cursor, tuple(records))


def _cinit_padded_start(data: bytes, start: int) -> int:
    padded_start = start
    while (
        padded_start > 0
        and start - padded_start < CINIT_TABLE_PADDING_MAX_LEN
        and data[padded_start - 1] == 0
    ):
        padded_start -= 1
    return padded_start


def _cinit_table_spans(
    data: bytes,
    base: int = 0,
    *,
    min_records: int = CINIT_TABLE_MIN_RECORDS,
) -> tuple[AddressSpan, ...]:
    """Find non-overlapping TI/EABI C initializer tables and leading padding."""

    candidates = []
    data_len = len(data)

    for cursor in range(0, data_len - CINIT_RECORD_HEADER_SIZE + 1, 2):
        candidate = _cinit_table_candidate(data, cursor, min_records)
        if candidate is not None:
            candidates.append(candidate)

    selected = []
    for candidate in candidates:
        start, end, records = candidate
        if selected and start < selected[-1][1]:
            _prev_start, _prev_end, prev_records = selected[-1]
            if len(records) > len(prev_records):
                selected[-1] = candidate
            continue
        selected.append(candidate)

    spans = [
        (base + _cinit_padded_start(data, start), base + end)
        for start, end, _records in selected
    ]
    return _merge_spans(spans)


def _cinit_table_records(
    data: bytes,
    base: int = 0,
    *,
    min_records: int = CINIT_TABLE_MIN_RECORDS,
) -> tuple[CinitRecord, ...]:
    """Return TI/EABI initializer records from the selected table candidates."""

    candidates = []
    data_len = len(data)

    for cursor in range(0, data_len - CINIT_RECORD_HEADER_SIZE + 1, 2):
        candidate = _cinit_table_candidate(data, cursor, min_records)
        if candidate is not None:
            candidates.append(candidate)

    selected = []
    for candidate in candidates:
        start, end, records = candidate
        if selected and start < selected[-1][1]:
            _prev_start, _prev_end, prev_records = selected[-1]
            if len(records) > len(prev_records):
                selected[-1] = candidate
            continue
        selected.append(candidate)

    return tuple(
        (base + start, base + end, target, length)
        for _table_start, _table_end, records in selected
        for start, end, target, length in records
    )


def _is_vector_handler_function(func) -> bool:
    name = getattr(func, "name", "")
    return name == "reset_handler" or name.startswith("isr_")


def _flash_ascii_string_spans(bv: BinaryView) -> tuple[AddressSpan, ...]:
    try:
        data = bytes(bv.read(FLASH_START, FLASH_SIZE))
    except Exception:
        return ()
    return _ascii_string_spans(data, FLASH_START)


def _flash_ascii_string_padding_spans(bv: BinaryView) -> tuple[AddressSpan, ...]:
    try:
        data = bytes(bv.read(FLASH_START, FLASH_SIZE))
    except Exception:
        return ()
    return _ascii_string_padding_spans(data, FLASH_START)


def _flash_ascii_string_related_spans(bv: BinaryView) -> tuple[AddressSpan, ...]:
    return _merge_spans((*_flash_ascii_string_spans(bv), *_flash_ascii_string_padding_spans(bv)))


def _flash_ascii_string_cluster_spans(bv: BinaryView) -> tuple[AddressSpan, ...]:
    try:
        data = bytes(bv.read(FLASH_START, FLASH_SIZE))
    except Exception:
        return ()
    return _ascii_string_cluster_spans(data, FLASH_START)


def _flash_ascii_string_gap_spans(bv: BinaryView) -> tuple[AddressSpan, ...]:
    try:
        data = bytes(bv.read(FLASH_START, FLASH_SIZE))
    except Exception:
        return ()
    return _ascii_string_gap_spans(data, FLASH_START)


def _flash_numeric_lookup_table_spans(bv: BinaryView) -> tuple[AddressSpan, ...]:
    try:
        data = bytes(bv.read(FLASH_START, FLASH_SIZE))
    except Exception:
        return ()
    return _numeric_lookup_table_spans(data, FLASH_START)


def _flash_address_jump_table_spans(bv: BinaryView) -> tuple[AddressSpan, ...]:
    try:
        data = bytes(bv.read(FLASH_START, FLASH_SIZE))
    except Exception:
        return ()
    return _address_jump_table_spans(data, FLASH_START)


def _flash_address_jump_tables(bv: BinaryView) -> tuple[AddressJumpTable, ...]:
    try:
        data = bytes(bv.read(FLASH_START, FLASH_SIZE))
    except Exception:
        return ()
    return _address_jump_tables(data, FLASH_START)


def _flash_cinit_table_spans(bv: BinaryView) -> tuple[AddressSpan, ...]:
    try:
        data = bytes(bv.read(FLASH_START, FLASH_SIZE))
    except Exception:
        return ()
    spans = _cinit_table_spans(data, FLASH_START)
    vector_handlers = [
        getattr(func, "start", None)
        for func in getattr(bv, "functions", [])
        if _is_vector_handler_function(func)
    ]
    if not vector_handlers:
        return spans
    return tuple(
        (start, end)
        for start, end in spans
        if not any(handler is not None and start <= handler < end for handler in vector_handlers)
    )


def _flash_cinit_table_records(bv: BinaryView) -> tuple[CinitRecord, ...]:
    try:
        data = bytes(bv.read(FLASH_START, FLASH_SIZE))
    except Exception:
        return ()
    spans = _flash_cinit_table_spans(bv)
    if not spans:
        return ()
    return tuple(
        record
        for record in _cinit_table_records(data, FLASH_START)
        if _addr_in_spans(record[0], spans)
    )


def _addr_in_spans(addr: int, spans: Sequence[AddressSpan]) -> bool:
    return any(start <= addr < end for start, end in spans)


def _function_contains_addr(func, addr: int) -> bool:
    start = getattr(func, "start", None)
    if start is None or addr < start:
        return False
    end = getattr(func, "highest_address", None)
    if end is None:
        end = getattr(func, "end", None)
    return end is None or addr <= end


def _functions_containing_addr(bv: BinaryView, addr: int):
    getter = getattr(bv, "get_functions_containing", None)
    if getter is not None:
        try:
            funcs = tuple(getter(addr))
            if funcs:
                return funcs
        except Exception:
            pass
    return tuple(
        func
        for func in getattr(bv, "functions", [])
        if _function_contains_addr(func, addr)
    )


def _cleanup_ascii_string_functions(bv: BinaryView, verbose: bool) -> int:
    spans = _flash_ascii_string_cluster_spans(bv)
    if not spans:
        return 0

    removed = 0
    for func in list(getattr(bv, "functions", [])):
        start = getattr(func, "start", None)
        if start is None or not _addr_in_spans(start, spans):
            continue
        try:
            bv.remove_function(func)
            removed += 1
        except Exception as exc:
            log_warn(f"Could not remove ASCII-string function at {start:#x}: {exc}")
    if verbose and removed:
        print(f"Removed {removed} stale function(s) that start in printable ASCII flash data.")
    return removed


def _cleanup_numeric_lookup_table_functions(bv: BinaryView, verbose: bool) -> int:
    spans = _flash_numeric_lookup_table_spans(bv)
    if not spans:
        return 0

    removed = 0
    for func in list(getattr(bv, "functions", [])):
        start = getattr(func, "start", None)
        if start is None or not _addr_in_spans(start, spans):
            continue
        try:
            bv.remove_function(func)
            removed += 1
        except Exception as exc:
            log_warn(f"Could not remove numeric-table function at {start:#x}: {exc}")
    if verbose and removed:
        print(f"Removed {removed} stale function(s) that start in numeric flash lookup tables.")
    return removed


def _cleanup_address_jump_table_functions(bv: BinaryView, verbose: bool) -> int:
    spans = _flash_address_jump_table_spans(bv)
    if not spans:
        return 0

    removed = 0
    for func in list(getattr(bv, "functions", [])):
        start = getattr(func, "start", None)
        if start is None or not _addr_in_spans(start, spans):
            continue
        try:
            bv.remove_function(func)
            removed += 1
        except Exception as exc:
            log_warn(f"Could not remove address-jump-table function at {start:#x}: {exc}")
    if verbose and removed:
        print(f"Removed {removed} stale function(s) that start in address jump tables.")
    return removed


def _cleanup_cinit_table_functions(bv: BinaryView, verbose: bool) -> int:
    spans = _flash_cinit_table_spans(bv)
    if not spans:
        return 0

    removed = 0
    for func in list(getattr(bv, "functions", [])):
        start = getattr(func, "start", None)
        if start is None or not _addr_in_spans(start, spans):
            continue
        try:
            bv.remove_function(func)
            removed += 1
        except Exception as exc:
            log_warn(f"Could not remove C initializer table function at {start:#x}: {exc}")
    if verbose and removed:
        print(f"Removed {removed} stale function(s) that start in C initializer tables.")
    return removed


def _seed_address_jump_table_indirect_branches(bv: BinaryView, verbose: bool = False) -> int:
    """Attach recovered case targets to each containing indirect branch."""

    arch = getattr(bv, "arch", None)
    if arch is None:
        try:
            arch = Architecture["msp430x"]
        except Exception:
            arch = None
    if arch is None:
        return 0

    seeded = 0
    for source_addr, _table_addr, targets in _flash_address_jump_tables(bv):
        branches = [(arch, target) for target in targets]
        for func in _functions_containing_addr(bv, source_addr):
            setter = getattr(func, "set_auto_indirect_branches", None)
            if setter is None:
                continue
            try:
                setter(source_addr, branches)
                seeded += 1
            except Exception as exc:
                log_warn(f"Could not seed jump-table branches at {source_addr:#x}: {exc}")
            break

    if verbose and seeded:
        print(f"Seeded {seeded} MSP430X address jump table indirect branch set(s).")
    return seeded


def _is_backed_code_word(bv: BinaryView, addr: int) -> bool:
    if not _is_probable_flash_jump_target(addr):
        return False
    try:
        data = bytes(bv.read(addr, 2))
    except Exception:
        return False
    if len(data) < 2:
        return False
    word = _u16_from_le(data, 0)
    return word not in (0x0000, 0xFFFF)


def _seed_address_jump_table_target_functions(bv: BinaryView, verbose: bool = False) -> int:
    """Create functions for backed jump-table targets not classified as data."""

    add_function = getattr(bv, "add_function", None)
    if add_function is None:
        return 0

    table_spans = _flash_address_jump_table_spans(bv)
    created = 0
    for _source_addr, _table_addr, targets in _flash_address_jump_tables(bv):
        for target in targets:
            if (
                _has_function_at(bv, target)
                or _addr_in_spans(target, table_spans)
                or _has_data_var_at(bv, target)
                or not _is_backed_code_word(bv, target)
            ):
                continue
            try:
                add_function(target)
                created += 1
            except Exception as exc:
                log_warn(f"Could not add jump-table target function at {target:#x}: {exc}")

    if verbose and created:
        print(f"Seeded {created} MSP430X address jump table target function(s).")
    return created


def _has_data_var_at(bv: BinaryView, addr: int) -> bool:
    try:
        getter = getattr(bv, "get_data_var_at", None)
        if getter is not None and getter(addr) is not None:
            return True
    except Exception:
        pass
    try:
        return addr in getattr(bv, "data_vars", {})
    except Exception:
        return False


def _define_ascii_string_data_vars(
    bv: BinaryView,
    *,
    auto_defined: bool = False,
    verbose: bool = False,
) -> int:
    defined = 0
    for start, end in _flash_ascii_string_spans(bv):
        if _has_data_var_at(bv, start):
            continue
        name = f"str_{start:05x}"
        try:
            if auto_defined and hasattr(bv, "define_data_var"):
                bv.define_data_var(start, _char_array_type(end - start), name)
            elif hasattr(bv, "define_user_data_var"):
                bv.define_user_data_var(start, _char_array_type(end - start), name)
            else:
                _define_symbol(
                    bv,
                    Symbol(SymbolType.DataSymbol, start, name),
                    auto_defined=auto_defined,
                )
            defined += 1
        except Exception as exc:
            log_warn(f"Could not define ASCII string data at {start:#x}: {exc}")
    if verbose and defined:
        print(f"Defined {defined} printable ASCII flash string data variable(s).")
    return defined


def _define_ascii_string_gap_data_vars(
    bv: BinaryView,
    *,
    auto_defined: bool = False,
    verbose: bool = False,
) -> int:
    defined = 0
    for start, end in _flash_ascii_string_gap_spans(bv):
        if _has_data_var_at(bv, start):
            continue
        name = f"strgap_{start:05x}"
        try:
            if auto_defined and hasattr(bv, "define_data_var"):
                bv.define_data_var(start, _uint8_array_type(end - start), name)
            elif hasattr(bv, "define_user_data_var"):
                bv.define_user_data_var(start, _uint8_array_type(end - start), name)
            else:
                _define_symbol(
                    bv,
                    Symbol(SymbolType.DataSymbol, start, name),
                    auto_defined=auto_defined,
                )
            defined += 1
        except Exception as exc:
            log_warn(f"Could not define ASCII string gap data at {start:#x}: {exc}")
    if verbose and defined:
        print(f"Defined {defined} inter-string flash data gap variable(s).")
    return defined


def _define_numeric_lookup_table_data_vars(
    bv: BinaryView,
    *,
    auto_defined: bool = False,
    verbose: bool = False,
) -> int:
    defined = 0
    for start, end in _flash_numeric_lookup_table_spans(bv):
        if _has_data_var_at(bv, start):
            continue
        name = f"lookup_{start:05x}"
        try:
            if auto_defined and hasattr(bv, "define_data_var"):
                bv.define_data_var(start, _uint8_array_type(end - start), name)
            elif hasattr(bv, "define_user_data_var"):
                bv.define_user_data_var(start, _uint8_array_type(end - start), name)
            else:
                _define_symbol(
                    bv,
                    Symbol(SymbolType.DataSymbol, start, name),
                    auto_defined=auto_defined,
                )
            defined += 1
        except Exception as exc:
            log_warn(f"Could not define numeric lookup table data at {start:#x}: {exc}")
    if verbose and defined:
        print(f"Defined {defined} numeric flash lookup table data variable(s).")
    return defined


def _define_address_jump_table_data_vars(
    bv: BinaryView,
    *,
    auto_defined: bool = False,
    verbose: bool = False,
) -> int:
    defined = 0
    for _source_addr, start, targets in _flash_address_jump_tables(bv):
        for index, target in enumerate(targets):
            _set_comment_if_empty(
                bv,
                start + index * 4,
                f"Jump table target: {target:#x}",
                auto_defined=auto_defined,
            )
        if _has_data_var_at(bv, start):
            continue
        name = f"jumptable_{start:05x}"
        table_type = _uint32_array_type(len(targets))
        try:
            if auto_defined and hasattr(bv, "define_data_var"):
                bv.define_data_var(start, table_type, name)
            elif hasattr(bv, "define_user_data_var"):
                bv.define_user_data_var(start, table_type, name)
            else:
                _define_symbol(
                    bv,
                    Symbol(SymbolType.DataSymbol, start, name),
                    auto_defined=auto_defined,
                )
            defined += 1
        except Exception as exc:
            log_warn(f"Could not define address jump table data at {start:#x}: {exc}")
    if verbose and defined:
        print(f"Defined {defined} address jump table data variable(s).")
    return defined


def _cinit_record_comment(target: int, length: int) -> str:
    return f"C init: copy {length:#x} byte(s) to {target:#05x}"


def _define_cinit_table_data_vars(
    bv: BinaryView,
    *,
    auto_defined: bool = False,
    verbose: bool = False,
) -> int:
    defined = 0
    for start, end, target, length in _flash_cinit_table_records(bv):
        name = f"cinit_{start:05x}_to_{target:05x}"
        added = False
        if not _has_data_var_at(bv, start):
            try:
                if auto_defined and hasattr(bv, "define_data_var"):
                    bv.define_data_var(start, _uint8_array_type(end - start), name)
                elif hasattr(bv, "define_user_data_var"):
                    bv.define_user_data_var(start, _uint8_array_type(end - start), name)
                else:
                    _define_symbol(
                        bv,
                        Symbol(SymbolType.DataSymbol, start, name),
                        auto_defined=auto_defined,
                    )
                added = True
            except Exception as exc:
                log_warn(f"Could not define C initializer record data at {start:#x}: {exc}")

        if not _symbol_exists(bv, name, start):
            try:
                _define_symbol(
                    bv,
                    Symbol(SymbolType.DataSymbol, start, name),
                    auto_defined=auto_defined,
                )
                added = True
            except Exception as exc:
                log_warn(f"Could not define C initializer record symbol at {start:#x}: {exc}")

        if _set_comment_if_empty(
            bv,
            start,
            _cinit_record_comment(target, length),
            auto_defined=auto_defined,
        ):
            added = True

        if added:
            defined += 1
    if verbose and defined:
        print(f"Defined or annotated {defined} C initializer flash record(s).")
    return defined


def _define_ascii_string_padding_data_vars(
    bv: BinaryView,
    *,
    auto_defined: bool = False,
    verbose: bool = False,
) -> int:
    defined = 0
    for start, end in _flash_ascii_string_padding_spans(bv):
        if _has_data_var_at(bv, start):
            continue
        name = f"strpad_{start:05x}"
        try:
            if auto_defined and hasattr(bv, "define_data_var"):
                bv.define_data_var(start, _uint8_array_type(end - start), name)
            elif hasattr(bv, "define_user_data_var"):
                bv.define_user_data_var(start, _uint8_array_type(end - start), name)
            else:
                _define_symbol(
                    bv,
                    Symbol(SymbolType.DataSymbol, start, name),
                    auto_defined=auto_defined,
                )
            defined += 1
        except Exception as exc:
            log_warn(f"Could not define ASCII string padding data at {start:#x}: {exc}")
    if verbose and defined:
        print(f"Defined {defined} short ASCII-string padding data variable(s).")
    return defined


def _view_type_name(bv: BinaryView) -> str:
    view_type = getattr(bv, "view_type", None)
    view_name = getattr(view_type, "name", None)
    if view_name is None:
        view_name = str(view_type or "")
    return view_name


def _is_raw_binary_view(bv: BinaryView) -> bool:
    return _view_type_name(bv).lower() == "raw"


def _is_msp430f5438_mapped_view(bv: BinaryView) -> bool:
    return _view_type_name(bv) == "MSP430F5438"


def _section_names(bv: BinaryView) -> set[str]:
    sections = getattr(bv, "sections", {})
    if isinstance(sections, dict):
        return set(sections.keys())
    try:
        return {getattr(section, "name", "") for section in sections}
    except Exception:
        return set()


def _mapped_regions_present(bv: BinaryView, regions: Iterable[Region]) -> bool:
    names = _section_names(bv)
    for region in regions:
        prefix = f"{region.name}."
        if not any(name == region.name or name.startswith(prefix) for name in names):
            return False
    return True


def _update_analysis(bv: BinaryView) -> None:
    try:
        bv.update_analysis_and_wait()
    except Exception:
        bv.update_analysis()


def _function_block_ranges(func) -> tuple[AddressSpan, ...]:
    blocks = getattr(func, "basic_blocks", None)
    if blocks:
        ranges = []
        for block in blocks:
            start = getattr(block, "start", None)
            end = getattr(block, "end", None)
            if start is None or end is None or end <= start:
                continue
            ranges.append((start, end))
        return tuple(ranges)

    start = getattr(func, "start", None)
    end = getattr(func, "highest_address", None)
    if start is None or end is None or end <= start:
        return ()
    return ((start, end),)


def _cpux_fallbacks_in_functions(
    bv: BinaryView,
    *,
    max_hits: int = 32,
) -> tuple[CpuxFallback, ...]:
    """Collect undecoded CPUX fallback instructions from analyzed functions."""

    arch = getattr(bv, "arch", None)
    if arch is None:
        return ()

    hits = []
    max_len = 10
    for func in getattr(bv, "functions", []):
        func_name = getattr(func, "name", f"sub_{getattr(func, 'start', 0):x}")
        for start, end in _function_block_ranges(func):
            addr = start
            while addr + 2 <= end:
                try:
                    data = bytes(bv.read(addr, max_len))
                except Exception:
                    break
                if len(data) < 2:
                    break
                try:
                    tokens, length = arch.get_instruction_text(data, addr)
                except Exception:
                    break
                text = "".join(token.text for token in tokens)
                if length is None or length <= 0:
                    length = 2
                if text.startswith("cpux "):
                    hits.append((addr, func_name, text, data[: min(length, len(data))]))
                    if len(hits) >= max_hits:
                        return tuple(hits)
                addr += max(2, length)
    return tuple(hits)


def report_cpux_fallbacks(bv: BinaryView) -> None:
    """Print undecoded CPUX words that occur inside analyzed functions."""

    hits = _cpux_fallbacks_in_functions(bv)
    if not hits:
        print("No CPUX fallback instructions found inside analyzed functions.")
        return

    print(f"Found {len(hits)} possible CPUX fallback instruction(s) inside analyzed functions:")
    for addr, func_name, text, raw in hits:
        print(f"  {addr:#08x} {func_name}: {raw.hex()} {text}")


def diagnose_msp430f5438_view(bv: BinaryView) -> None:
    """Print concise mapping and decoder diagnostics for the active view."""

    spec = DEFAULT_DEVICE_SPEC
    raw_len = _raw_length(bv)
    reset = _read_u16(bv, spec.reset_vector)
    view_type = _view_type_name(bv)
    regions = spec.regions
    mapped_count = sum(1 for region in regions if _mapped_regions_present(bv, (region,)))
    erased_function_count = sum(
        1
        for func in getattr(bv, "functions", [])
        if _is_erased_flash_function_start(bv, getattr(func, "start", -1))
    )
    print(f"view_type={view_type} arch={getattr(bv, 'arch', None)} platform={getattr(bv, 'platform', None)}")
    print(f"raw_len={raw_len:#x} view_start={getattr(bv, 'start', 0):#x} view_end={getattr(bv, 'end', 0):#x}")
    print(f"mapped_sections={mapped_count}/{len(regions)}")
    print(f"erased_flash_functions={erased_function_count}")
    cpux_fallbacks = _cpux_fallbacks_in_functions(bv)
    print(f"cpux_fallback_functions={len(cpux_fallbacks)}")
    for addr, func_name, text, raw in cpux_fallbacks[:8]:
        print(f"  {addr:#08x} {func_name}: {raw.hex()} {text}")
    print(f"reset_vector={reset if reset is None else hex(reset)}")
    if reset is None:
        print("Reset vector is unreadable. Re-run with the correct image_base for this dump.")
    elif not _is_probable_code_pointer(reset):
        print("Reset vector does not look like a valid low-flash/RAM code pointer.")
    else:
        print("Reset vector looks usable.")


def _emit_raw_view_guidance() -> None:
    msg = (
        "This is BN's Raw view. Raw views cannot accept memory segments, so the "
        "MSP430F5438 map must be applied while loading a mapped/custom view. "
        "Run register_msp430f5438_binary_view(), then reopen the file with "
        "'MSP430F5438 Raw Firmware (MSP430X)' / view type 'MSP430F5438'."
    )
    print(msg)
    log_warn(msg)


def _spec_for_variant(variant: str = DEVICE_VARIANT) -> DeviceSpec:
    normalized = variant.strip().upper()
    spec_name = DEVICE_SPEC_ALIASES.get(normalized)
    if spec_name is None:
        known = ", ".join(spec.name for spec in DEVICE_SPECS)
        raise ValueError(f"Unknown variant {variant!r}; use one of: {known}")
    return DEVICE_SPEC_BY_NAME[spec_name]


def _regions_for_variant(variant: str) -> tuple[Region, ...]:
    return _spec_for_variant(variant).regions


def _refresh_msp430x_analysis(
    bv: BinaryView,
    *,
    variant: str = DEVICE_VARIANT,
    arch_name: Optional[str] = "msp430x",
    add_reset_entry: bool = True,
    enable_linear_sweep: bool = False,
    cleanup_peripheral_functions: bool = True,
    verbose: bool = True,
) -> int:
    """Reapply analysis annotations without rebuilding the memory segments."""

    spec = _spec_for_variant(variant)
    arch = _configure_architecture(bv, arch_name, verbose, set_platform=True)
    _enable_analysis_options(bv, enable_linear_sweep)
    if cleanup_peripheral_functions:
        _cleanup_peripheral_functions(bv, verbose)

    vector_functions = 0
    if add_reset_entry:
        vector_functions = _seed_interrupt_vectors(
            bv,
            verbose,
            spec=spec,
            create_functions=getattr(bv, "platform", None) is not None,
        )
    _define_symbols(bv, spec.symbols)
    apply_msp430_header_labels(bv, verbose=verbose)
    _remove_boundary_symbols_at_function_starts(bv, verbose, spec.symbols)
    _cleanup_erased_flash_functions(bv, verbose)
    _cleanup_ascii_string_functions(bv, verbose)
    _cleanup_numeric_lookup_table_functions(bv, verbose)
    _cleanup_address_jump_table_functions(bv, verbose)
    _cleanup_cinit_table_functions(bv, verbose)
    _define_ascii_string_data_vars(bv, verbose=verbose)
    _define_ascii_string_padding_data_vars(bv, verbose=verbose)
    _define_ascii_string_gap_data_vars(bv, verbose=verbose)
    _define_numeric_lookup_table_data_vars(bv, verbose=verbose)
    _define_address_jump_table_data_vars(bv, verbose=verbose)
    _define_cinit_table_data_vars(bv, verbose=verbose)
    _seed_address_jump_table_target_functions(bv, verbose=verbose)
    _seed_address_jump_table_indirect_branches(bv, verbose=verbose)

    _update_analysis(bv)

    if verbose and arch is None:
        print(
            "Map is present, but BN has no MSP430/MSP430X architecture loaded. "
            "You will get sections/symbols, not real disassembly/decompilation."
        )
    if verbose and vector_functions == 0:
        print(
            "No vector target functions were created. If this is a raw dump, "
            "try image_base=0x5c00 for main flash or image_base=0 for a full image."
        )

    log_info(
        "Refreshed MSP430X analysis "
        f"variant={variant}, vector_functions={vector_functions}"
    )
    return vector_functions


def apply_msp430f5438_memory_map(
    bv: BinaryView,
    *,
    variant: str = DEVICE_VARIANT,
    image_base: Optional[int] = None,
    arch_name: Optional[str] = None,
    remove_flat_raw_segment: bool = True,
    add_reset_entry: bool = True,
    enable_linear_sweep: bool = False,
    cleanup_peripheral_functions: bool = True,
    verbose: bool = True,
) -> None:
    """
    Apply MSP430F5438/F5438A segments and sections to the active BinaryView.

    image_base:
        None      -> auto-detect full address-space image vs main-flash dump.
        0x005c00  -> first file byte maps to main flash start.
        0x000000  -> first file byte maps to address zero.
        any addr  -> first file byte maps to that virtual address.

    arch_name:
        Optional Binary Ninja architecture name. If omitted, this tries msp430x
        first, then plain msp430 if that is all Binary Ninja has available.
    """

    if _is_raw_binary_view(bv):
        register_msp430f5438_binary_view()
        _emit_raw_view_guidance()
        return

    spec = _spec_for_variant(variant)
    raw_len = _raw_length(bv)
    effective_image_base = _detect_image_base(bv, raw_len)
    if image_base is not None:
        effective_image_base = image_base

    regions = spec.regions
    if _is_msp430f5438_mapped_view(bv) and _mapped_regions_present(bv, regions):
        if verbose:
            print(
                f"{spec.name} mapped view already has its memory map; "
                "refreshing architecture, vector functions, and analysis without rebuilding segments."
            )
        _refresh_msp430x_analysis(
            bv,
            variant=variant,
            arch_name=arch_name or "msp430x",
            add_reset_entry=add_reset_entry,
            enable_linear_sweep=enable_linear_sweep,
            cleanup_peripheral_functions=cleanup_peripheral_functions,
            verbose=verbose,
        )
        return

    arch = _configure_architecture(bv, arch_name, verbose, set_platform=True)
    _remove_previous_map(bv, ALL_KNOWN_MAP_REGIONS)
    if remove_flat_raw_segment:
        _remove_flat_raw_segment(bv, raw_len, effective_image_base)

    try:
        bv.begin_bulk_add_segments()
    except Exception:
        pass

    try:
        for region in regions:
            _add_region(bv, region, raw_len, effective_image_base)
    finally:
        try:
            bv.end_bulk_add_segments()
        except Exception:
            pass

    _enable_analysis_options(bv, enable_linear_sweep)
    if cleanup_peripheral_functions:
        _cleanup_peripheral_functions(bv, verbose)

    vector_functions = 0
    if add_reset_entry:
        vector_functions = _seed_interrupt_vectors(
            bv,
            verbose,
            spec=spec,
            create_functions=getattr(bv, "platform", None) is not None,
        )
    _define_symbols(bv, spec.symbols)
    apply_msp430_header_labels(bv, verbose=verbose)
    _remove_boundary_symbols_at_function_starts(bv, verbose, spec.symbols)
    _cleanup_erased_flash_functions(bv, verbose)
    _cleanup_ascii_string_functions(bv, verbose)
    _cleanup_numeric_lookup_table_functions(bv, verbose)
    _cleanup_address_jump_table_functions(bv, verbose)
    _cleanup_cinit_table_functions(bv, verbose)
    _define_ascii_string_data_vars(bv, verbose=verbose)
    _define_ascii_string_padding_data_vars(bv, verbose=verbose)
    _define_ascii_string_gap_data_vars(bv, verbose=verbose)
    _define_numeric_lookup_table_data_vars(bv, verbose=verbose)
    _define_address_jump_table_data_vars(bv, verbose=verbose)
    _define_cinit_table_data_vars(bv, verbose=verbose)
    _seed_address_jump_table_target_functions(bv, verbose=verbose)
    _seed_address_jump_table_indirect_branches(bv, verbose=verbose)

    _update_analysis(bv)

    if verbose and arch is None:
        print(
            "Map is applied, but BN has no MSP430/MSP430X architecture loaded. "
            "You will get sections/symbols, not real disassembly/decompilation."
        )
    if verbose and vector_functions == 0:
        print(
            "No vector target functions were created. If this is a raw dump, "
            "try image_base=0x5c00 for main flash or image_base=0 for a full image."
        )

    log_info(
        f"Applied {spec.name} memory map "
        f"variant={variant}, raw_len={raw_len:#x}, image_base={effective_image_base:#x}, "
        f"flash={spec.flash_start:#x}-{spec.flash_end:#x}, ram={spec.ram_start:#x}-{spec.ram_end:#x}, "
        f"vector_functions={vector_functions}"
    )


def apply_msp430f5438a_memory_map(bv: BinaryView) -> None:
    """Apply the auto-based MSP430F5438A map to the active view."""

    apply_msp430f5438_memory_map(bv, variant="MSP430F5438A")


def apply_msp430f5438_main_flash_memory_map(bv: BinaryView) -> None:
    """Map an MSP430F5438 main-flash dump beginning at address 0x5c00."""

    apply_msp430f5438_memory_map(bv, image_base=FLASH_START, arch_name="msp430x")


def apply_msp430f5438_full_image_memory_map(bv: BinaryView) -> None:
    """Map a full-address-space MSP430F5438 image beginning at address zero."""

    apply_msp430f5438_memory_map(bv, image_base=0, arch_name="msp430x")


def apply_msp430f5438a_main_flash_memory_map(bv: BinaryView) -> None:
    """Map an MSP430F5438A main-flash dump beginning at address 0x5c00."""

    apply_msp430f5438_memory_map(bv, variant="MSP430F5438A", image_base=FLASH_START, arch_name="msp430x")


def apply_msp430f5438a_full_image_memory_map(bv: BinaryView) -> None:
    """Map a full-address-space MSP430F5438A image beginning at address zero."""

    apply_msp430f5438_memory_map(bv, variant="MSP430F5438A", image_base=0, arch_name="msp430x")


def rerun_msp430x_analysis(bv: BinaryView) -> None:
    """Refresh architecture-aware analysis for an already mapped view."""

    if _is_raw_binary_view(bv):
        register_msp430f5438_binary_view()
        _emit_raw_view_guidance()
        return

    vector_functions = _refresh_msp430x_analysis(bv, arch_name="msp430x", verbose=True)
    print(f"Re-ran MSP430X analysis and refreshed {vector_functions} vector target function(s).")
    diagnose_msp430f5438_view(bv)


class MSP430F5438BinaryView(BinaryView):
    """Mapped raw-firmware view prepared before Binary Ninja analyzes code."""

    name = "MSP430F5438"
    long_name = "MSP430F5438 Raw Firmware (MSP430X)"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data
        self.spec = DEFAULT_DEVICE_SPEC
        self._entry_point = self.spec.flash_start

    @classmethod
    def is_valid_for_data(cls, data):
        """Return whether the data contains a plausible MSP430 vector table."""

        raw_len = _raw_length(data)
        return _has_probable_msp430_vector_table(data, raw_len)

    @classmethod
    def is_force_loadable(cls):
        return True

    @classmethod
    def get_load_settings_for_data(cls, data):
        """Build read-only platform and image-base defaults for candidate data."""

        raw_len = _raw_length(data)
        image_base = _detect_image_base(data, raw_len)
        platform_name = _msp430x_platform_name()

        load_settings = Settings("msp430f5438_load_settings")
        load_settings.set_resource_id(cls.name)
        _set_load_setting_default(load_settings, "loader.platform", platform_name)
        _set_load_setting_default(load_settings, "loader.imageBase", image_base)
        _set_load_setting_default(load_settings, "loader.entryPointOffset", 0)
        _set_load_setting_value(load_settings, "loader.platform", platform_name)
        _set_load_setting_value(load_settings, "loader.imageBase", image_base)
        _set_load_setting_value(load_settings, "loader.entryPointOffset", 0)
        return load_settings

    def init(self):
        """Create device segments, seed symbols/vectors, and select the entry point."""

        spec = self.spec
        raw_len = _raw_length(self.raw)
        image_base = _detect_image_base(self.raw, raw_len)
        regions = spec.regions
        if getattr(self, "parse_only", False):
            reset = _read_raw_u16(self.raw, spec.reset_vector - image_base)
            if reset is not None and _is_probable_code_pointer(reset):
                self._entry_point = reset
            return True

        self.begin_bulk_add_segments()
        try:
            for region in regions:
                _add_region(
                    self,
                    region,
                    raw_len,
                    image_base,
                    auto_defined=True,
                )
        finally:
            self.end_bulk_add_segments()

        _configure_architecture(self, "msp430x", False, set_platform=True)
        vector_functions = _seed_interrupt_vectors(
            self,
            False,
            spec=spec,
            auto_defined=True,
            create_functions=getattr(self, "platform", None) is not None,
        )
        _define_symbols(self, spec.symbols, auto_defined=True)
        try:
            apply_msp430_header_labels(self, auto_defined=True, verbose=False)
        except Exception as exc:
            log_warn(f"Could not apply MSP430 header labels during load: {exc}")
        _remove_boundary_symbols_at_function_starts(self, symbols=spec.symbols)
        _cleanup_erased_flash_functions(self, False)
        _cleanup_ascii_string_functions(self, False)
        _cleanup_numeric_lookup_table_functions(self, False)
        _cleanup_address_jump_table_functions(self, False)
        _cleanup_cinit_table_functions(self, False)
        _define_ascii_string_data_vars(self, auto_defined=True, verbose=False)
        _define_ascii_string_padding_data_vars(self, auto_defined=True, verbose=False)
        _define_ascii_string_gap_data_vars(self, auto_defined=True, verbose=False)
        _define_numeric_lookup_table_data_vars(self, auto_defined=True, verbose=False)
        _define_address_jump_table_data_vars(self, auto_defined=True, verbose=False)
        _define_cinit_table_data_vars(self, auto_defined=True, verbose=False)
        _seed_address_jump_table_target_functions(self, verbose=False)
        _seed_address_jump_table_indirect_branches(self, verbose=False)
        reset = _read_u16(self, spec.reset_vector)
        if reset is not None and _is_probable_code_pointer(reset):
            self._entry_point = reset

        log_info(
            f"Loaded {spec.name} mapped firmware view "
            f"raw_len={raw_len:#x}, image_base={image_base:#x}, "
            f"entry={self._entry_point:#x}, vector_functions={vector_functions}"
        )
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self._entry_point

    def perform_get_address_size(self):
        return 4


def register_msp430f5438_binary_view() -> None:
    """Register the mapped view and its default MSP430X platform once."""

    _try_load_local_msp430x_plugin()
    if _binary_view_type_registered(MSP430F5438BinaryView.name):
        _register_msp430f5438_default_platform()
        return
    try:
        MSP430F5438BinaryView.register()
        _register_msp430f5438_default_platform()
        print("Registered MSP430F5438 Raw Firmware (MSP430X) BinaryView.")
    except Exception as exc:
        text = str(exc).lower()
        if "already" not in text and "duplicate" not in text:
            log_warn(f"Could not register MSP430F5438 BinaryView: {exc}")
        _register_msp430f5438_default_platform()


def _register_msp430f5438_default_platform() -> None:
    """Associate the mapped BinaryView with the registered MSP430X platform."""

    global _REGISTERED_PLATFORM_RECOGNIZER

    arch = _find_msp430_arch("msp430x")
    platform = getattr(arch, "standalone_platform", None) if arch is not None else None
    if arch is None or platform is None:
        return

    view_type = getattr(MSP430F5438BinaryView, "registered_view_type", None)
    if view_type is None:
        try:
            view_type = BinaryViewType[MSP430F5438BinaryView.name]
        except Exception:
            return

    try:
        view_type.register_arch(0, Endianness.LittleEndian, arch)
        view_type.register_platform(0, arch, platform)
        view_type.register_default_platform(arch, platform)
        if not _REGISTERED_PLATFORM_RECOGNIZER:
            view_type.register_platform_recognizer(
                0,
                Endianness.LittleEndian,
                lambda _view, _metadata: platform,
            )
            _REGISTERED_PLATFORM_RECOGNIZER = True
        log_info(f"Registered MSP430F5438 default platform: {platform}")
    except Exception as exc:
        log_warn(f"Could not register MSP430F5438 default platform: {exc}")


def _binary_view_type_registered(name: str) -> bool:
    try:
        if name in BinaryViewType:
            return True
    except Exception:
        pass

    try:
        return any(getattr(view_type, "name", None) == name for view_type in BinaryViewType)
    except Exception:
        return False


register_msp430f5438_binary_view()


# PluginCommand is unavailable in some headless/API contexts. The architecture
# and BinaryView remain usable there, so command registration is best-effort.
try:
    PluginCommand.register_global(
        "MSP430F5438\\Register mapped raw firmware view",
        "Register the MSP430F5438 mapped BinaryView and MSP430X architecture.",
        register_msp430f5438_binary_view,
    )
    PluginCommand.register(
        "MSP430F5438\\Apply memory map (auto base)",
        "Create or refresh MSP430F5438 segments, sections, vectors, RAM, BSL, and flash banks using base autodetection.",
        apply_msp430f5438_memory_map,
    )
    PluginCommand.register(
        "MSP430F5438\\Apply memory map (main flash @ 0x5c00)",
        "Create or refresh the MSP430F5438 map for a main-flash dump whose first byte maps to 0x5c00.",
        apply_msp430f5438_main_flash_memory_map,
    )
    PluginCommand.register(
        "MSP430F5438\\Apply memory map (full image @ 0)",
        "Create or refresh the MSP430F5438 map for a full address-space image whose first byte maps to 0.",
        apply_msp430f5438_full_image_memory_map,
    )
    PluginCommand.register(
        "MSP430F5438\\Diagnose active view",
        "Print MSP430F5438 architecture, range, and reset-vector diagnostics for the active view.",
        diagnose_msp430f5438_view,
    )
    PluginCommand.register(
        "MSP430F5438\\Report CPUX fallback instructions",
        "Print any undecoded CPUX fallback instructions that remain inside analyzed functions.",
        report_cpux_fallbacks,
    )
    PluginCommand.register(
        "MSP430F5438\\Re-run MSP430X analysis",
        "Refresh MSP430X architecture, vector functions, and Binary Ninja analysis without rebuilding segments.",
        rerun_msp430x_analysis,
    )
    PluginCommand.register(
        "MSP430F5438\\Apply MSP430 header labels",
        "Apply SFR, peripheral, vector, TLV, and board-alias labels parsed from MSP430 headers.",
        apply_msp430_header_labels,
    )
    PluginCommand.register(
        "MSP430F5438A\\Apply memory map (auto base)",
        "Create or refresh MSP430F5438A segments, sections, vectors, RAM, BSL, and flash banks using base autodetection.",
        apply_msp430f5438a_memory_map,
    )
    PluginCommand.register(
        "MSP430F5438A\\Apply memory map (main flash @ 0x5c00)",
        "Create or refresh the MSP430F5438A map for a main-flash dump whose first byte maps to 0x5c00.",
        apply_msp430f5438a_main_flash_memory_map,
    )
    PluginCommand.register(
        "MSP430F5438A\\Apply memory map (full image @ 0)",
        "Create or refresh the MSP430F5438A map for a full address-space image whose first byte maps to 0.",
        apply_msp430f5438a_full_image_memory_map,
    )
except Exception:
    pass
