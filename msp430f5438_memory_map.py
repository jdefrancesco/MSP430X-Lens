"""MSP430F5438/F5438A raw-firmware BinaryView and analysis helpers. Note ELF works as well."""

from __future__ import annotations

import bisect
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
    FunctionParameter,
    PluginCommand,
    SectionSemantics,
    SegmentFlag,
    Settings,
    SettingsScope,
    StructureBuilder,
    StructureMember,
    Symbol,
    SymbolType,
    Type,
    core_version,
    log_info,
    log_warn,
)
from binaryninja import _binaryninjacore as _bn_core
from binaryninja.enums import FunctionUpdateType, RegisterValueType, VariableSourceType

try:
    from .msp430_tlv import (
        TLV_REGION_END,
        TLV_REGION_SIZE,
        TLV_REGION_START,
        TLV_TAG_ADC12_CAL,
        TLV_TAG_ADC12_CAL_F5438,
        TLV_TAG_DIE_RECORD,
        TLV_TAG_PERIPHERAL,
        TLV_TAG_REF_CAL,
        TlvDescriptorBlock,
        TlvRecord,
        decode_peripheral_descriptor,
        parse_tlv_descriptor_block,
    )
except ImportError:
    from msp430_tlv import (
        TLV_REGION_END,
        TLV_REGION_SIZE,
        TLV_REGION_START,
        TLV_TAG_ADC12_CAL,
        TLV_TAG_ADC12_CAL_F5438,
        TLV_TAG_DIE_RECORD,
        TLV_TAG_PERIPHERAL,
        TLV_TAG_REF_CAL,
        TlvDescriptorBlock,
        TlvRecord,
        decode_peripheral_descriptor,
        parse_tlv_descriptor_block,
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
# The TI headers call the record-stream address (0x1a08) TLV_START.  Preserve
# these older module aliases for callers while keeping the region and stream
# concepts distinct in new code.
TLV_START = TLV_REGION_START
TLV_END = TLV_REGION_END
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
DEVICE_VARIANT_METADATA_KEY = "msp430x_lens.device_variant"


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


@dataclass(frozen=True, slots=True)
class TlvSpec:
    """Variant-specific factory device-descriptor expectations."""

    region_start: int
    region_end: int
    expected_device_id: bytes

    @property
    def region_size(self) -> int:
        return self.region_end - self.region_start + 1


@dataclass(frozen=True, slots=True)
class _TlvReadResult:
    """Backing-aware result for one BinaryView TLV inspection."""

    status: str
    block: Optional[TlvDescriptorBlock]
    backed_bytes: int
    detail: str = ""


AddressSpan = tuple[int, int]
SymbolDefinition = tuple[str, int]
VectorDefinition = tuple[int, str, str]
AddressJumpTable = tuple[int, int, tuple[int, ...]]
CinitRecordInfo = tuple[int, int, int]
CinitRecord = tuple[int, int, int, int]
CinitCandidate = tuple[int, int, tuple[CinitRecord, ...]]
CpuxFallback = tuple[int, str, str, bytes]


@dataclass(frozen=True, slots=True)
class _RoutineShape:
    """Conservative bounds and terminal-flow kind for one decoded routine."""

    length: int
    termination_kind: str
    instruction_count: int


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
    tlv: Optional[TlvSpec] = None

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
SPARSE_CODE_ISLAND_RETURN_SCAN_BYTES = 0x1000
EXECUTABLE_SEGMENT_SCAN_MAX_BYTES = 0x200000
ASCII_STRING_MIN_LEN = 8
STRING_CALL_MAX_BYTES = 0x400
AUTO_STRING_MIN_LENGTH_SETTING = "analysis.limits.minStringLength"
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


MSP430F5438_TLV_SPEC = TlvSpec(
    region_start=TLV_REGION_START,
    region_end=TLV_REGION_END,
    expected_device_id=b"\x54\x38",
)

MSP430F5438A_TLV_SPEC = TlvSpec(
    region_start=TLV_REGION_START,
    region_end=TLV_REGION_END,
    expected_device_id=b"\x05\x80",
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
    tlv=MSP430F5438_TLV_SPEC,
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
    tlv=MSP430F5438A_TLV_SPEC,
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


def _set_view_device_spec(bv: BinaryView, spec: DeviceSpec) -> None:
    try:
        bv.spec = spec
    except Exception:
        pass
    try:
        bv.store_metadata(DEVICE_VARIANT_METADATA_KEY, spec.name, isAuto=True)
    except Exception:
        pass


def _device_spec_for_view(bv: BinaryView) -> DeviceSpec:
    spec = getattr(bv, "spec", None)
    if isinstance(spec, DeviceSpec):
        return spec
    try:
        variant = bv.query_metadata(DEVICE_VARIANT_METADATA_KEY)
    except Exception:
        variant = None
    if isinstance(variant, str):
        spec_name = DEVICE_SPEC_ALIASES.get(variant.upper())
        if spec_name is not None:
            return DEVICE_SPEC_BY_NAME[spec_name]
    detector = globals().get("_detect_device_spec_from_mapped_tlv")
    if detector is not None:
        try:
            detected = detector(bv)
        except Exception:
            detected = None
        if isinstance(detected, DeviceSpec):
            _set_view_device_spec(bv, detected)
            return detected
    return DEFAULT_DEVICE_SPEC


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


def _detect_device_spec_from_tlv(
    bv: BinaryView,
    image_base: int,
) -> Optional[DeviceSpec]:
    """Identify a supported variant from backed factory device-ID bytes."""

    data_offset = TLV_REGION_START - image_base
    if data_offset < 0:
        return None
    data = _read_file_bytes(bv, data_offset, TLV_REGION_SIZE)
    if len(data) != TLV_REGION_SIZE:
        return None
    try:
        block = parse_tlv_descriptor_block(data, base=TLV_REGION_START)
    except ValueError:
        return None
    if block.erased or block.issues or not block.crc_valid:
        return None
    for spec in DEVICE_SPECS:
        if spec.tlv is not None and block.device_id == spec.tlv.expected_device_id:
            return spec
    return None


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


def _backed_island_spans(
    data: bytes,
    base: int = 0,
    min_erased_run: int = ERASED_FLASH_MIN_RUN,
) -> tuple[AddressSpan, ...]:
    """Return non-erased islands separated by long runs of erased flash."""

    erased = _erased_spans(data, min_erased_run)
    if not erased:
        return ((base, base + len(data)),) if data else ()

    islands = []
    cursor = 0
    for erased_start, erased_end in erased:
        if cursor < erased_start:
            islands.append((base + cursor, base + erased_start))
        cursor = erased_end
    if cursor < len(data):
        islands.append((base + cursor, base + len(data)))
    return tuple(islands)


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


def _configure_auto_string_minimum(bv: BinaryView) -> int:
    """Raise BN's inherited string minimum before the first analysis pass."""

    settings = Settings()
    try:
        current, scope = settings.get_integer_with_scope(
            AUTO_STRING_MIN_LENGTH_SETTING,
            bv,
        )
    except Exception as exc:
        log_warn(f"Could not read Binary Ninja's automatic-string minimum: {exc}")
        return 0

    # Only replace the inherited schema default. Preserve every explicit User,
    # Project, or Resource value, including load-option overrides.
    if scope != SettingsScope.SettingsDefaultScope or current >= ASCII_STRING_MIN_LEN:
        return current

    try:
        changed = settings.set_integer(
            AUTO_STRING_MIN_LENGTH_SETTING,
            ASCII_STRING_MIN_LEN,
            bv,
            SettingsScope.SettingsResourceScope,
        )
    except Exception as exc:
        log_warn(f"Could not set Binary Ninja's automatic-string minimum: {exc}")
        return current

    if not changed:
        log_warn("Binary Ninja rejected the MSP430 firmware automatic-string minimum.")
        return current
    return ASCII_STRING_MIN_LEN


def _read_u16(bv: BinaryView, addr: int) -> Optional[int]:
    try:
        data = bv.read(addr, 2)
    except Exception:
        return None
    if len(data) != 2:
        return None
    return data[0] | (data[1] << 8)


def _is_file_backed_byte(bv: BinaryView, addr: int) -> bool:
    """Return whether ``addr`` comes from the input file, not segment fill."""

    checker = getattr(bv, "is_offset_backed_by_file", None)
    if checker is not None:
        try:
            return bool(checker(addr))
        except Exception:
            return False

    getter = getattr(bv, "get_segment_at", None)
    if getter is None:
        return False
    try:
        segment = getter(addr)
        if segment is None:
            return False
        data_length = int(getattr(segment, "data_length", 0))
        return segment.start <= addr < segment.start + data_length
    except Exception:
        return False


def _detect_device_spec_from_mapped_tlv(bv: BinaryView) -> Optional[DeviceSpec]:
    """Identify a supported variant from a mapped, CRC-valid TLV block."""

    if not all(
        _is_file_backed_byte(bv, addr)
        for addr in range(TLV_REGION_START, TLV_REGION_END + 1)
    ):
        return None
    try:
        data = bytes(bv.read(TLV_REGION_START, TLV_REGION_SIZE))
        block = parse_tlv_descriptor_block(data, base=TLV_REGION_START)
    except Exception:
        return None
    if block.erased or block.issues or not block.crc_valid:
        return None
    for spec in DEVICE_SPECS:
        if spec.tlv is not None and block.device_id == spec.tlv.expected_device_id:
            return spec
    return None


def _read_tlv_descriptor(
    bv: BinaryView,
    spec: Optional[DeviceSpec] = None,
) -> _TlvReadResult:
    """Read and parse a fully file-backed factory descriptor block."""

    if spec is None:
        spec = _device_spec_for_view(bv)
    layout = spec.tlv
    if layout is None:
        return _TlvReadResult("unsupported", None, 0, "device profile has no TLV layout")

    backed = tuple(
        _is_file_backed_byte(bv, addr)
        for addr in range(layout.region_start, layout.region_end + 1)
    )
    backed_count = sum(backed)
    if backed_count == 0:
        return _TlvReadResult("absent", None, 0, "descriptor region is not file-backed")
    if backed_count != layout.region_size:
        return _TlvReadResult(
            "partial",
            None,
            backed_count,
            f"only {backed_count:#x}/{layout.region_size:#x} descriptor bytes are file-backed",
        )

    try:
        data = bytes(bv.read(layout.region_start, layout.region_size))
    except Exception as exc:
        return _TlvReadResult("unreadable", None, backed_count, str(exc))
    if len(data) != layout.region_size:
        return _TlvReadResult(
            "unreadable",
            None,
            backed_count,
            f"read returned {len(data):#x}/{layout.region_size:#x} bytes",
        )

    try:
        block = parse_tlv_descriptor_block(data, base=layout.region_start)
    except ValueError as exc:
        return _TlvReadResult("malformed", None, backed_count, str(exc))

    if block.erased:
        status = "erased"
    elif block.issues:
        status = "malformed"
    elif block.crc_valid:
        status = "valid"
    else:
        status = "crc-mismatch"
    return _TlvReadResult(status, block, backed_count)


def _is_probable_code_pointer(addr: int) -> bool:
    if addr in (0x0000, 0xFFFF):
        return False
    if addr & 1:
        return False
    return (FLASH_START <= addr <= VECTOR_END) or (RAM_START <= addr <= RAM_END)


def _uint16_type():
    return Type.int(2, False)


def _uint8_type():
    return Type.int(1, False)


def _int16_type():
    return Type.int(2, True)


def _uint32_type():
    return Type.int(4, False)


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


def _looks_like_msp430_function_entry(data: bytes) -> bool:
    """Recognize conservative compiler function-entry shapes.

    Sparse firmware images often contain one function between long erased
    ranges.  Binary Ninja's recursive analysis has no edge with which to enter
    those islands, so a strong entry signature is useful.  Keep this narrow:
    an arbitrary MSP430 word decodes too easily to be a safe code/data test.
    """

    if len(data) < 2:
        return False
    word = _u16_from_le(data, 0)
    if _is_ext_word(word):
        if len(data) < 4:
            return False
        word = _u16_from_le(data, 2)

    # PUSH R4-R15 and PUSHM.A/PUSHM.W are the usual saved-register prologues.
    if (word & 0xFFF0) == 0x1200 and (word & 0xF) >= 4:
        return True
    if (word & 0xFF00) in (0x1400, 0x1500) and (word & 0xF) >= 4:
        return True

    # Frame setup without a saved register: SUB <constant>, SP or MOV SP, Rn.
    opcode = (word >> 12) & 0xF
    src_reg = (word >> 8) & 0xF
    src_mode = (word >> 4) & 0x3
    dst_reg = word & 0xF
    if opcode == 0x8 and dst_reg == 1 and (
        (src_reg == 0 and src_mode == 3) or src_reg in (2, 3)
    ):
        return True
    return (word & 0xFFF0) == 0x4100 and dst_reg >= 4


def _msp430x_decode_api():
    """Return local decode and control-flow helpers for either import style."""

    package = globals().get("__package__")
    module_names = []
    if package:
        module_names.append(f"{package}.msp430x_arch")
    module_names.append("msp430x_arch")
    for module_name in module_names:
        try:
            module = importlib.import_module(module_name)
            decoder = getattr(module, "decode", None)
            branch_edges = getattr(module, "decoded_branch_edges", None)
            if decoder is not None and branch_edges is not None:
                return decoder, branch_edges
        except ImportError:
            continue
    return None, None


_FORMAT_ARGUMENT_RE = re.compile(
    r"%(?!%)(?:\d+\$)?[-+ #0']*(?:\*|\d+)?"
    r"(?:\.(?:\*|\d+))?(?:hh|h|ll|l|j|z|t|L)?[diuoxXfFeEgGaAcspn]"
)
_MSP430_CALLEE_SAVED_REGS = frozenset(
    {"r4", "r5", "r6", "r7", "r8", "r9", "r10"}
)


def _has_format_argument(text: str) -> bool:
    """Recognize a printf-style conversion while treating ``%%`` as literal."""

    cursor = 0
    while cursor < len(text):
        percent = text.find("%", cursor)
        if percent < 0:
            return False
        if percent + 1 < len(text) and text[percent + 1] == "%":
            cursor = percent + 2
            continue
        if _FORMAT_ARGUMENT_RE.match(text, percent) is not None:
            return True
        cursor = percent + 1
    return False


def _read_backed_ascii_c_string(
    bv: BinaryView,
    addr: int,
    *,
    min_len: int = ASCII_STRING_MIN_LEN,
    max_len: int = STRING_CALL_MAX_BYTES,
) -> Optional[str]:
    """Read a bounded firmware string without accepting segment-fill bytes."""

    if addr < 0 or min_len <= 0 or max_len < min_len:
        return None
    try:
        data = bytes(bv.read(addr, max_len + 1))
    except Exception:
        return None
    terminator = data.find(b"\x00")
    if terminator < min_len or terminator > max_len:
        return None
    payload = data[:terminator]
    if not payload or not all(_is_printable_string_byte(byte) for byte in payload):
        return None
    if not any(
        (0x41 <= byte <= 0x5A) or (0x61 <= byte <= 0x7A)
        for byte in payload
    ):
        return None
    if not all(
        _is_file_backed_byte(bv, byte_addr)
        for byte_addr in range(addr, addr + terminator + 1)
    ):
        return None
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError:
        return None


def _direct_msp430_call_target(bv: BinaryView, addr: int, decoder) -> Optional[int]:
    """Return a directly encoded CALL/CALLA destination at ``addr``."""

    try:
        data = bytes(bv.read(addr, 8))
        ins = decoder(data, addr)
    except Exception:
        return None
    src = getattr(ins, "src", None)
    if (
        ins is None
        or getattr(ins, "fmt", None) != "single"
        or getattr(ins, "mnemonic", None) not in ("call", "calla")
        or getattr(src, "kind", None) != "imm"
    ):
        return None
    return int(getattr(src, "value", 0)) & 0xFFFFF


def _function_at_call_target(bv: BinaryView, caller, addr: int):
    """Resolve a call target on the caller's platform when duplicate functions exist."""

    platform = getattr(caller, "platform", None)
    getter = getattr(bv, "get_function_at", None)
    if getter is not None and platform is not None:
        try:
            func = getter(addr, platform)
            if func is not None:
                return func
        except Exception:
            pass

    candidates_getter = getattr(bv, "get_functions_at", None)
    if candidates_getter is not None:
        try:
            candidates = list(candidates_getter(addr))
        except Exception:
            candidates = []
        caller_arch = str(getattr(caller, "arch", ""))
        for func in candidates:
            if str(getattr(func, "platform", "")) == str(platform):
                return func
        for func in candidates:
            if str(getattr(func, "arch", "")) == caller_arch:
                return func
        if len(candidates) == 1:
            return candidates[0]
    return None


def _register_parameter_names(func) -> set[str]:
    """Return native registers already represented by a function prototype."""

    arch = getattr(func, "arch", None)
    if arch is None:
        return set()
    names = set()
    try:
        variables = getattr(func, "parameter_vars", ())
        variables = getattr(variables, "vars", variables)
        for variable in variables:
            if getattr(variable, "source_type", None) != VariableSourceType.RegisterVariableSourceType:
                continue
            names.add(str(arch.get_reg_name(variable.storage)))
    except Exception:
        return set()
    return names


def _preservable_auto_parameters(func) -> Optional[tuple]:
    """Keep only the narrow auto-prototype shape that causes lost string inputs.

    Binary Ninja can infer PUSH/POP preservation of R4-R10 as formal inputs for
    this 20-bit architecture.  We retain those uncertain inputs rather than
    deleting them, but refuse to rewrite a prototype containing stack,
    implicit, caller-saved, or otherwise meaningful parameters.
    """

    if bool(getattr(func, "has_user_type", False)):
        return None
    try:
        parameters = tuple(func.type.parameters)
        arch = func.arch
    except Exception:
        return None
    if not parameters:
        return None
    for parameter in parameters:
        location = getattr(parameter, "location", None)
        if (
            location is None
            or getattr(location, "source_type", None)
            != VariableSourceType.RegisterVariableSourceType
        ):
            return None
        try:
            register_name = str(arch.get_reg_name(location.storage))
        except Exception:
            return None
        if register_name not in _MSP430_CALLEE_SAVED_REGS:
            return None
    return parameters


def _set_auto_call_type_adjustment(caller, addr: int, adjusted_type) -> None:
    """Apply an automatic, call-site-local type without creating a user type."""

    setter = getattr(caller, "set_auto_call_type_adjustment", None)
    if setter is not None:
        try:
            setter(addr, adjusted_type, arch=caller.arch)
        except TypeError:
            setter(addr, adjusted_type)
        return

    setter = getattr(_bn_core, "BNSetAutoCallTypeAdjustment", None)
    if setter is None:
        raise RuntimeError("Binary Ninja has no automatic call type adjustment API")
    immutable_type = adjusted_type.immutable_copy()
    type_confidence = _bn_core.BNTypeWithConfidence()
    type_confidence.type = immutable_type.handle
    type_confidence.confidence = immutable_type.confidence
    setter(caller.handle, caller.arch.handle, addr, type_confidence)


def _mark_incremental_function_updates(functions: Iterable) -> None:
    """Invalidate only affected callers without forcing full user reanalysis."""

    for caller in functions:
        marker = getattr(caller, "mark_updates_required", None)
        if marker is None:
            continue
        try:
            marker(FunctionUpdateType.IncrementalAutoFunctionUpdate)
        except Exception:
            pass


def _recover_direct_string_call_parameters(bv: BinaryView, verbose: bool = False) -> int:
    """Restore proven R12 strings with automatic call-site type adjustments.

    This runs only after function analysis.  It requires a direct CALL/CALLA,
    a constant R12 value at that call, a fully file-backed printable C string,
    and an untyped target whose inferred inputs consist exclusively of MSP430
    callee-saved registers.  Existing call adjustments, user types,
    zero-argument functions, and more specific prototypes are never replaced.
    Keeping the adjustment on the proven call site prevents Binary Ninja's
    interprocedural inference from repeatedly replacing a callee-wide auto type.
    """

    decoder, _branch_edges = _msp430x_decode_api()
    if decoder is None:
        return 0

    candidates = {}
    for caller in list(getattr(bv, "functions", [])):
        if str(getattr(caller, "arch", "")) != "msp430x":
            continue
        try:
            call_sites = list(caller.call_sites)
        except Exception:
            continue
        for call_site in call_sites:
            call_addr = getattr(call_site, "address", None)
            if call_addr is None:
                continue
            target_addr = _direct_msp430_call_target(bv, call_addr, decoder)
            if target_addr is None:
                continue
            try:
                r12_value = caller.get_reg_value_at(call_addr, "r12", caller.arch)
            except Exception:
                continue
            if getattr(r12_value, "type", None) not in (
                RegisterValueType.ConstantValue,
                RegisterValueType.ConstantPointerValue,
            ):
                continue
            string_addr = int(getattr(r12_value, "value", 0)) & 0xFFFFF
            text = _read_backed_ascii_c_string(bv, string_addr)
            if text is None:
                continue
            callee = _function_at_call_target(bv, caller, target_addr)
            if callee is None or str(getattr(callee, "arch", "")) != "msp430x":
                continue
            key = (
                str(getattr(caller, "platform", "")),
                int(getattr(caller, "start", 0)),
                int(call_addr),
            )
            candidates.setdefault(
                key,
                {
                    "caller": caller,
                    "callee": callee,
                    "call_addr": int(call_addr),
                    "format": _has_format_argument(text),
                },
            )

    recovered = 0
    affected_callers = {}
    for candidate in candidates.values():
        caller = candidate["caller"]
        callee = candidate["callee"]
        call_addr = candidate["call_addr"]
        if "r12" in _register_parameter_names(callee):
            continue
        existing_parameters = _preservable_auto_parameters(callee)
        if existing_parameters is None:
            continue

        getter = getattr(caller, "get_call_type_adjustment", None)
        if getter is None:
            continue
        try:
            existing_adjustment = getter(call_addr, caller.arch)
        except TypeError:
            try:
                existing_adjustment = getter(call_addr)
            except Exception:
                continue
        except Exception:
            continue
        if existing_adjustment is not None:
            continue

        calling_convention = getattr(callee, "calling_convention", None)
        if calling_convention is None:
            calling_convention = getattr(
                getattr(callee, "platform", None),
                "default_calling_convention",
                None,
            )
        try:
            argument_registers = tuple(calling_convention.int_arg_regs)
        except Exception:
            argument_registers = ()
        if not argument_registers or str(argument_registers[0]) != "r12":
            continue

        is_format = bool(candidate["format"])
        try:
            current_type = callee.type
            pointer_type = Type.pointer(callee.arch, Type.char())
            adjusted_type = Type.function(
                callee.return_type,
                [
                    FunctionParameter(pointer_type, "format" if is_format else "text"),
                    *existing_parameters,
                ],
                calling_convention=calling_convention,
                variable_arguments=(
                    is_format
                    or bool(getattr(current_type.has_variable_arguments, "value", False))
                ),
                stack_adjust=getattr(current_type, "stack_adjustment", None),
            ).mutable_copy()
            adjusted_type.can_return = current_type.can_return
            adjusted_type.pure = current_type.pure
            _set_auto_call_type_adjustment(caller, call_addr, adjusted_type)
        except Exception as exc:
            if verbose:
                print(
                    f"Could not recover R12 string parameter at call "
                    f"{call_addr:#x}: {exc}"
                )
            log_warn(
                f"Could not recover R12 string parameter at call "
                f"{call_addr:#x}: {exc}"
            )
            continue

        caller_key = (
            str(getattr(caller, "platform", "")),
            int(getattr(caller, "start", 0)),
        )
        affected_callers[caller_key] = caller
        recovered += 1

    _mark_incremental_function_updates(affected_callers.values())
    if verbose and recovered:
        print(
            f"Recovered R12 string parameter(s) at {recovered} direct call site(s)."
        )
    return recovered


def _decoded_return_kind(ins) -> Optional[str]:
    """Return the architectural return kind for a decoded instruction."""

    if (
        getattr(ins, "fmt", None) == "single"
        and getattr(ins, "mnemonic", None) in ("ret", "reta", "reti")
    ):
        return ins.mnemonic
    if (
        getattr(ins, "fmt", None) != "double"
        or getattr(ins, "mnemonic", None) not in ("mov", "mova")
    ):
        return None
    src = getattr(ins, "src", None)
    dst = getattr(ins, "dst", None)
    if (
        getattr(src, "kind", None) == "indirect"
        and getattr(src, "reg", None) == 1
        and getattr(src, "autoinc", False)
        and getattr(dst, "kind", None) == "reg"
        and getattr(dst, "reg", None) == 0
    ):
        return "reta" if getattr(ins, "size", 2) == 4 else "ret"
    return None


def _looks_like_msp430_reti_leaf_entry(
    data: bytes,
    addr: int,
    *,
    decoder,
    branch_edges,
) -> bool:
    """Reject padding and control transfers as unevidenced leaf-ISR entries."""

    if len(data) < 4 or _u16_from_le(data, 0) in (0x0000, 0x4303, 0xFFFF):
        return False
    try:
        ins = decoder(data, addr)
        flow = tuple(branch_edges(ins, addr)) if ins is not None else ()
    except Exception:
        return False
    return (
        ins is not None
        and getattr(ins, "fmt", None) not in ("bad", "cpux")
        and getattr(ins, "mnemonic", None) not in (None, "???", "cpux")
        and not flow
    )


def _decode_msp430_routine(
    data: bytes,
    addr: int,
    *,
    decoder=None,
    branch_edges=None,
) -> Optional[_RoutineShape]:
    """Recover a dense, terminal-bounded routine with a small CFG walk.

    This intentionally rejects indirect exits, ambiguous instruction overlap,
    and code that cannot reach a return or direct tail exit. It is a validation
    helper for sparse discovery, not a replacement for Binary Ninja's full
    function analysis.
    """

    if decoder is None or branch_edges is None:
        default_decoder, default_branch_edges = _msp430x_decode_api()
        decoder = decoder or default_decoder
        branch_edges = branch_edges or default_branch_edges
    if decoder is None or branch_edges is None:
        return None

    scan = data[:SPARSE_CODE_ISLAND_RETURN_SCAN_BYTES]
    window_end = addr + len(scan)
    pending = [addr]
    decoded = {}
    occupied_words = set()
    successors = {}
    predecessors = {}
    return_nodes = set()
    tail_exit_nodes = set()
    return_kinds = set()

    while pending:
        instruction_addr = pending.pop()
        if instruction_addr in decoded:
            continue
        if (
            instruction_addr & 1
            or instruction_addr < addr
            or instruction_addr + 2 > window_end
        ):
            return None

        offset = instruction_addr - addr
        try:
            ins = decoder(scan[offset:], instruction_addr)
        except Exception:
            return None
        if ins is None or getattr(ins, "fmt", None) in ("bad", "cpux"):
            return None
        if getattr(ins, "mnemonic", None) in (None, "???", "cpux"):
            return None
        if any(
            operand is not None and getattr(operand, "kind", None) == "bad"
            for operand in (getattr(ins, "src", None), getattr(ins, "dst", None))
        ):
            return None

        length = getattr(ins, "length", 0)
        instruction_end = (
            instruction_addr + length if isinstance(length, int) else instruction_addr
        )
        if (
            not isinstance(length, int)
            or length < 2
            or length & 1
            or instruction_end > window_end
        ):
            return None

        instruction_words = range(instruction_addr, instruction_end, 2)
        if any(word_addr in occupied_words for word_addr in instruction_words):
            return None
        occupied_words.update(instruction_words)
        decoded[instruction_addr] = (instruction_end, ins)

        return_kind = _decoded_return_kind(ins)
        try:
            flow = tuple(branch_edges(ins, instruction_addr))
        except Exception:
            return None

        if return_kind is not None:
            if flow != (("return", None),):
                return None
            next_addresses = ()
            return_nodes.add(instruction_addr)
            return_kinds.add(return_kind)
        elif not flow:
            next_addresses = (instruction_end,)
        elif len(flow) == 1 and flow[0][0] == "call":
            next_addresses = (instruction_end,)
        elif len(flow) == 1 and flow[0][0] == "unconditional":
            next_addresses = (flow[0][1],)
        elif len(flow) == 1 and flow[0][0] == "unconditional_pc":
            target = flow[0][1]
            if (
                not isinstance(target, int)
                or target & 1
                or target < addr
                or target >= window_end
            ):
                return None
            next_addresses = ()
            tail_exit_nodes.add(instruction_addr)
        elif (
            len(flow) == 2
            and {kind for kind, _target in flow} == {"true", "false"}
        ):
            next_addresses = tuple(target for _kind, target in flow)
        else:
            return None

        if any(
            not isinstance(target, int)
            or target & 1
            or target < addr
            or target >= window_end
            for target in next_addresses
        ):
            return None
        successors[instruction_addr] = next_addresses
        for target in next_addresses:
            predecessors.setdefault(target, set()).add(instruction_addr)
        pending.extend(target for target in next_addresses if target not in decoded)

    terminal_nodes = return_nodes | tail_exit_nodes
    if len(decoded) < 2 or not terminal_nodes or len(return_kinds) > 1:
        return None

    can_reach_terminal = set(terminal_nodes)
    reachable_pending = list(terminal_nodes)
    while reachable_pending:
        instruction_addr = reachable_pending.pop()
        for predecessor in predecessors.get(instruction_addr, ()):
            if predecessor in can_reach_terminal:
                continue
            can_reach_terminal.add(predecessor)
            reachable_pending.append(predecessor)
    if len(can_reach_terminal) != len(decoded):
        return None

    cursor = addr
    for instruction_addr, (instruction_end, _ins) in sorted(decoded.items()):
        if instruction_addr != cursor:
            return None
        cursor = instruction_end
    if not any(decoded[node][0] == cursor for node in terminal_nodes):
        return None

    if tail_exit_nodes:
        termination_kind = "mixed" if return_nodes else "tail"
    else:
        termination_kind = next(iter(return_kinds))

    return _RoutineShape(
        length=cursor - addr,
        termination_kind=termination_kind,
        instruction_count=len(decoded),
    )


def _code_window_end(addr: int, island_end: int, data_spans: Sequence[AddressSpan]) -> int:
    """Bound code validation at the next known data range."""

    end = island_end
    for data_start, data_end in data_spans:
        if data_start <= addr < data_end:
            return addr
        if addr < data_start:
            return min(end, data_start)
    return end


def _data_variable_spans(bv: BinaryView) -> tuple[AddressSpan, ...]:
    """Return defensively sized spans for data variables already in the view."""

    try:
        items = tuple(getattr(bv, "data_vars", {}).items())
    except Exception:
        return ()

    spans = []
    for start, data_var in items:
        try:
            start = int(start)
        except (TypeError, ValueError):
            continue
        data_type = getattr(data_var, "type", None)
        width = getattr(data_type, "width", getattr(data_var, "width", 1))
        try:
            width = max(1, int(width))
        except (TypeError, ValueError):
            width = 1
        spans.append((start, start + width))
    return _merge_spans(spans)


def _executable_backed_islands(bv: BinaryView) -> tuple[AddressSpan, ...]:
    """Find backed islands in every executable segment, including ELF ranges."""

    islands = []
    seen = set()
    for segment in getattr(bv, "segments", ()):
        if not getattr(segment, "executable", False):
            continue
        start = getattr(segment, "start", None)
        end = getattr(segment, "end", None)
        if start is None or end is None or end <= start:
            continue
        backed_length = getattr(segment, "data_length", end - start)
        try:
            backed_length = int(backed_length)
        except (TypeError, ValueError):
            backed_length = end - start
        length = min(end - start, max(0, backed_length), EXECUTABLE_SEGMENT_SCAN_MAX_BYTES)
        if length <= 0:
            continue
        key = (start, length)
        if key in seen:
            continue
        seen.add(key)
        try:
            data = bytes(bv.read(start, length))
        except Exception:
            continue
        islands.extend(_backed_island_spans(data, start))
    return tuple(_merge_spans(islands))


def _seed_sparse_code_island_functions(bv: BinaryView, verbose: bool = False) -> int:
    """Seed conservative function chains inside backed executable islands.

    Besides an island's prologue-shaped first routine, compiler output may pack
    several small functions together without erased padding. A decoded return
    or direct tail exit is a reliable boundary for another prologue-shaped
    routine. RETI-to-RETI chains also admit leaf handlers without a
    saved-register prologue, matching the compact interrupt-handler layout used
    by TI toolchains.
    """

    add_function = getattr(bv, "add_function", None)
    if add_function is None or getattr(bv, "platform", None) is None:
        return 0

    decoder, branch_edges = _msp430x_decode_api()
    if decoder is None or branch_edges is None:
        return 0

    known_data_spans = _merge_spans((
        *_flash_ascii_string_cluster_spans(bv),
        *_flash_numeric_lookup_table_spans(bv),
        *_flash_address_jump_table_spans(bv),
        *_flash_cinit_table_spans(bv),
        *_data_variable_spans(bv),
    ))
    created = 0
    for island_start, island_end in _executable_backed_islands(bv):
        length = island_end - island_start
        if island_start & 1 or length < 4:
            continue
        try:
            data = bytes(bv.read(island_start, length))
        except Exception:
            continue

        def candidate_is_blocked(addr: int) -> bool:
            return (
                addr & 1
                or addr < island_start
                or addr + 4 > island_end
                or _has_data_var_at(bv, addr)
                or _addr_in_spans(addr, known_data_spans)
            )

        function_starts = set()
        for func in getattr(bv, "functions", ()):
            function_start = getattr(func, "start", None)
            if isinstance(function_start, int) and island_start <= function_start < island_end:
                function_starts.add(function_start)
        sorted_function_starts = sorted(function_starts)

        def remember_function_start(addr: int) -> None:
            if addr in function_starts:
                return
            function_starts.add(addr)
            bisect.insort(sorted_function_starts, addr)

        def ensure_function(addr: int, description: str) -> bool:
            nonlocal created
            if _has_function_at(bv, addr):
                remember_function_start(addr)
                return True
            try:
                added = add_function(addr)
            except Exception as exc:
                log_warn(f"Could not add {description} function at {addr:#x}: {exc}")
                return False
            if added is None and not _has_function_at(bv, addr):
                log_warn(f"Binary Ninja rejected {description} function at {addr:#x}.")
                return False
            created += 1
            remember_function_start(addr)
            return True

        def decode_at(addr: int) -> Optional[_RoutineShape]:
            if candidate_is_blocked(addr):
                return None
            window_end = _code_window_end(addr, island_end, known_data_spans)
            next_function_index = bisect.bisect_right(sorted_function_starts, addr)
            if next_function_index < len(sorted_function_starts):
                window_end = min(window_end, sorted_function_starts[next_function_index])
            if window_end - addr < 4:
                return None
            offset = addr - island_start
            return _decode_msp430_routine(
                data[offset:offset + (window_end - addr)],
                addr,
                decoder=decoder,
                branch_edges=branch_edges,
            )

        anchors = set(function_starts)
        partition_starts = {island_start}
        partition_starts.update(
            data_end
            for data_start, data_end in known_data_spans
            if data_start < island_end and island_start < data_end < island_end
        )
        for partition_start in sorted(partition_starts):
            offset = partition_start - island_start
            routine = decode_at(partition_start)
            if routine is None or not _looks_like_msp430_function_entry(data[offset:]):
                continue
            if not ensure_function(partition_start, "sparse code-island"):
                continue
            anchors.add(partition_start)

        pending = list(anchors)
        processed = set()
        while pending:
            function_start = pending.pop()
            if function_start in processed or candidate_is_blocked(function_start):
                continue
            processed.add(function_start)
            routine = decode_at(function_start)
            if routine is None:
                continue

            next_start = function_start + routine.length
            next_routine = decode_at(next_start)
            if next_routine is None:
                continue
            next_offset = next_start - island_start
            has_strong_entry = _looks_like_msp430_function_entry(data[next_offset:])
            is_packed_isr = (
                routine.termination_kind == "reti"
                and next_routine.termination_kind == "reti"
                and _looks_like_msp430_reti_leaf_entry(
                    data[next_offset:],
                    next_start,
                    decoder=decoder,
                    branch_edges=branch_edges,
                )
            )
            if not has_strong_entry and not is_packed_isr:
                continue

            if not ensure_function(next_start, "packed code-island"):
                continue
            if next_start not in processed:
                pending.append(next_start)

    if verbose and created:
        print(f"Seeded {created} unreferenced MSP430X sparse code-island function(s).")
    return created


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


_TLV_AUTO_TYPE_SOURCE = "msp430x-lens.tlv"


def _tlv_structure_definitions():
    u8 = _uint8_type()
    u16 = _uint16_type()
    i16 = _int16_type()
    u32 = _uint32_type()
    return {
        "msp430_tlv_info_block": (
            8,
            (
                (u8, "info_length", 0),
                (u8, "crc_length", 1),
                (u16, "crc16", 2),
                (u16, "device_id", 4),
                (u8, "hardware_revision", 6),
                (u8, "firmware_revision", 7),
            ),
        ),
        "msp430_tlv_die_record": (
            12,
            (
                (u8, "tag", 0),
                (u8, "length", 1),
                (u32, "lot_wafer_id", 2),
                (u16, "die_x", 6),
                (u16, "die_y", 8),
                (u16, "test_results", 10),
            ),
        ),
        "msp430_tlv_adc12_calibration_f5438": (
            18,
            (
                (u8, "tag", 0),
                (u8, "length", 1),
                (u16, "gain_factor", 2),
                (i16, "offset", 4),
                (u16, "ref15_factor", 6),
                (u16, "ref15_30c", 8),
                (u16, "ref15_85c", 10),
                (u16, "ref25_factor", 12),
                (u16, "ref25_30c", 14),
                (u16, "ref25_85c", 16),
            ),
        ),
        "msp430_tlv_adc12_calibration_f5438a": (
            18,
            (
                (u8, "tag", 0),
                (u8, "length", 1),
                (u16, "gain_factor", 2),
                (i16, "offset", 4),
                (u16, "ref15_30c", 6),
                (u16, "ref15_85c", 8),
                (u16, "ref20_30c", 10),
                (u16, "ref20_85c", 12),
                (u16, "ref25_30c", 14),
                (u16, "ref25_85c", 16),
            ),
        ),
        "msp430_tlv_ref_calibration": (
            8,
            (
                (u8, "tag", 0),
                (u8, "length", 1),
                (u16, "ref15", 2),
                (u16, "ref20", 4),
                (u16, "ref25", 6),
            ),
        ),
    }


def _register_tlv_types(bv: BinaryView) -> dict[str, object]:
    """Register stable packed TLV record types and return named references."""

    result = {}
    for name, (width, members) in _tlv_structure_definitions().items():
        type_id = Type.generate_auto_type_id(_TLV_AUTO_TYPE_SOURCE, name)
        try:
            registered_name = bv.get_type_name_by_id(type_id)
        except Exception:
            registered_name = None
        try:
            structure = StructureBuilder.create(
                members=[
                    StructureMember(member_type, member_name, offset)
                    for member_type, member_name, offset in members
                ],
                packed=True,
                width=width,
            )
            registered_name = bv.define_type(type_id, name, structure)
        except Exception as exc:
            if registered_name is None:
                log_warn(f"Could not register TLV type {name}: {exc}")
                continue
        try:
            result[name] = Type.named_type_from_registered_type(bv, registered_name)
        except Exception as exc:
            log_warn(f"Could not reference TLV type {registered_name}: {exc}")
    return result


def _data_var_overlaps(bv: BinaryView, start: int, width: int) -> bool:
    if width <= 0:
        return True
    try:
        if bv.get_data_var_at(start) is not None:
            return True
    except Exception:
        pass
    try:
        following = bv.get_next_data_var_after(start)
        if following is not None and following.address < start + width:
            return True
    except Exception:
        try:
            for addr, variable in getattr(bv, "data_vars", {}).items():
                variable_width = int(getattr(getattr(variable, "type", None), "width", 1))
                if start < addr + max(1, variable_width) and addr < start + width:
                    return True
        except Exception:
            pass
    return False


def _define_tlv_data_var(
    bv: BinaryView,
    addr: int,
    var_type,
    name: str,
    *,
    auto_defined: bool,
) -> bool:
    width = int(getattr(var_type, "width", 0))
    if _data_var_overlaps(bv, addr, width):
        return False
    try:
        if auto_defined and hasattr(bv, "define_data_var"):
            bv.define_data_var(addr, var_type, name)
        elif hasattr(bv, "define_user_data_var"):
            bv.define_user_data_var(addr, var_type, name)
        else:
            _define_symbol(
                bv,
                Symbol(SymbolType.DataSymbol, addr, name),
                auto_defined=auto_defined,
            )
        return True
    except Exception as exc:
        log_warn(f"Could not define TLV data {name} at {addr:#06x}: {exc}")
        return False


def _tlv_device_name(device_id: bytes) -> str:
    names = {
        b"\x54\x38": "MSP430F5438",
        b"\x05\x80": "MSP430F5438A",
    }
    return names.get(bytes(device_id), "unknown device")


def _tlv_record_comment(record: TlvRecord) -> str:
    prefix = f"TLV {record.name}: payload length={record.length:#x}"
    value = record.value
    if record.tag == TLV_TAG_DIE_RECORD and record.length == 0x0A:
        wafer_id = int.from_bytes(value[0:4], "little")
        die_x = int.from_bytes(value[4:6], "little")
        die_y = int.from_bytes(value[6:8], "little")
        test_results = int.from_bytes(value[8:10], "little")
        return (
            f"{prefix}; wafer/lot={wafer_id:#010x}, die=({die_x}, {die_y}), "
            f"test_results={test_results:#06x}"
        )
    if record.tag == TLV_TAG_ADC12_CAL_F5438 and record.length == 0x10:
        values = tuple(int.from_bytes(value[i:i + 2], "little") for i in range(0, 16, 2))
        offset = int.from_bytes(value[2:4], "little", signed=True)
        return (
            f"{prefix}; gain={values[0]:#06x}, offset={offset}, "
            f"ref1.5_factor={values[2]:#06x}, ref1.5_temp={[hex(item) for item in values[3:5]]}, "
            f"ref2.5_factor={values[5]:#06x}, ref2.5_temp={[hex(item) for item in values[6:8]]}"
        )
    if record.tag == TLV_TAG_ADC12_CAL and record.length == 0x10:
        values = tuple(int.from_bytes(value[i:i + 2], "little") for i in range(0, 16, 2))
        offset = int.from_bytes(value[2:4], "little", signed=True)
        return (
            f"{prefix}; gain={values[0]:#06x}, offset={offset}, "
            f"temperature_cal={[hex(item) for item in values[2:]]}"
        )
    if record.tag == TLV_TAG_REF_CAL and record.length == 0x06:
        refs = tuple(int.from_bytes(value[i:i + 2], "little") for i in range(0, 6, 2))
        return f"{prefix}; ref1.5={refs[0]:#06x}, ref2.0={refs[1]:#06x}, ref2.5={refs[2]:#06x}"
    if record.tag == TLV_TAG_PERIPHERAL:
        descriptor = decode_peripheral_descriptor(record)
        if descriptor is None:
            return f"{prefix}; peripheral payload is malformed"
        crc_modules = [
            f"{entry.name}@{entry.address:#05x}"
            for entry in descriptor.entries
            if entry.peripheral_id in (0x3C, 0x3D)
        ]
        crc_text = ", ".join(crc_modules) if crc_modules else "no CRC16 entry"
        return f"{prefix}; peripherals={len(descriptor.entries)}, {crc_text}"
    return prefix


def _tlv_record_type_and_name(record: TlvRecord, tlv_types: dict[str, object]):
    raw_type = _uint8_array_type(record.end - record.address)
    if record.tag == TLV_TAG_DIE_RECORD and record.length == 0x0A:
        return tlv_types.get("msp430_tlv_die_record", raw_type), "tlv_die_record"
    if record.tag == TLV_TAG_ADC12_CAL_F5438 and record.length == 0x10:
        return (
            tlv_types.get("msp430_tlv_adc12_calibration_f5438", raw_type),
            "tlv_adc12_calibration",
        )
    if record.tag == TLV_TAG_ADC12_CAL and record.length == 0x10:
        return (
            tlv_types.get("msp430_tlv_adc12_calibration_f5438a", raw_type),
            "tlv_adc12_calibration",
        )
    if record.tag == TLV_TAG_REF_CAL and record.length == 0x06:
        return tlv_types.get("msp430_tlv_ref_calibration", raw_type), "tlv_ref_calibration"
    if record.tag == TLV_TAG_PERIPHERAL:
        name = "tlv_peripheral_descriptor"
    else:
        name = f"tlv_record_{record.address:05x}"
    return raw_type, name


def _annotate_tlv_descriptor(
    bv: BinaryView,
    descriptor: Optional[object] = None,
    *,
    spec: Optional[DeviceSpec] = None,
    auto_defined: bool = False,
    verbose: bool = False,
) -> int:
    """Apply bounded, idempotent types/comments for a backed TLV block."""

    if spec is None:
        spec = _device_spec_for_view(bv)
    if isinstance(descriptor, TlvDescriptorBlock):
        if descriptor.erased:
            status = "erased"
        elif descriptor.issues:
            status = "malformed"
        elif descriptor.crc_valid:
            status = "valid"
        else:
            status = "crc-mismatch"
        result = _TlvReadResult(status, descriptor, TLV_REGION_SIZE)
    elif isinstance(descriptor, _TlvReadResult):
        result = descriptor
    else:
        result = _read_tlv_descriptor(bv, spec)
    block = result.block
    if block is None or block.erased or block.issues:
        if verbose and result.status not in ("absent", "erased"):
            print(f"TLV descriptors: {result.status} ({result.detail})")
            if block is not None:
                for issue in block.issues:
                    print(f"  issue: {issue}")
        return 0

    changed = 0
    tlv_types = _register_tlv_types(bv)
    info_type = tlv_types.get("msp430_tlv_info_block", _uint8_array_type(8))
    if _define_tlv_data_var(
        bv,
        block.base,
        info_type,
        "tlv_info_block",
        auto_defined=auto_defined,
    ):
        changed += 1

    device_name = _tlv_device_name(block.device_id)
    expected = spec.tlv.expected_device_id if spec.tlv is not None else None
    profile_note = ""
    if expected is not None and block.device_id != expected:
        profile_note = f"; selected profile expects device ID {expected.hex(' ')}"
    info_comment = (
        f"MSP430 device descriptors: {device_name}, device_id={block.device_id.hex(' ')}, "
        f"hardware_revision={block.hardware_revision:#04x}, "
        f"firmware_revision={block.firmware_revision:#04x}{profile_note}"
    )
    if _set_comment_if_empty(bv, block.base, info_comment, auto_defined=auto_defined):
        changed += 1

    crc_state = "valid" if block.crc_valid else "MISMATCH"
    crc_comment = (
        f"TLV CRC16/CCITT-FALSE {crc_state}: stored={block.stored_crc:#06x}, "
        f"computed={block.computed_crc:#06x} over "
        f"[{block.base + 4:#06x}, {block.end:#06x})"
    )
    if _set_comment_if_empty(bv, block.base + 2, crc_comment, auto_defined=auto_defined):
        changed += 1
    for name, addr in (
        ("tlv_crc16", block.base + 2),
        ("tlv_device_id", block.base + 4),
    ):
        if _symbol_exists(bv, name, addr):
            continue
        try:
            _define_symbol(
                bv,
                Symbol(SymbolType.DataSymbol, addr, name),
                auto_defined=auto_defined,
            )
            changed += 1
        except Exception as exc:
            log_warn(f"Could not define TLV symbol {name} at {addr:#06x}: {exc}")

    for record in block.records:
        record_type, name = _tlv_record_type_and_name(record, tlv_types)
        if record_type is not None and _define_tlv_data_var(
            bv,
            record.address,
            record_type,
            name,
            auto_defined=auto_defined,
        ):
            changed += 1
        if _set_comment_if_empty(
            bv,
            record.address,
            _tlv_record_comment(record),
            auto_defined=auto_defined,
        ):
            changed += 1

    if block.terminator_address is not None:
        if _define_tlv_data_var(
            bv,
            block.terminator_address,
            _uint8_type(),
            "tlv_tag_end",
            auto_defined=auto_defined,
        ):
            changed += 1
        if _set_comment_if_empty(
            bv,
            block.terminator_address,
            "TLV end tag",
            auto_defined=auto_defined,
        ):
            changed += 1

    if verbose:
        print(
            f"TLV descriptors: {result.status}, device={device_name}, "
            f"records={len(block.records)}, crc16={crc_state.lower()}"
        )
        for issue in block.issues:
            print(f"  issue: {issue}")
    return changed


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


def report_msp430_tlv(bv: BinaryView) -> None:
    """Print backed factory descriptors and their stored CRC16 status."""

    spec = _device_spec_for_view(bv)
    result = _read_tlv_descriptor(bv, spec)
    if result.block is None:
        suffix = f": {result.detail}" if result.detail else ""
        print(f"TLV device descriptors: {result.status}{suffix}")
        return

    block = result.block
    device_name = _tlv_device_name(block.device_id)
    crc_state = "valid" if block.crc_valid else "MISMATCH"
    print(
        f"TLV device descriptors: {result.status}; device={device_name}; "
        f"device_id={block.device_id.hex(' ')}; hw_rev={block.hardware_revision:#04x}; "
        f"fw_rev={block.firmware_revision:#04x}"
    )
    print(
        f"CRC16/CCITT-FALSE: {crc_state}; stored={block.stored_crc:#06x}; "
        f"computed={block.computed_crc:#06x}; range=[{block.base + 4:#06x}, {block.end:#06x})"
    )
    for record in block.records:
        print(f"  {record.address:#06x}: {_tlv_record_comment(record)}")
        peripheral = decode_peripheral_descriptor(record)
        if peripheral is None:
            continue
        memory = ", ".join(f"{word:#06x}" for word in peripheral.memory_words)
        print(f"    memory descriptors: {memory}")
        for entry in peripheral.entries:
            print(
                f"    {entry.address:#06x}: {entry.name} "
                f"(peripheral ID {entry.peripheral_id:#04x})"
            )
    if block.terminator_address is not None:
        print(f"  {block.terminator_address:#06x}: TLV end tag")
    for issue in block.issues:
        print(f"  issue: {issue}")


def diagnose_msp430f5438_view(bv: BinaryView) -> None:
    """Print concise mapping and decoder diagnostics for the active view."""

    spec = _device_spec_for_view(bv)
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
    tlv_result = _read_tlv_descriptor(bv, spec)
    if tlv_result.block is None:
        print(f"tlv={tlv_result.status}")
    else:
        tlv_block = tlv_result.block
        crc_state = "valid" if tlv_block.crc_valid else "mismatch"
        print(
            f"tlv={tlv_result.status} device={_tlv_device_name(tlv_block.device_id)} "
            f"records={len(tlv_block.records)} crc16={crc_state}"
        )
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
    variant: Optional[str] = None,
    arch_name: Optional[str] = "msp430x",
    add_reset_entry: bool = True,
    enable_linear_sweep: bool = False,
    cleanup_peripheral_functions: bool = True,
    verbose: bool = True,
) -> int:
    """Reapply analysis annotations without rebuilding the memory segments."""

    spec = _device_spec_for_view(bv) if variant is None else _spec_for_variant(variant)
    _set_view_device_spec(bv, spec)
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
    _annotate_tlv_descriptor(bv, spec=spec, verbose=verbose)
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
    _seed_sparse_code_island_functions(bv, verbose=verbose)
    _seed_address_jump_table_target_functions(bv, verbose=verbose)
    _seed_address_jump_table_indirect_branches(bv, verbose=verbose)

    _update_analysis(bv)
    recovered_string_calls = _recover_direct_string_call_parameters(bv, verbose=verbose)
    if recovered_string_calls:
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
        f"variant={spec.name}, vector_functions={vector_functions}, "
        f"string_call_targets={recovered_string_calls}"
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
    _set_view_device_spec(bv, spec)
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
    _annotate_tlv_descriptor(bv, spec=spec, verbose=verbose)
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
    _seed_sparse_code_island_functions(bv, verbose=verbose)
    _seed_address_jump_table_target_functions(bv, verbose=verbose)
    _seed_address_jump_table_indirect_branches(bv, verbose=verbose)

    _update_analysis(bv)
    recovered_string_calls = _recover_direct_string_call_parameters(bv, verbose=verbose)
    if recovered_string_calls:
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
        f"vector_functions={vector_functions}, string_call_targets={recovered_string_calls}"
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

        raw_len = _raw_length(self.raw)
        image_base = _detect_image_base(self.raw, raw_len)
        detected_spec = _detect_device_spec_from_tlv(self.raw, image_base)
        if detected_spec is not None:
            self.spec = detected_spec
        spec = self.spec
        _set_view_device_spec(self, spec)
        regions = spec.regions
        if getattr(self, "parse_only", False):
            reset = _read_raw_u16(self.raw, spec.reset_vector - image_base)
            if reset is not None and _is_probable_code_pointer(reset):
                self._entry_point = reset
            return True

        _configure_auto_string_minimum(self)

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
        _annotate_tlv_descriptor(
            self,
            spec=spec,
            auto_defined=True,
            verbose=False,
        )
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
        _seed_sparse_code_island_functions(self, verbose=False)
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
        "MSP430F5438\\Report TLV device descriptors and CRC16",
        "Print factory device descriptors, calibration records, peripheral IDs, and stored TLV CRC16 validity.",
        report_msp430_tlv,
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
