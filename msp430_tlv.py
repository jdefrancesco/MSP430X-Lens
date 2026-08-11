"""Pure MSP430F5xx device-descriptor (TLV) parsing and CRC helpers.

The Binary Ninja integration lives in :mod:`msp430f5438_memory_map`.  Keeping
the byte parser here makes malformed-table handling and checksum behavior easy
to test without depending on Binary Ninja analysis state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


TLV_REGION_START = 0x1A00
TLV_REGION_END = 0x1AFF
TLV_REGION_SIZE = TLV_REGION_END - TLV_REGION_START + 1
TLV_DESCRIPTOR_START = 0x1A08
TLV_CRC_ADDRESS = 0x1A02
TLV_CRC_DATA_START = 0x1A04

TLV_TAG_PERIPHERAL = 0x02
TLV_TAG_DIE_RECORD = 0x08
TLV_TAG_ADC12_CAL_F5438 = 0x10
TLV_TAG_ADC12_CAL = 0x11
TLV_TAG_REF_CAL = 0x12
TLV_TAG_EXTENDED = 0xFE
TLV_TAG_END = 0xFF


TLV_TAG_NAMES = {
    0x01: "legacy descriptor",
    TLV_TAG_PERIPHERAL: "peripheral discovery",
    0x03: "reserved 3",
    0x04: "reserved 4",
    0x05: "blank descriptor",
    0x06: "reserved 6",
    0x07: "reserved 7 (serial number)",
    TLV_TAG_DIE_RECORD: "die record",
    TLV_TAG_ADC12_CAL_F5438: "ADC12 calibration",
    TLV_TAG_ADC12_CAL: "ADC12 calibration",
    TLV_TAG_REF_CAL: "reference calibration",
    0x13: "ADC10 calibration",
}


TLV_PERIPHERAL_NAMES = {
    0x00: "NO_MODULE",
    0x02: "EEM_XS",
    0x03: "EEM_S",
    0x04: "EEM_M",
    0x05: "EEM_L",
    0x09: "JTAG",
    0x0F: "SBW",
    0x10: "PORT_MAPPING",
    0x1F: "PACKAGE",
    0x23: "MSP430CPUXV2",
    0x30: "PMM",
    0x32: "PMM_FR",
    0x38: "FCTL",
    0x39: "FCTL",
    0x3C: "CRC16",
    0x3D: "CRC16_RB",
    0x40: "WDT_A",
    0x41: "SFR",
    0x42: "SYS",
    0x44: "RAMCTL",
    0x46: "DMA_1",
    0x47: "DMA_3",
    0x48: "UCS",
    0x4A: "DMA_6",
    0x4B: "DMA_2",
    0x51: "PORT1_2",
    0x52: "PORT3_4",
    0x53: "PORT5_6",
    0x54: "PORT7_8",
    0x55: "PORT9_10",
    0x56: "PORT11_12",
    0x5E: "PORTU",
    0x5F: "PORTJ",
    0x60: "TA2",
    0x61: "TA3",
    0x62: "TA5",
    0x63: "TA7",
    0x65: "TB3",
    0x66: "TB5",
    0x67: "TB7",
    0x68: "RTC",
    0x69: "BT_RTC",
    0x6A: "BBS",
    0x6B: "RTC_B",
    0x6C: "TD2",
    0x6D: "TD3",
    0x6E: "TD5",
    0x6F: "TD7",
    0x70: "TEC",
    0x71: "RTC_C",
    0x80: "AES",
    0x84: "MPY16",
    0x85: "MPY32",
    0x86: "MPU",
    0x90: "USCI_AB",
    0x91: "USCI_A",
    0x92: "USCI_B",
    0x94: "EUSCI_A",
    0x95: "EUSCI_B",
    0x98: "USB",
    0xA0: "REF",
    0xA8: "COMP_B",
    0xA9: "COMP_D",
    0xB1: "LCD_B",
    0xB2: "LCD_C",
    0xC0: "DAC12_A",
    0xC8: "SD16_B_1",
    0xC9: "SD16_B_2",
    0xCA: "SD16_B_3",
    0xCB: "SD16_B_4",
    0xCC: "SD16_B_5",
    0xCD: "SD16_B_6",
    0xCE: "SD16_B_7",
    0xCF: "SD16_B_8",
    0xD1: "ADC12_A",
    0xD3: "ADC10_A",
    0xD4: "ADC10_B",
    0xD8: "SD16_A",
    0xFC: "TI_BSL",
}


@dataclass(frozen=True, slots=True)
class TlvRecord:
    """One bounded descriptor from the TLV record stream."""

    address: int
    tag: int
    length: int
    value: bytes
    header_length: int = 2
    extended_tag: Optional[int] = None

    @property
    def payload_address(self) -> int:
        return self.address + self.header_length

    @property
    def end(self) -> int:
        return self.payload_address + self.length

    @property
    def effective_tag(self) -> int:
        return self.extended_tag if self.extended_tag is not None else self.tag

    @property
    def name(self) -> str:
        if self.extended_tag is not None:
            return f"extended tag {self.extended_tag:#04x}"
        return TLV_TAG_NAMES.get(self.tag, f"tag {self.tag:#04x}")


@dataclass(frozen=True, slots=True)
class TlvPeripheralEntry:
    """One peripheral ID and its cumulative module base address."""

    address: int
    peripheral_id: int

    @property
    def name(self) -> str:
        return TLV_PERIPHERAL_NAMES.get(
            self.peripheral_id,
            f"PID_{self.peripheral_id:02X}",
        )


@dataclass(frozen=True, slots=True)
class TlvPeripheralDescriptor:
    """Decoded F5438/A four-word prefix of a peripheral descriptor."""

    memory_words: tuple[int, int, int, int]
    entries: tuple[TlvPeripheralEntry, ...]
    trailing_data: bytes


@dataclass(frozen=True, slots=True)
class TlvDescriptorBlock:
    """Parsed device-descriptor block, including trust and parse state."""

    base: int
    info_length: int
    crc_length: int
    stored_crc: int
    computed_crc: int
    device_id: bytes
    hardware_revision: int
    firmware_revision: int
    records: tuple[TlvRecord, ...]
    terminator_address: Optional[int]
    issues: tuple[str, ...]
    erased: bool = False

    @property
    def crc_valid(self) -> bool:
        return not self.erased and self.stored_crc == self.computed_crc

    @property
    def end(self) -> int:
        return self.base + TLV_REGION_SIZE


def crc16_ccitt_false(data: bytes, seed: int = 0xFFFF) -> int:
    """Return TI's TLV CRC16 (CRC-16/CCITT-FALSE) for ``data``.

    MSP430x5xx/6xx Family User's Guide SLAU208Q section 1.13.4 specifies a
    0xffff seed and ascending bytes through the CRC16 reverse-input register;
    this is the equivalent software formulation with polynomial 0x1021.
    """

    crc = seed & 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def parse_tlv_descriptor_block(
    data: bytes,
    *,
    base: int = TLV_REGION_START,
) -> TlvDescriptorBlock:
    """Parse one complete 256-byte F5xx/F6xx device-descriptor block.

    Record lengths are never allowed to cross the supplied block.  A malformed
    record ends parsing at that point rather than attempting to resynchronize
    in calibration bytes that happen to resemble another tag.
    """

    data = bytes(data)
    if len(data) != TLV_REGION_SIZE:
        raise ValueError(
            f"TLV descriptor block must be {TLV_REGION_SIZE:#x} bytes, got {len(data):#x}"
        )

    crc_offset = TLV_CRC_ADDRESS - TLV_REGION_START
    crc_data_offset = TLV_CRC_DATA_START - TLV_REGION_START
    stored_crc = int.from_bytes(data[crc_offset:crc_offset + 2], "little")
    computed_crc = crc16_ccitt_false(data[crc_data_offset:])
    erased = all(byte == 0xFF for byte in data)
    issues: list[str] = []
    records: list[TlvRecord] = []
    terminator_address: Optional[int] = None

    if erased:
        issues.append("descriptor block is erased")
    else:
        if data[0] != 0x06:
            issues.append(f"unexpected info length {data[0]:#04x}")
        if data[1] != 0x06:
            issues.append(f"unexpected CRC length {data[1]:#04x}")

        if not issues:
            cursor = TLV_DESCRIPTOR_START - TLV_REGION_START
            while cursor < len(data):
                record_address = base + cursor
                tag = data[cursor]
                if tag == TLV_TAG_END:
                    terminator_address = record_address
                    break
                if tag == 0:
                    issues.append(f"invalid TLV tag 0 at {record_address:#06x}")
                    break

                if tag == TLV_TAG_EXTENDED:
                    if cursor + 4 > len(data):
                        issues.append(f"truncated extended TLV header at {record_address:#06x}")
                        break
                    extended_tag = data[cursor + 1]
                    length = int.from_bytes(data[cursor + 2:cursor + 4], "little")
                    header_length = 4
                else:
                    if cursor + 2 > len(data):
                        issues.append(f"truncated TLV header at {record_address:#06x}")
                        break
                    extended_tag = None
                    length = data[cursor + 1]
                    header_length = 2

                payload_start = cursor + header_length
                record_end = payload_start + length
                if record_end > len(data):
                    issues.append(
                        f"TLV record at {record_address:#06x} extends beyond {base + len(data):#06x}"
                    )
                    break

                records.append(
                    TlvRecord(
                        address=record_address,
                        tag=tag,
                        length=length,
                        value=data[payload_start:record_end],
                        header_length=header_length,
                        extended_tag=extended_tag,
                    )
                )
                cursor = record_end

            if terminator_address is None and not issues:
                issues.append("TLV record stream has no end tag")

    return TlvDescriptorBlock(
        base=base,
        info_length=data[0],
        crc_length=data[1],
        stored_crc=stored_crc,
        computed_crc=computed_crc,
        device_id=data[4:6],
        hardware_revision=data[6],
        firmware_revision=data[7],
        records=tuple(records),
        terminator_address=terminator_address,
        issues=tuple(issues),
        erased=erased,
    )


def decode_peripheral_descriptor(
    record: TlvRecord,
) -> Optional[TlvPeripheralDescriptor]:
    """Decode the F5438/A memory/peripheral prefix of a PDTAG payload."""

    if (
        record.tag != TLV_TAG_PERIPHERAL
        or len(record.value) < 10
        or record.value[8] != 0
    ):
        return None

    memory_words = tuple(
        int.from_bytes(record.value[offset:offset + 2], "little")
        for offset in range(0, 8, 2)
    )
    count = record.value[9]
    entries_end = 10 + (count * 2)
    if entries_end > len(record.value):
        return None
    trailing_data = record.value[entries_end:]
    if not trailing_data or trailing_data[-1] != 0:
        return None

    address = 0
    entries = []
    for offset in range(10, entries_end, 2):
        displacement = record.value[offset]
        peripheral_id = record.value[offset + 1]
        unit = 0x800 if displacement & 0x80 else 0x10
        address += (displacement & 0x7F) * unit
        entries.append(TlvPeripheralEntry(address, peripheral_id))

    return TlvPeripheralDescriptor(
        memory_words=memory_words,  # type: ignore[arg-type]
        entries=tuple(entries),
        trailing_data=trailing_data,
    )
