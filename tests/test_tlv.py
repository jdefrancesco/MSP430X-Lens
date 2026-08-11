from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from binaryninja import BinaryView, BinaryViewType

import msp430f5438_memory_map as memory_map
from msp430_tlv import (
    TLV_TAG_ADC12_CAL,
    TLV_TAG_DIE_RECORD,
    TLV_TAG_PERIPHERAL,
    TLV_TAG_REF_CAL,
    TlvRecord,
    crc16_ccitt_false,
    decode_peripheral_descriptor,
    parse_tlv_descriptor_block,
)
from tests.fixture_firmware import (
    RESET_HANDLER,
    SPARSE_FUNCTION_ADDRESS,
    TLV_DESCRIPTOR,
    TLV_DESCRIPTOR_ADDRESS,
    TLV_STORED_CRC,
    build_base_zero_low64k_firmware,
)


F5438_TLV_STORED_CRC = 0x5FB1


def build_f5438_tlv_descriptor():
    descriptor = bytearray(b"\xff" * 0x100)
    descriptor[0:8] = bytes.fromhex("06 06 b1 5f 54 38 12 34")
    descriptor[0x08:0x14] = bytes.fromhex(
        "08 0a 11 22 33 44 34 12 78 56 01 00"
    )
    descriptor[0x14:0x26] = bytes.fromhex(
        "10 10 ff 7f f0 ff 00 01 00 02 00 03 00 04 00 05 00 06"
    )
    descriptor[0x26:0x28] = bytes((TLV_TAG_PERIPHERAL, 0x5D))
    descriptor[0x28:0x85] = b"\x00" * 0x5D
    descriptor[0x85] = 0xFF
    return bytes(descriptor)


class PartialTlvView:
    def is_offset_backed_by_file(self, address):
        return TLV_DESCRIPTOR_ADDRESS <= address < TLV_DESCRIPTOR_ADDRESS + 8

    def read(self, address, length):
        offset = address - TLV_DESCRIPTOR_ADDRESS
        return TLV_DESCRIPTOR[offset:offset + length]


class BackedTlvView(PartialTlvView):
    def __init__(self, descriptor=TLV_DESCRIPTOR):
        self.metadata = {}
        self.descriptor = bytes(descriptor)

    def is_offset_backed_by_file(self, address):
        return (
            TLV_DESCRIPTOR_ADDRESS
            <= address
            < TLV_DESCRIPTOR_ADDRESS + len(TLV_DESCRIPTOR)
        )

    def query_metadata(self, key):
        if key not in self.metadata:
            raise KeyError(key)
        return self.metadata[key]

    def store_metadata(self, key, value, isAuto=False):
        self.metadata[key] = value

    def read(self, address, length):
        offset = address - TLV_DESCRIPTOR_ADDRESS
        return self.descriptor[offset:offset + length]


class ElfStyleTlvView(BackedTlvView):
    """Minimal non-loader mapped view with only a backed TLV segment."""

    def __init__(self, descriptor=TLV_DESCRIPTOR):
        super().__init__(descriptor)
        self.data_vars = {}
        self.symbols = []
        self.comments = {}

    def get_data_var_at(self, address):
        for start, variable in self.data_vars.items():
            if start <= address < start + variable.type.width:
                return variable
        return None

    def get_next_data_var_after(self, address):
        starts = [start for start in self.data_vars if start > address]
        return self.data_vars[min(starts)] if starts else None

    def define_data_var(self, address, var_type, name=None):
        self.data_vars[address] = SimpleNamespace(address=address, type=var_type)
        if name is not None:
            self.symbols.append(SimpleNamespace(address=address, raw_name=name))

    define_user_data_var = define_data_var

    def get_symbols_by_raw_name(self, name):
        return [symbol for symbol in self.symbols if symbol.raw_name == name]

    def define_auto_symbol(self, symbol):
        self.symbols.append(symbol)

    define_user_symbol = define_auto_symbol

    def get_comment_at(self, address):
        return self.comments.get(address)

    def set_comment_at(self, address, comment):
        self.comments[address] = comment


class FlatImageView:
    def __init__(self, data):
        self.data = bytes(data)

    def read(self, offset, length):
        return self.data[offset:offset + length]


class TlvParserTests(unittest.TestCase):
    def test_crc16_ccitt_false_standard_check_value(self):
        self.assertEqual(crc16_ccitt_false(b"123456789"), 0x29B1)

    def test_f5438a_descriptor_and_crc(self):
        descriptor = parse_tlv_descriptor_block(TLV_DESCRIPTOR)

        self.assertEqual(descriptor.base, TLV_DESCRIPTOR_ADDRESS)
        self.assertEqual(descriptor.info_length, 0x06)
        self.assertEqual(descriptor.crc_length, 0x06)
        self.assertEqual(descriptor.stored_crc, TLV_STORED_CRC)
        self.assertEqual(descriptor.computed_crc, TLV_STORED_CRC)
        self.assertTrue(descriptor.crc_valid)
        self.assertEqual(descriptor.device_id, bytes.fromhex("05 80"))
        self.assertEqual(descriptor.hardware_revision, 0x12)
        self.assertEqual(descriptor.firmware_revision, 0x34)
        self.assertEqual(descriptor.issues, ())
        self.assertEqual(descriptor.terminator_address, 0x1A91)

    def test_legacy_f5438_layout_and_adc_tag_are_distinct(self):
        descriptor = parse_tlv_descriptor_block(build_f5438_tlv_descriptor())

        self.assertEqual(descriptor.stored_crc, F5438_TLV_STORED_CRC)
        self.assertEqual(descriptor.computed_crc, F5438_TLV_STORED_CRC)
        self.assertTrue(descriptor.crc_valid)
        self.assertEqual(descriptor.device_id, b"\x54\x38")
        self.assertEqual(
            [(record.address, record.tag, record.length) for record in descriptor.records],
            [
                (0x1A08, TLV_TAG_DIE_RECORD, 0x0A),
                (0x1A14, memory_map.TLV_TAG_ADC12_CAL_F5438, 0x10),
                (0x1A26, TLV_TAG_PERIPHERAL, 0x5D),
            ],
        )
        adc_comment = memory_map._tlv_record_comment(descriptor.records[1])
        self.assertIn("ref1.5_factor", adc_comment)
        self.assertIn("ref2.5_factor", adc_comment)
        self.assertNotIn("ref2.0", adc_comment)
        definitions = memory_map._tlv_structure_definitions()
        legacy_members = [
            name
            for _type, name, _offset in definitions[
                "msp430_tlv_adc12_calibration_f5438"
            ][1]
        ]
        a_members = [
            name
            for _type, name, _offset in definitions[
                "msp430_tlv_adc12_calibration_f5438a"
            ][1]
        ]
        self.assertIn("ref15_factor", legacy_members)
        self.assertNotIn("ref20_30c", legacy_members)
        self.assertIn("ref20_30c", a_members)

    def test_known_records_retain_addresses_lengths_and_values(self):
        records = parse_tlv_descriptor_block(TLV_DESCRIPTOR).records

        self.assertEqual(
            [(record.address, record.tag, record.length) for record in records],
            [
                (0x1A08, TLV_TAG_DIE_RECORD, 0x0A),
                (0x1A14, TLV_TAG_ADC12_CAL, 0x10),
                (0x1A26, TLV_TAG_REF_CAL, 0x06),
                (0x1A2E, TLV_TAG_PERIPHERAL, 0x61),
            ],
        )
        die = records[0]
        self.assertEqual(die.header_length, 2)
        self.assertEqual(die.payload_address, 0x1A0A)
        self.assertEqual(die.end, 0x1A14)
        self.assertEqual(die.name, "die record")
        self.assertEqual(die.value, bytes.fromhex("11 22 33 44 34 12 78 56 01 00"))

    def test_peripheral_descriptor_includes_both_crc16_interfaces(self):
        descriptor = parse_tlv_descriptor_block(TLV_DESCRIPTOR)
        peripheral_record = descriptor.records[-1]
        peripheral = decode_peripheral_descriptor(peripheral_record)

        self.assertIsNotNone(peripheral)
        self.assertEqual(peripheral.memory_words, (0x8A08, 0x860C, 0x300E, 0x982E))
        self.assertEqual(len(peripheral.entries), 0x21)
        crc_entries = [
            (entry.address, entry.peripheral_id, entry.name)
            for entry in peripheral.entries
            if entry.peripheral_id in (0x3C, 0x3D)
        ]
        self.assertEqual(
            crc_entries,
            [(0x150, 0x3C, "CRC16"), (0x150, 0x3D, "CRC16_RB")],
        )

    def test_peripheral_descriptor_requires_both_delimiters(self):
        record = parse_tlv_descriptor_block(TLV_DESCRIPTOR).records[-1]

        bad_memory_delimiter = bytearray(record.value)
        bad_memory_delimiter[8] = 1
        self.assertIsNone(
            decode_peripheral_descriptor(
                TlvRecord(
                    record.address,
                    record.tag,
                    record.length,
                    bytes(bad_memory_delimiter),
                )
            )
        )

        bad_interrupt_delimiter = bytearray(record.value)
        bad_interrupt_delimiter[-1] = 1
        self.assertIsNone(
            decode_peripheral_descriptor(
                TlvRecord(
                    record.address,
                    record.tag,
                    record.length,
                    bytes(bad_interrupt_delimiter),
                )
            )
        )

    def test_bad_crc_remains_parseable_but_untrusted(self):
        damaged = bytearray(TLV_DESCRIPTOR)
        damaged[0x10] ^= 0x01

        descriptor = parse_tlv_descriptor_block(damaged)

        self.assertEqual(descriptor.stored_crc, TLV_STORED_CRC)
        self.assertNotEqual(descriptor.computed_crc, TLV_STORED_CRC)
        self.assertFalse(descriptor.crc_valid)
        self.assertEqual(len(descriptor.records), 4)

    def test_crc_covers_erased_tail_through_0x1aff(self):
        damaged = bytearray(TLV_DESCRIPTOR)
        damaged[-1] = 0x00

        descriptor = parse_tlv_descriptor_block(damaged)

        self.assertFalse(descriptor.crc_valid)
        self.assertEqual(descriptor.terminator_address, 0x1A91)

    def test_record_cannot_extend_past_descriptor_region(self):
        malformed = bytearray(TLV_DESCRIPTOR)
        malformed[0x2F] = 0xFF

        descriptor = parse_tlv_descriptor_block(malformed)

        self.assertFalse(descriptor.crc_valid)
        self.assertEqual(len(descriptor.records), 3)
        self.assertTrue(
            any("extends beyond" in issue for issue in descriptor.issues),
            descriptor.issues,
        )

    def test_extended_tag_uses_four_byte_header_and_little_endian_length(self):
        extended = bytearray(b"\xff" * 0x100)
        extended[0:8] = bytes.fromhex("06 06 00 00 54 38 01 02")
        extended[8:15] = bytes.fromhex("fe 42 02 00 aa bb ff")
        crc = crc16_ccitt_false(extended[4:])
        extended[2:4] = crc.to_bytes(2, "little")

        descriptor = parse_tlv_descriptor_block(extended)

        self.assertTrue(descriptor.crc_valid)
        self.assertEqual(len(descriptor.records), 1)
        record = descriptor.records[0]
        self.assertEqual(record.tag, 0xFE)
        self.assertEqual(record.extended_tag, 0x42)
        self.assertEqual(record.header_length, 4)
        self.assertEqual(record.length, 2)
        self.assertEqual(record.value, b"\xaa\xbb")
        self.assertEqual(descriptor.terminator_address, 0x1A0E)

    def test_erased_and_partial_blocks_are_not_misidentified(self):
        erased = parse_tlv_descriptor_block(b"\xff" * 0x100)
        self.assertTrue(erased.erased)
        self.assertFalse(erased.crc_valid)
        self.assertEqual(erased.records, ())
        self.assertTrue(any("erased" in issue for issue in erased.issues))

        with self.assertRaises(ValueError):
            parse_tlv_descriptor_block(TLV_DESCRIPTOR[:-1])

    def test_zero_filled_block_stops_before_interpreting_zero_length_records(self):
        descriptor = parse_tlv_descriptor_block(b"\x00" * 0x100)

        self.assertFalse(descriptor.crc_valid)
        self.assertEqual(descriptor.records, ())
        self.assertTrue(any("info length" in issue for issue in descriptor.issues))


class TlvBinaryViewIntegrationTests(unittest.TestCase):
    def test_elf_style_backed_segment_uses_same_bounded_annotations(self):
        view = ElfStyleTlvView()
        result = memory_map._read_tlv_descriptor(view)

        self.assertEqual(result.status, "valid")
        self.assertEqual(memory_map._device_spec_for_view(view).name, "MSP430F5438A")
        with patch.object(memory_map, "_register_tlv_types", return_value={}):
            created = memory_map._annotate_tlv_descriptor(
                view,
                descriptor=result,
                auto_defined=True,
            )
            repeated = memory_map._annotate_tlv_descriptor(
                view,
                descriptor=result,
                auto_defined=True,
            )

        self.assertGreater(created, 0)
        self.assertEqual(repeated, 0)
        self.assertEqual(
            tuple(sorted(view.data_vars)),
            (0x1A00, 0x1A08, 0x1A14, 0x1A26, 0x1A2E, 0x1A91),
        )

    def test_mapped_tlv_autodetects_variant_without_raw_loader_metadata(self):
        view = BackedTlvView()

        detected = memory_map._device_spec_for_view(view)

        self.assertEqual(detected.name, "MSP430F5438A")
        self.assertEqual(
            view.metadata[memory_map.DEVICE_VARIANT_METADATA_KEY],
            "MSP430F5438A",
        )

    def test_variant_autodetection_requires_a_valid_factory_crc(self):
        firmware = bytearray(build_base_zero_low64k_firmware())
        detected = memory_map._detect_device_spec_from_tlv(FlatImageView(firmware), 0)
        self.assertIsNotNone(detected)
        self.assertEqual(detected.name, "MSP430F5438A")

        firmware[TLV_DESCRIPTOR_ADDRESS + 0x10] ^= 1
        self.assertIsNone(
            memory_map._detect_device_spec_from_tlv(FlatImageView(firmware), 0)
        )

        legacy_firmware = bytearray(b"\xff" * 0x10000)
        legacy_firmware[0x1A00:0x1B00] = build_f5438_tlv_descriptor()
        legacy = memory_map._detect_device_spec_from_tlv(
            FlatImageView(legacy_firmware),
            0,
        )
        self.assertIsNotNone(legacy)
        self.assertEqual(legacy.name, "MSP430F5438")

    def test_partial_file_backing_is_not_parsed_as_zero_filled_tlv(self):
        result = memory_map._read_tlv_descriptor(PartialTlvView())

        self.assertEqual(result.status, "partial")
        self.assertEqual(result.backed_bytes, 8)
        self.assertIsNone(result.block)

    def test_malformed_backed_tlv_is_not_annotated(self):
        view = BackedTlvView(b"\x00" * 0x100)
        result = memory_map._read_tlv_descriptor(view)

        self.assertEqual(result.status, "malformed")
        self.assertIsNotNone(result.block)
        self.assertEqual(result.block.records, ())
        self.assertEqual(
            memory_map._annotate_tlv_descriptor(view, descriptor=result),
            0,
        )

    def test_crc_mismatch_remains_visible_and_safely_annotated(self):
        damaged = bytearray(TLV_DESCRIPTOR)
        damaged[0x10] ^= 1
        view = ElfStyleTlvView(damaged)
        result = memory_map._read_tlv_descriptor(view)

        self.assertEqual(result.status, "crc-mismatch")
        self.assertFalse(result.block.crc_valid)
        with patch.object(memory_map, "_register_tlv_types", return_value={}):
            created = memory_map._annotate_tlv_descriptor(
                view,
                descriptor=result,
                auto_defined=True,
            )

        self.assertGreater(created, 0)
        self.assertIn("MISMATCH", view.comments[0x1A02])
        self.assertIn(0x1A08, view.data_vars)

    def test_base_zero_low64k_view_reads_and_annotates_tlv_idempotently(self):
        raw = BinaryView.new(build_base_zero_low64k_firmware())
        try:
            view_type = BinaryViewType[memory_map.MSP430F5438BinaryView.name]
            self.assertTrue(view_type.is_valid_for_data(raw))
            view = view_type.create(raw)
            self.assertIsNotNone(view)
            view.update_analysis_and_wait()
            self.assertEqual(
                memory_map._device_spec_for_view(view).name,
                "MSP430F5438A",
            )
            self.assertEqual(str(view.arch), "msp430x")
            self.assertEqual(view.entry_point, RESET_HANDLER)
            self.assertIsNotNone(view.get_function_at(RESET_HANDLER))
            self.assertIsNotNone(view.get_function_at(SPARSE_FUNCTION_ADDRESS))

            read_result = memory_map._read_tlv_descriptor(view)
            self.assertEqual(read_result.status, "valid")
            self.assertEqual(read_result.backed_bytes, len(TLV_DESCRIPTOR))
            descriptor = read_result.block
            self.assertIsNotNone(descriptor)
            self.assertTrue(descriptor.crc_valid)
            self.assertEqual(descriptor.stored_crc, TLV_STORED_CRC)
            self.assertEqual(
                [record.address for record in descriptor.records],
                [0x1A08, 0x1A14, 0x1A26, 0x1A2E],
            )
            self.assertIn("valid", view.get_comment_at(0x1A02))
            self.assertEqual(view.get_data_var_at(0x1A00).type.width, 8)
            self.assertEqual(view.get_data_var_at(0x1A08).type.width, 12)
            self.assertEqual(view.get_data_var_at(0x1A14).type.width, 18)
            self.assertEqual(view.get_data_var_at(0x1A26).type.width, 8)
            self.assertIsNotNone(view.get_data_var_at(0x1A91))
            self.assertEqual(
                [
                    function.start
                    for function in view.functions
                    if 0x1A00 <= function.start <= 0x1AFF
                ],
                [],
            )

            report_output = StringIO()
            with redirect_stdout(report_output):
                memory_map.report_msp430_tlv(view)
            report = report_output.getvalue()
            self.assertIn("CRC16/CCITT-FALSE: valid", report)
            self.assertIn("0x0150: CRC16", report)
            self.assertIn("0x0150: CRC16_RB", report)

            first_repeat = memory_map._annotate_tlv_descriptor(
                view,
                descriptor=descriptor,
                auto_defined=True,
                verbose=False,
            )
            before = tuple(sorted(view.data_vars))
            second_repeat = memory_map._annotate_tlv_descriptor(
                view,
                descriptor=descriptor,
                auto_defined=True,
                verbose=False,
            )
            after = tuple(sorted(view.data_vars))

            self.assertEqual(after, before)
            self.assertEqual(first_repeat, 0)
            self.assertEqual(second_repeat, 0)
            self.assertIsNotNone(view.get_data_var_at(TLV_DESCRIPTOR_ADDRESS))
            for record in descriptor.records:
                self.assertIsNotNone(view.get_data_var_at(record.address))
        finally:
            raw.file.close()


if __name__ == "__main__":
    unittest.main()
