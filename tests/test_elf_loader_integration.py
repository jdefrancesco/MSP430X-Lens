import unittest

from binaryninja import (
    BinaryView,
    BinaryViewType,
    SectionSemantics,
    Settings,
    SettingsScope,
    load,
)

import msp430f5438_memory_map as memory_map
from tests.fixture_firmware import (
    ELF_RESET_FUNCTION,
    ELF_STRING_REGION_END,
    EXACT_MIN_STRING_ADDRESS,
    LONG_STRING_ADDRESS,
    RESET_HANDLER,
    RESET_VECTOR,
    SHORT_JUNK_STRING_ADDRESS,
    TLV_DESCRIPTOR,
    TLV_DESCRIPTOR_ADDRESS,
    build_msp430_elf_firmware,
)


class ElfLoaderIntegrationTests(unittest.TestCase):
    def _create_elf_view(self, image=None):
        raw = BinaryView.new(
            build_msp430_elf_firmware() if image is None else image
        )
        view_type = BinaryViewType["ELF"]
        self.assertTrue(view_type.is_valid_for_data(raw))
        view = view_type.create(raw)
        self.assertIsNotNone(view)
        return raw, view

    def assert_symbol_at(self, view, name, address):
        self.assertTrue(
            any(
                symbol.address == address
                for symbol in view.get_symbols_by_raw_name(name)
            ),
            f"expected symbol {name} at {address:#x}",
        )

    def test_elf_factory_selects_msp430x_before_initial_analysis(self):
        raw, view = self._create_elf_view()
        try:
            self.assertEqual(view.view_type, "ELF")
            self.assertFalse(view.has_initial_analysis())
            self.assertEqual(str(view.arch), "msp430x")
            self.assertEqual(str(view.platform), "msp430x")
            self.assertEqual(view.entry_point, RESET_HANDLER)

            reset_functions = [
                function
                for function in view.functions
                if function.start == RESET_HANDLER
            ]
            self.assertEqual(len(reset_functions), 1)
            self.assertEqual(str(reset_functions[0].arch), "msp430x")
            self.assertEqual(str(reset_functions[0].platform), "msp430x")
        finally:
            raw.file.close()

    def test_elf_finalization_raises_only_the_inherited_string_minimum(self):
        inherited_minimum, inherited_scope = Settings().get_integer_with_scope(
            memory_map.AUTO_STRING_MIN_LENGTH_SETTING,
        )
        expected_minimum = inherited_minimum
        if (
            inherited_scope == SettingsScope.SettingsDefaultScope
            and inherited_minimum < memory_map.ASCII_STRING_MIN_LEN
        ):
            expected_minimum = memory_map.ASCII_STRING_MIN_LEN

        raw, view = self._create_elf_view()
        try:
            self.assertFalse(view.has_initial_analysis())
            configured_minimum = Settings().get_integer(
                memory_map.AUTO_STRING_MIN_LENGTH_SETTING,
                view,
            )
            self.assertEqual(configured_minimum, expected_minimum)
        finally:
            raw.file.close()

    def test_elf_finalization_preserves_layout_and_applies_device_annotations(self):
        raw, view = self._create_elf_view()
        try:
            expected_segments = (
                (
                    TLV_DESCRIPTOR_ADDRESS,
                    TLV_DESCRIPTOR_ADDRESS + len(TLV_DESCRIPTOR),
                    True,
                    False,
                    False,
                ),
                (
                    RESET_HANDLER,
                    RESET_HANDLER + len(ELF_RESET_FUNCTION),
                    True,
                    False,
                    True,
                ),
                (
                    SHORT_JUNK_STRING_ADDRESS,
                    ELF_STRING_REGION_END,
                    True,
                    False,
                    False,
                ),
                (0xFF80, 0x10000, True, False, False),
            )
            for start, end, readable, writable, executable in expected_segments:
                with self.subTest(segment_start=start):
                    segment = view.get_segment_at(start)
                    self.assertIsNotNone(segment)
                    self.assertEqual((segment.start, segment.end), (start, end))
                    self.assertEqual(segment.data_length, end - start)
                    self.assertEqual(segment.readable, readable)
                    self.assertEqual(segment.writable, writable)
                    self.assertEqual(segment.executable, executable)

            expected_sections = {
                ".tlv": SectionSemantics.ReadOnlyDataSectionSemantics,
                ".text": SectionSemantics.ReadOnlyCodeSectionSemantics,
                ".rodata": SectionSemantics.ReadOnlyDataSectionSemantics,
                ".vectors": SectionSemantics.ReadOnlyDataSectionSemantics,
            }
            for name, semantics in expected_sections.items():
                with self.subTest(section=name):
                    self.assertIn(name, view.sections)
                    self.assertEqual(view.sections[name].semantics, semantics)

            self.assertEqual(
                bytes(view.read(TLV_DESCRIPTOR_ADDRESS, len(TLV_DESCRIPTOR))),
                TLV_DESCRIPTOR,
            )
            self.assertEqual(
                bytes(view.read(RESET_HANDLER, len(ELF_RESET_FUNCTION))),
                ELF_RESET_FUNCTION,
            )
            self.assertEqual(
                int.from_bytes(view.read(RESET_VECTOR, 2), "little"),
                RESET_HANDLER,
            )

            self.assertEqual(
                view.query_metadata(memory_map.DEVICE_VARIANT_METADATA_KEY),
                "MSP430F5438A",
            )
            self.assertEqual(memory_map._read_tlv_descriptor(view).status, "valid")
            tlv_info = view.get_data_var_at(TLV_DESCRIPTOR_ADDRESS)
            self.assertIsNotNone(tlv_info)
            self.assertIn("msp430_tlv_info_block", str(tlv_info.type))
            self.assertIn(
                "CRC16/CCITT-FALSE valid",
                view.get_comment_at(TLV_DESCRIPTOR_ADDRESS + 2),
            )

            self.assert_symbol_at(view, "_start", RESET_HANDLER)
            self.assert_symbol_at(
                view,
                "__msp430f5438_flash_start",
                RESET_HANDLER,
            )
            self.assert_symbol_at(view, "vector_reset", RESET_VECTOR)
            self.assert_symbol_at(view, "tlv_crc16", TLV_DESCRIPTOR_ADDRESS + 2)
            self.assert_symbol_at(view, "WDTCTL", 0x015C)
            self.assertTrue(
                view.query_metadata(memory_map.ELF_PREPARED_METADATA_KEY)
            )

            reset_functions = [
                function
                for function in view.functions
                if function.start == RESET_HANDLER
            ]
            self.assertEqual(len(reset_functions), 1)
            # Existing ELF symbols are authoritative; the device hook must not
            # replace `_start` with its raw-firmware reset-handler alias.
            self.assertEqual(reset_functions[0].name, "_start")
            self.assertFalse(memory_map._prepare_msp430x_elf_view(view))
        finally:
            raw.file.close()

    def test_generic_msp430_elf_does_not_assume_an_f5438_device_profile(self):
        image = bytearray(build_msp430_elf_firmware())
        descriptor_offset = image.find(TLV_DESCRIPTOR)
        self.assertGreaterEqual(descriptor_offset, 0)
        image[descriptor_offset:descriptor_offset + len(TLV_DESCRIPTOR)] = (
            b"\xff" * len(TLV_DESCRIPTOR)
        )

        raw, view = self._create_elf_view(bytes(image))
        try:
            self.assertEqual(str(view.arch), "msp430x")
            self.assertTrue(
                view.query_metadata(memory_map.ELF_PREPARED_METADATA_KEY)
            )
            with self.assertRaises(KeyError):
                view.query_metadata(memory_map.DEVICE_VARIANT_METADATA_KEY)
            self.assertEqual(view.get_symbols_by_raw_name("WDTCTL"), [])
            self.assertEqual(view.get_symbols_by_raw_name("vector_reset"), [])
            self.assertIsNone(view.get_data_var_at(TLV_DESCRIPTOR_ADDRESS))
        finally:
            raw.file.close()

    def test_explicit_elf_profile_is_applied_before_initial_analysis(self):
        image = bytearray(build_msp430_elf_firmware())
        descriptor_offset = image.find(TLV_DESCRIPTOR)
        self.assertGreaterEqual(descriptor_offset, 0)
        image[descriptor_offset:descriptor_offset + len(TLV_DESCRIPTOR)] = (
            b"\xff" * len(TLV_DESCRIPTOR)
        )

        view = load(
            bytes(image),
            update_analysis=False,
            options={
                memory_map.ELF_DEVICE_PROFILE_SETTING: "MSP430F5438A",
            },
        )
        self.assertIsNotNone(view)
        try:
            self.assertEqual(view.view_type, "ELF")
            self.assertFalse(view.has_initial_analysis())
            self.assertEqual(str(view.arch), "msp430x")
            self.assertEqual(
                view.query_metadata(memory_map.DEVICE_VARIANT_METADATA_KEY),
                "MSP430F5438A",
            )
            self.assert_symbol_at(view, "WDTCTL", 0x015C)
        finally:
            view.file.close()

    def test_none_elf_profile_overrides_factory_tlv_detection(self):
        view = load(
            build_msp430_elf_firmware(),
            update_analysis=False,
            options={
                memory_map.ELF_DEVICE_PROFILE_SETTING: "none",
            },
        )
        self.assertIsNotNone(view)
        try:
            self.assertEqual(str(view.arch), "msp430x")
            with self.assertRaises(KeyError):
                view.query_metadata(memory_map.DEVICE_VARIANT_METADATA_KEY)
            self.assertEqual(view.get_symbols_by_raw_name("WDTCTL"), [])
            self.assertIsNone(view.get_data_var_at(TLV_DESCRIPTOR_ADDRESS))
        finally:
            view.file.close()

    def test_explicit_builtin_msp430_platform_override_is_preserved(self):
        view = load(
            build_msp430_elf_firmware(),
            update_analysis=False,
            options={"loader.platform": "msp430"},
        )
        self.assertIsNotNone(view)
        try:
            self.assertEqual(str(view.arch), "msp430")
            self.assertEqual(str(view.platform), "msp430")
            with self.assertRaises(KeyError):
                view.query_metadata(memory_map.ELF_PREPARED_METADATA_KEY)
            self.assertEqual(view.get_symbols_by_raw_name("WDTCTL"), [])
        finally:
            view.file.close()

    def test_elf_first_analysis_uses_hook_results_without_duplicate_functions(self):
        raw, view = self._create_elf_view()
        try:
            configured_minimum = Settings().get_integer(
                memory_map.AUTO_STRING_MIN_LENGTH_SETTING,
                view,
            )
            view.update_analysis_and_wait()
            self.assertTrue(view.has_initial_analysis())

            if configured_minimum == memory_map.ASCII_STRING_MIN_LEN:
                self.assertIsNone(view.get_string_at(SHORT_JUNK_STRING_ADDRESS))
                self.assertIsNotNone(view.get_string_at(EXACT_MIN_STRING_ADDRESS))
                self.assertIsNotNone(view.get_string_at(LONG_STRING_ADDRESS))

            reset_functions = [
                function
                for function in view.functions
                if function.start == RESET_HANDLER
            ]
            self.assertEqual(len(reset_functions), 1)
            self.assertEqual(str(reset_functions[0].arch), "msp430x")
            self.assertEqual(str(reset_functions[0].platform), "msp430x")
            self.assertEqual(reset_functions[0].name, "_start")
        finally:
            raw.file.close()

    def test_relocatable_elf_selects_arch_without_absolute_device_annotations(self):
        image = bytearray(build_msp430_elf_firmware())
        image[16:18] = (1).to_bytes(2, "little")  # ET_REL
        raw, view = self._create_elf_view(bytes(image))
        try:
            self.assertEqual(str(view.arch), "msp430x")
            self.assertEqual(str(view.platform), "msp430x")
            self.assertTrue(view.relocatable)
            with self.assertRaises(KeyError):
                view.query_metadata(memory_map.ELF_PREPARED_METADATA_KEY)
            self.assertEqual(view.get_symbols_by_raw_name("WDTCTL"), [])
            self.assertIsNone(view.get_data_var_at(TLV_DESCRIPTOR_ADDRESS))
        finally:
            raw.file.close()


if __name__ == "__main__":
    unittest.main()
