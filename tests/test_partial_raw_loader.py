import json
import unittest

from binaryninja import BinaryView, BinaryViewType

import msp430f5438_memory_map as memory_map


SLICE_BASE = 0x6000
SLICE_END = 0x10000
RESET_VECTOR = 0xFFFE
RESET_FUNCTION = bytes.fromhex("03 43 30 41")
RAW_DEVICE_PROFILE_SETTING = "msp430xLens.rawDeviceProfile"


class _BackedGapBinaryView(BinaryView):
    """Minimal mapped view with eight backed bytes and an unbacked suffix."""

    name = "MSP430X-Lens-Test-Backed-Gap"
    long_name = name

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, _data):
        return False

    def init(self):
        self.add_auto_segment(
            memory_map.FLASH_START,
            0x20,
            0,
            8,
            memory_map.READ_ONLY_CODE,
        )
        return True

    def perform_is_executable(self):
        return False

    def perform_get_address_size(self):
        return 4


try:
    BinaryViewType[_BackedGapBinaryView.name]
except KeyError:
    _BackedGapBinaryView.register()


def build_partial_flash_slice() -> bytes:
    """Return a raw slice whose first byte belongs at 0x6000."""

    image = bytearray(b"\xff" * (SLICE_END - SLICE_BASE))
    image[: len(RESET_FUNCTION)] = RESET_FUNCTION
    reset_offset = RESET_VECTOR - SLICE_BASE
    image[reset_offset : reset_offset + 2] = SLICE_BASE.to_bytes(2, "little")
    return bytes(image)


class PartialRawLoaderTests(unittest.TestCase):
    @staticmethod
    def _load_settings(raw):
        view_type = BinaryViewType[memory_map.MSP430F5438BinaryView.name]
        settings = view_type.get_load_settings_for_data(raw)
        if settings is None:
            raise AssertionError("MSP430F5438 raw view did not provide load settings")
        return view_type, settings

    def test_raw_image_base_load_setting_is_editable(self):
        raw = BinaryView.new(build_partial_flash_slice())
        try:
            _view_type, settings = self._load_settings(raw)

            schema = json.loads(settings.serialize_schema())
            self.assertFalse(
                schema["loader"]["settings"]["imageBase"].get("readOnly", False),
                "bare-metal slices need an editable image base in Open With Options",
            )
        finally:
            raw.file.close()

    def test_partial_slice_honors_explicit_image_base_before_analysis(self):
        raw = BinaryView.new(build_partial_flash_slice())
        try:
            view_type, settings = self._load_settings(raw)
            self.assertTrue(settings.set_integer("loader.imageBase", SLICE_BASE))
            raw.set_load_settings(view_type.name, settings)

            view = view_type.create(raw)
            self.assertIsNotNone(view)
            self.assertFalse(view.has_initial_analysis())
            self.assertEqual(
                bytes(view.read(SLICE_BASE, len(RESET_FUNCTION))),
                RESET_FUNCTION,
            )
            self.assertTrue(view.is_offset_backed_by_file(SLICE_BASE))
            self.assertTrue(view.get_segment_at(SLICE_BASE).executable)
            self.assertEqual(view.entry_point, SLICE_BASE)
            self.assertIsNotNone(view.get_function_at(SLICE_BASE))
        finally:
            raw.file.close()

    def test_raw_device_profile_can_select_f5438a_before_analysis(self):
        raw = BinaryView.new(build_partial_flash_slice())
        try:
            view_type, settings = self._load_settings(raw)
            self.assertTrue(
                settings.contains(RAW_DEVICE_PROFILE_SETTING),
                "raw load settings need an explicit device-profile choice",
            )
            self.assertTrue(settings.set_integer("loader.imageBase", SLICE_BASE))
            self.assertTrue(
                settings.set_string(RAW_DEVICE_PROFILE_SETTING, "MSP430F5438A")
            )
            raw.set_load_settings(view_type.name, settings)

            view = view_type.create(raw)
            self.assertIsNotNone(view)
            self.assertFalse(view.has_initial_analysis())
            self.assertEqual(
                view.query_metadata(memory_map.DEVICE_VARIANT_METADATA_KEY),
                "MSP430F5438A",
            )
            self.assertEqual(memory_map._device_spec_for_view(view).name, "MSP430F5438A")
            self.assertNotIn(".factory_bootcode", view.sections)
        finally:
            raw.file.close()

    def test_unbacked_zero_fill_cannot_terminate_ascii_string(self):
        raw = BinaryView.new(b"ABCDEFGH")
        try:
            view = BinaryViewType[_BackedGapBinaryView.name].create(raw)
            self.assertIsNotNone(view)
            self.assertTrue(view.is_offset_backed_by_file(memory_map.FLASH_START + 7))
            self.assertFalse(view.is_offset_backed_by_file(memory_map.FLASH_START + 8))

            self.assertEqual(memory_map._flash_ascii_string_spans(view), ())
        finally:
            raw.file.close()


if __name__ == "__main__":
    unittest.main()
