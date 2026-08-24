import unittest
from unittest import mock

from binaryninja import BinaryView, BinaryViewType, FunctionParameter, Type

import msp430f5438_memory_map as memory_map
from tests.fixture_firmware import (
    RESET_HANDLER,
    SPARSE_FUNCTION_ADDRESS,
    build_msp430_elf_firmware,
    build_sparse_raw_firmware,
)


PORT1_VECTOR = 0xFFDE


def _segment_snapshot(view):
    return tuple(
        sorted(
            (
                segment.start,
                segment.end,
                segment.data_offset,
                segment.data_length,
                segment.readable,
                segment.writable,
                segment.executable,
            )
            for segment in view.segments
        )
    )


def _section_snapshot(view):
    return tuple(
        sorted(
            (
                name,
                section.start,
                section.end,
                str(section.semantics),
            )
            for name, section in view.sections.items()
        )
    )


def _backed_byte_snapshot(view):
    return tuple(
        (
            segment.start,
            segment.data_length,
            bytes(view.read(segment.start, segment.data_length)),
        )
        for segment in sorted(view.segments, key=lambda item: item.start)
        if segment.data_length
    )


def _analysis_snapshot(view):
    functions = tuple(
        sorted(
            (
                function.start,
                function.name,
                str(function.type),
                bool(function.has_user_type),
            )
            for function in view.functions
        )
    )
    symbols = tuple(
        sorted(
            (
                symbol.address,
                str(symbol.type),
                symbol.raw_name,
            )
            for symbol in view.get_symbols()
        )
    )
    data_vars = tuple(
        sorted(
            (address, str(data_var.type))
            for address, data_var in view.data_vars.items()
        )
    )
    return (
        _segment_snapshot(view),
        _section_snapshot(view),
        _backed_byte_snapshot(view),
        functions,
        symbols,
        data_vars,
    )


class RefreshSafetyTests(unittest.TestCase):
    def _create_elf_view(self):
        raw = BinaryView.new(build_msp430_elf_firmware())
        view_type = BinaryViewType["ELF"]
        self.assertTrue(view_type.is_valid_for_data(raw))
        view = view_type.create(raw)
        self.assertIsNotNone(view)
        return raw, view

    def _create_mapped_raw_with_port1_vector(self):
        image = bytearray(build_sparse_raw_firmware())
        vector_offset = PORT1_VECTOR - memory_map.FLASH_START
        image[vector_offset:vector_offset + 2] = SPARSE_FUNCTION_ADDRESS.to_bytes(
            2,
            "little",
        )
        raw = BinaryView.new(bytes(image))
        view_type = BinaryViewType[memory_map.MSP430F5438BinaryView.name]
        self.assertTrue(view_type.is_valid_for_data(raw))
        view = view_type.create(raw)
        self.assertIsNotNone(view)
        return raw, view

    def test_apply_memory_map_does_not_rebuild_elf_layout(self):
        raw, view = self._create_elf_view()
        try:
            original_segments = _segment_snapshot(view)
            original_sections = _section_snapshot(view)
            original_bytes = _backed_byte_snapshot(view)

            memory_map.apply_msp430f5438_memory_map(view, verbose=False)

            self.assertEqual(_segment_snapshot(view), original_segments)
            self.assertEqual(_section_snapshot(view), original_sections)
            self.assertEqual(_backed_byte_snapshot(view), original_bytes)
        finally:
            raw.file.close()

    def test_mapped_refresh_preserves_user_state_and_is_idempotent(self):
        raw, view = self._create_mapped_raw_with_port1_vector()
        try:
            reset = view.get_function_at(RESET_HANDLER)
            port1 = view.get_function_at(SPARSE_FUNCTION_ADDRESS)
            self.assertIsNotNone(reset)
            self.assertIsNotNone(port1)

            calling_convention = view.arch.default_calling_convention
            reset_type = Type.function(
                Type.int(2, False),
                [FunctionParameter(Type.int(2, False), "boot_reason")],
                calling_convention=calling_convention,
            )
            port1_type = Type.function(
                Type.void(),
                [FunctionParameter(Type.int(2, False), "interrupt_state")],
                calling_convention=calling_convention,
            )
            reset.name = "firmware_entry"
            port1.name = "board_port1_handler"
            reset.set_user_type(reset_type)
            port1.set_user_type(port1_type)

            original_segments = _segment_snapshot(view)
            original_sections = _section_snapshot(view)
            original_bytes = _backed_byte_snapshot(view)

            # The initial-analysis callback normally dispatches a separate
            # background recovery task. Keep this regression deterministic:
            # the explicit refresh below already performs the same bounded
            # recovery synchronously.
            with mock.patch.object(
                memory_map,
                "_run_background_analysis_command",
                return_value=None,
            ):
                memory_map.apply_msp430f5438_memory_map(view, verbose=False)

                self.assertEqual(_segment_snapshot(view), original_segments)
                self.assertEqual(_section_snapshot(view), original_sections)
                self.assertEqual(_backed_byte_snapshot(view), original_bytes)

                refreshed_reset = view.get_function_at(RESET_HANDLER)
                refreshed_port1 = view.get_function_at(SPARSE_FUNCTION_ADDRESS)
                self.assertEqual(refreshed_reset.name, "firmware_entry")
                self.assertEqual(refreshed_port1.name, "board_port1_handler")
                self.assertTrue(refreshed_reset.has_user_type)
                self.assertTrue(refreshed_port1.has_user_type)
                self.assertEqual(str(refreshed_reset.type), str(reset_type))
                self.assertEqual(str(refreshed_port1.type), str(port1_type))

                first_refresh = _analysis_snapshot(view)
                memory_map.rerun_msp430x_analysis(view)
                second_refresh = _analysis_snapshot(view)

            self.assertEqual(second_refresh, first_refresh)
            self.assertEqual(
                view.get_function_at(RESET_HANDLER).name,
                "firmware_entry",
            )
            self.assertEqual(
                view.get_function_at(SPARSE_FUNCTION_ADDRESS).name,
                "board_port1_handler",
            )
        finally:
            raw.file.close()


if __name__ == "__main__":
    unittest.main()
