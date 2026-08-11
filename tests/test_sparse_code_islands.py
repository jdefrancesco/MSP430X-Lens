from types import SimpleNamespace
import unittest

import msp430f5438_memory_map as memory_map
from tests.fixture_firmware import CINIT_TABLE, PACKED_ISR_ROUTINES, SPARSE_FUNCTION


class MockView:
    def __init__(self, start, data):
        self._start = start
        self._data = data
        self.platform = object()
        self.functions = []
        self.data_vars = {}
        self.rejected_function_starts = set()
        self.segments = [
            SimpleNamespace(
                start=start,
                end=start + len(data),
                data_length=len(data),
                executable=True,
            )
        ]

    def read(self, addr, length):
        offset = addr - self._start
        if offset < 0 or offset >= len(self._data):
            return b""
        return self._data[offset:offset + length]

    def add_function(self, addr):
        if addr in self.rejected_function_starts:
            return None
        function = SimpleNamespace(start=addr)
        self.functions.append(function)
        return function


class SparseCodeIslandTests(unittest.TestCase):
    def test_mapped_raw_executable_chunk_is_seeded(self):
        view = MockView(0x60B00, SPARSE_FUNCTION)

        created = memory_map._seed_sparse_code_island_functions(view)

        self.assertEqual(created, 1)
        self.assertEqual([function.start for function in view.functions], [0x60B00])

    def test_sparse_elf_style_segment_is_seeded(self):
        segment_start = 0x60AE0
        data = b"\xff" * 0x20 + SPARSE_FUNCTION + b"\xff" * 0x40
        view = MockView(segment_start, data)

        created = memory_map._seed_sparse_code_island_functions(view)

        self.assertEqual(created, 1)
        self.assertEqual([function.start for function in view.functions], [0x60B00])

    def test_prologue_shaped_data_without_return_is_not_seeded(self):
        view = MockView(0x60B00, SPARSE_FUNCTION[:-2])

        created = memory_map._seed_sparse_code_island_functions(view)

        self.assertEqual(created, 0)
        self.assertEqual(view.functions, [])

    def test_adjacent_reti_handlers_are_all_seeded(self):
        start = 0xD1BA
        data = b"".join(PACKED_ISR_ROUTINES)
        view = MockView(start, data)

        created = memory_map._seed_sparse_code_island_functions(view)

        expected = [
            start,
            start + len(PACKED_ISR_ROUTINES[0]),
            start + len(PACKED_ISR_ROUTINES[0]) + len(PACKED_ISR_ROUTINES[1]),
        ]
        self.assertEqual(created, 3)
        self.assertEqual([function.start for function in view.functions], expected)

    def test_known_first_handler_seeds_rest_and_second_run_is_idempotent(self):
        start = 0xD1BA
        view = MockView(start, b"".join(PACKED_ISR_ROUTINES))
        view.functions.append(SimpleNamespace(start=start))

        created = memory_map._seed_sparse_code_island_functions(view)

        expected = [
            start,
            start + len(PACKED_ISR_ROUTINES[0]),
            start + len(PACKED_ISR_ROUTINES[0]) + len(PACKED_ISR_ROUTINES[1]),
        ]
        self.assertEqual(created, 2)
        self.assertEqual(sorted(function.start for function in view.functions), expected)
        self.assertEqual(memory_map._seed_sparse_code_island_functions(view), 0)
        self.assertEqual(sorted(function.start for function in view.functions), expected)

    def test_known_data_stops_reti_chain_discovery(self):
        start = 0xD1BA
        data = b"".join(PACKED_ISR_ROUTINES[:2])
        view = MockView(start, data)
        second_start = start + len(PACKED_ISR_ROUTINES[0])
        view.data_vars[second_start] = object()

        created = memory_map._seed_sparse_code_island_functions(view)

        self.assertEqual(created, 1)
        self.assertEqual([function.start for function in view.functions], [start])

    def test_padding_is_not_used_as_a_weak_isr_entry(self):
        start = 0xD1BA
        data = PACKED_ISR_ROUTINES[0] + bytes.fromhex("03 43") + PACKED_ISR_ROUTINES[1]
        view = MockView(start, data)

        created = memory_map._seed_sparse_code_island_functions(view)

        self.assertEqual(created, 1)
        self.assertEqual([function.start for function in view.functions], [start])

    def test_rejected_function_is_not_counted_or_used_as_an_anchor(self):
        start = 0xD1BA
        view = MockView(start, b"".join(PACKED_ISR_ROUTINES))
        second_start = start + len(PACKED_ISR_ROUTINES[0])
        view.rejected_function_starts.add(second_start)

        created = memory_map._seed_sparse_code_island_functions(view)

        self.assertEqual(created, 1)
        self.assertEqual([function.start for function in view.functions], [start])

    def test_cinit_payloads_that_look_like_functions_remain_data(self):
        start = memory_map.FLASH_START
        handlers = b"".join(PACKED_ISR_ROUTINES)
        view = MockView(start, handlers + CINIT_TABLE)
        cinit_start = start + len(handlers)

        created = memory_map._seed_sparse_code_island_functions(view)

        expected_functions = [
            start,
            start + len(PACKED_ISR_ROUTINES[0]),
            start + len(PACKED_ISR_ROUTINES[0]) + len(PACKED_ISR_ROUTINES[1]),
        ]
        self.assertEqual(created, 3)
        self.assertEqual([function.start for function in view.functions], expected_functions)
        self.assertEqual(
            memory_map._cinit_table_spans(handlers + CINIT_TABLE, start),
            ((cinit_start, cinit_start + len(CINIT_TABLE)),),
        )
        actual_functions = {function.start for function in view.functions}
        for payload_offset in (0x06, 0x14, 0x20, 0x30):
            self.assertNotIn(cinit_start + payload_offset, actual_functions)

    def test_code_after_cinit_starts_a_new_clean_partition(self):
        start = memory_map.FLASH_START
        handler_start = start + len(CINIT_TABLE)
        view = MockView(start, CINIT_TABLE + b"".join(PACKED_ISR_ROUTINES))

        created = memory_map._seed_sparse_code_island_functions(view)

        expected = [
            handler_start,
            handler_start + len(PACKED_ISR_ROUTINES[0]),
            handler_start + len(PACKED_ISR_ROUTINES[0]) + len(PACKED_ISR_ROUTINES[1]),
        ]
        self.assertEqual(created, 3)
        self.assertEqual([function.start for function in view.functions], expected)

    def test_weak_ordinary_leaf_after_return_is_not_inferred(self):
        start = 0x6000
        prologue_function = bytes.fromhex("04 12 03 43 34 41 30 41")
        leaf_function = bytes.fromhex("0f 4c 0f 5d 30 41")
        view = MockView(start, prologue_function + leaf_function)

        created = memory_map._seed_sparse_code_island_functions(view)

        self.assertEqual(created, 1)
        self.assertEqual([function.start for function in view.functions], [start])

    def test_cfg_validator_accepts_multiple_return_paths(self):
        data = bytes.fromhex("04 12 02 24 34 41 30 41 34 41 30 41")

        shape = memory_map._decode_msp430_routine(data, 0x6000)

        self.assertIsNotNone(shape)
        self.assertEqual(shape.length, len(data))
        self.assertEqual(shape.termination_kind, "ret")
        self.assertEqual(shape.instruction_count, 6)

    def test_cfg_validator_rejects_unreachable_reti_after_indirect_pc_write(self):
        data = bytes.fromhex("04 12 00 44 03 43 00 13")
        decoder, branch_edges = memory_map._msp430x_decode_api()
        pc_write = decoder(data[2:], 0x6002)

        self.assertEqual(branch_edges(pc_write, 0x6002), (("indirect", None),))
        self.assertIsNone(memory_map._decode_msp430_routine(data, 0x6000))

    def test_cfg_validator_rejects_branch_into_immediate_word(self):
        data = bytes.fromhex("04 12 01 20 3c 40 00 13 34 41 30 41")

        self.assertIsNone(memory_map._decode_msp430_routine(data, 0x6000))

    def test_cfg_validator_rejects_cpux_fallback_before_fake_reti(self):
        data = bytes.fromhex("04 12 00 18 70 00 00 13")

        self.assertIsNone(memory_map._decode_msp430_routine(data, 0x6000))

    def test_far_pc_branch_ends_routine_and_seeds_strong_target(self):
        data = bytes.fromhex("04 12 30 40 06 60 05 12 03 43 35 41 30 41")
        decoder, branch_edges = memory_map._msp430x_decode_api()
        tail_branch = decoder(data[2:], 0x6002)

        self.assertEqual(
            branch_edges(tail_branch, 0x6002),
            (("unconditional_pc", 0x6006),),
        )
        shape = memory_map._decode_msp430_routine(data, 0x6000)
        self.assertIsNotNone(shape)
        self.assertEqual(shape.length, 6)
        self.assertEqual(shape.termination_kind, "tail")

        view = MockView(0x6000, data)
        self.assertEqual(memory_map._seed_sparse_code_island_functions(view), 2)
        self.assertEqual(
            [function.start for function in view.functions],
            [0x6000, 0x6006],
        )

    def test_tail_exit_to_unbacked_target_is_not_a_sparse_function_shape(self):
        data = bytes.fromhex("04 12 30 40 00 1c")

        self.assertIsNone(memory_map._decode_msp430_routine(data, 0x6000))


if __name__ == "__main__":
    unittest.main()
