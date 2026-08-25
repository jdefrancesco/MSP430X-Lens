from types import SimpleNamespace
import unittest

import msp430f5438_memory_map as memory_map
from tests.fixture_firmware import CINIT_TABLE, PACKED_ISR_ROUTINES, SPARSE_FUNCTION


# Exact routines from ``aegisnode_f5438a_v2714.bin`` at 0x10000, 0x10060,
# and 0x100c0.  Each routine is followed by erased flash in the source image.
# Keeping the bytes here makes the regression independent of the external demo
# pack while preserving the compiler shapes that recursive analysis missed.
AEGIS_HIGH_BANK_RETA_ROUTINE_STARTS = (0x10000, 0x10060, 0x100C0)
AEGIS_HIGH_BANK_RETA_ROUTINES = (
    bytes.fromhex(
        "04 12 05 12 06 12 07 12 08 12 88 03 00 60 80 19 "
        "59 42 00 60 b1 13 60 00 b1 13 80 04 b1 13 40 05 "
        "38 41 37 41 36 41 35 41 34 41 10 01"
    ),
    bytes.fromhex(
        "04 12 05 12 06 12 34 40 4e a4 15 42 36 2f 36 40 "
        "04 00 04 55 34 e0 53 27 84 10 15 53 16 83 f9 23 "
        "8a 03 4e c0 80 19 5b 42 4e c0 b0 12 c0 a6 82 44 "
        "36 2f 36 41 35 41 34 41 10 01"
    ),
    bytes.fromhex(
        "04 12 05 12 06 12 34 40 b3 58 15 42 32 40 36 40 "
        "04 00 04 55 34 e0 25 23 04 54 15 53 16 83 f9 23 "
        "8a 04 b2 00 00 1a 5b 42 b2 00 b1 13 40 05 82 44 "
        "32 40 36 41 35 41 34 41 10 01"
    ),
)

# Exact calibration records at 0x3a880 in the same image.  The bytes beginning
# at 0x3a8bc happen to decode as a compiler-entry-shaped, RETI-terminated
# routine by crossing the boundary between records 0x22 and 0x23.  It is still
# random-looking table data and therefore provides only review evidence.
AEGIS_CALIBRATION_WINDOW_ADDRESS = 0x3A880
AEGIS_CALIBRATION_WINDOW_BYTES = bytes.fromhex(
    "22 00 30 fe 6b 7f 80 00 4d 5c 97 12 80 29 9f 0b "
    "ae a9 4d 77 70 62 b0 fe 56 9f d1 c8 7b 45 21 8a "
    "f3 f3 0e 8e ef 38 de e1 97 c5 78 2a da ee 06 11 "
    "5c cd 76 dc c9 e1 c9 3b 7b fa b7 ab 5c 15 65 01 "
    "23 00 84 fe d8 79 49 00 7d 1b 64 13 f9 b7 39 86 "
    "37 93 5d a9 31 94 2e a4 a2 25 e9 bb cb 71 72 0c "
    "51 76 2d 69 8a b2 a9 91 e1 4f 65 16 ea 94 2b c5 "
    "7f b2 dd 90 ff 2c 6b 46 fe 72 26 f9 0c 15 71 af"
)
AEGIS_CALIBRATION_RETI_ADDRESS = 0x3A8BC
AEGIS_CALIBRATION_RETI_BYTES = bytes.fromhex(
    "5c 15 65 01 23 00 84 fe d8 79 49 00 7d 1b"
)

HIGH_BANK_LEGACY_RET_ADDRESS = 0x11400
HIGH_BANK_LEGACY_RET_BYTES = bytes.fromhex("04 12 03 43 34 41 30 41")


def _erased_spaced_view(starts, routines, *, trailing_erased=0x20):
    start = min(starts)
    end = max(
        address + len(routine)
        for address, routine in zip(starts, routines)
    ) + trailing_erased
    data = bytearray(b"\xff" * (end - start))
    for address, routine in zip(starts, routines):
        offset = address - start
        data[offset : offset + len(routine)] = routine
    view = MockView(start, bytes(data))
    view.spec = memory_map.DEFAULT_DEVICE_SPEC
    return view


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
    def test_strong_aegis_high_bank_reta_cluster_is_seeded_idempotently(self):
        view = _erased_spaced_view(
            AEGIS_HIGH_BANK_RETA_ROUTINE_STARTS,
            AEGIS_HIGH_BANK_RETA_ROUTINES,
        )

        candidates = memory_map._raw_orphan_function_candidates(
            view,
            spec=memory_map.DEFAULT_DEVICE_SPEC,
        )
        self.assertEqual(
            [candidate.address for candidate in candidates],
            list(AEGIS_HIGH_BANK_RETA_ROUTINE_STARTS),
        )
        self.assertTrue(
            all(candidate.confidence == "strong" for candidate in candidates)
        )

        created = memory_map._seed_strong_raw_orphan_function_clusters(view)

        self.assertEqual(created, len(AEGIS_HIGH_BANK_RETA_ROUTINES))
        self.assertEqual(
            sorted(function.start for function in view.functions),
            list(AEGIS_HIGH_BANK_RETA_ROUTINE_STARTS),
        )
        self.assertEqual(
            memory_map._seed_strong_raw_orphan_function_clusters(view),
            0,
        )
        self.assertEqual(
            sorted(function.start for function in view.functions),
            list(AEGIS_HIGH_BANK_RETA_ROUTINE_STARTS),
        )

    def test_single_strong_high_bank_reta_remains_review_only(self):
        view = _erased_spaced_view(
            (AEGIS_HIGH_BANK_RETA_ROUTINE_STARTS[0],),
            (AEGIS_HIGH_BANK_RETA_ROUTINES[0],),
        )

        candidates = memory_map._raw_orphan_function_candidates(
            view,
            spec=memory_map.DEFAULT_DEVICE_SPEC,
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].confidence, "strong")

        self.assertEqual(
            memory_map._seed_strong_raw_orphan_function_clusters(view),
            0,
        )
        self.assertEqual(view.functions, [])

    def test_random_calibration_reti_is_review_only_and_not_auto_seeded(self):
        offset = AEGIS_CALIBRATION_RETI_ADDRESS - AEGIS_CALIBRATION_WINDOW_ADDRESS
        self.assertEqual(
            AEGIS_CALIBRATION_WINDOW_BYTES[
                offset : offset + len(AEGIS_CALIBRATION_RETI_BYTES)
            ],
            AEGIS_CALIBRATION_RETI_BYTES,
        )
        shape = memory_map._decode_msp430_routine(
            AEGIS_CALIBRATION_WINDOW_BYTES[offset:],
            AEGIS_CALIBRATION_RETI_ADDRESS,
        )
        self.assertIsNotNone(shape)
        self.assertEqual(shape.length, len(AEGIS_CALIBRATION_RETI_BYTES))
        self.assertEqual(shape.termination_kind, "reti")
        confidence, reasons = memory_map._raw_orphan_candidate_confidence(
            AEGIS_CALIBRATION_RETI_ADDRESS,
            shape,
            memory_map.DEFAULT_DEVICE_SPEC,
            boundary_evidence=False,
        )
        self.assertEqual(confidence, "review")
        self.assertIn("exit-reti", reasons)

        view = _erased_spaced_view(
            (AEGIS_CALIBRATION_WINDOW_ADDRESS,),
            (AEGIS_CALIBRATION_WINDOW_BYTES,),
        )
        self.assertEqual(
            memory_map._seed_strong_raw_orphan_function_clusters(view),
            0,
        )
        self.assertEqual(view.functions, [])

    def test_high_bank_legacy_ret_is_ambiguous_and_not_auto_seeded(self):
        view = _erased_spaced_view(
            (HIGH_BANK_LEGACY_RET_ADDRESS,),
            (HIGH_BANK_LEGACY_RET_BYTES,),
        )
        candidates = memory_map._raw_orphan_function_candidates(
            view,
            spec=memory_map.DEFAULT_DEVICE_SPEC,
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].address, HIGH_BANK_LEGACY_RET_ADDRESS)
        self.assertEqual(candidates[0].confidence, "ambiguous")
        self.assertEqual(candidates[0].termination_kind, "ret")

        self.assertEqual(
            memory_map._seed_strong_raw_orphan_function_clusters(view),
            0,
        )
        self.assertEqual(view.functions, [])

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
