import unittest
from unittest import mock

from binaryninja import BinaryView, BinaryViewType, LowLevelILOperation

import msp430f5438_memory_map as memory_map
import msp430x_arch as architecture
from tests.fixture_firmware import (
    HIGH_BANK_BACKED_ERASED_ADDRESS,
    HIGH_BANK_CALLA,
    HIGH_BANK_CALLA_ADDRESS,
    HIGH_BANK_FUNCTION,
    HIGH_BANK_FUNCTION_ADDRESS,
    HIGH_BANK_INDIRECT_CALLA,
    HIGH_BANK_INDIRECT_CALLA_ADDRESS,
    HIGH_BANK_INDIRECT_CALLA_POINTER,
    HIGH_BANK_INDIRECT_CALLA_POINTER_ADDRESS,
    HIGH_BANK_INDIRECT_CALLA_TARGET,
    HIGH_BANK_INDIRECT_CALLA_TARGET_ADDRESS,
    HIGH_BANK_INDIRECT_CALLA_WRAPPER,
    HIGH_BANK_INDIRECT_CALLA_WRAPPER_ADDRESS,
    HIGH_BANK_LOOKUP_TABLE,
    HIGH_BANK_LOOKUP_TABLE_ADDRESS,
    HIGH_BANK_PROLOGUE_DATA,
    HIGH_BANK_PROLOGUE_DATA_ADDRESS,
    HIGH_BANK_STRING,
    HIGH_BANK_STRING_ADDRESS,
    HIGH_BANK_UNBACKED_ADDRESS,
    RESET_HANDLER,
    build_high_bank_raw_firmware,
)


class HighBankRawTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = BinaryView.new(build_high_bank_raw_firmware())
        view_type = BinaryViewType[memory_map.MSP430F5438BinaryView.name]
        if not view_type.is_valid_for_data(cls.raw):
            cls.raw.file.close()
            raise AssertionError("high-bank fixture was not accepted by the raw loader")
        with mock.patch.object(
            memory_map,
            "_run_background_analysis_command",
            return_value=None,
        ):
            cls.view = view_type.create(cls.raw)
            if cls.view is None:
                cls.raw.file.close()
                raise AssertionError("raw loader did not create the high-bank view")
            cls.view.update_analysis_and_wait()
            cls.address_word_recovery = (
                memory_map._seed_referenced_address_word_targets(
                    cls.view,
                    verbose=False,
                )
            )
            cls.view.update_analysis_and_wait()

    @classmethod
    def tearDownClass(cls):
        cls.raw.file.close()

    def test_address_word_recovery_is_idempotent(self):
        target = HIGH_BANK_INDIRECT_CALLA_TARGET_ADDRESS
        functions_before = tuple(self.view.get_functions_at(target))
        data_var_before = self.view.get_data_var_at(
            HIGH_BANK_INDIRECT_CALLA_POINTER_ADDRESS
        )

        recovered_again = memory_map._seed_referenced_address_word_targets(
            self.view,
            verbose=False,
        )

        self.assertEqual(recovered_again, (0, 1, 0))
        self.assertEqual(tuple(self.view.get_functions_at(target)), functions_before)
        self.assertIsNotNone(data_var_before)
        self.assertIsNotNone(
            self.view.get_data_var_at(HIGH_BANK_INDIRECT_CALLA_POINTER_ADDRESS)
        )
        wrapper = self.view.get_function_at(
            HIGH_BANK_INDIRECT_CALLA_WRAPPER_ADDRESS
        )
        target_edges = [
            branch.dest_addr
            for branch in wrapper.get_indirect_branches_at(
                HIGH_BANK_INDIRECT_CALLA_ADDRESS
            )
            if branch.dest_addr == target
        ]
        self.assertEqual(target_edges, [target])

    def test_direct_calla_seeds_the_full_twenty_bit_target(self):
        self.assertEqual(
            bytes(self.view.read(HIGH_BANK_FUNCTION_ADDRESS, len(HIGH_BANK_FUNCTION))),
            HIGH_BANK_FUNCTION,
        )
        segment = self.view.get_segment_at(HIGH_BANK_FUNCTION_ADDRESS)
        self.assertIsNotNone(segment)
        self.assertTrue(segment.executable)
        self.assertGreater(segment.data_length, 0)

        caller = self.view.get_function_at(RESET_HANDLER)
        callee = self.view.get_function_at(HIGH_BANK_FUNCTION_ADDRESS)
        self.assertIsNotNone(caller)
        self.assertIsNotNone(callee)
        self.assertIsNone(self.view.get_function_at(HIGH_BANK_FUNCTION_ADDRESS & 0xFFFF))

        call_bytes = bytes(
            self.view.read(HIGH_BANK_CALLA_ADDRESS, len(HIGH_BANK_CALLA))
        )
        self.assertEqual(call_bytes, HIGH_BANK_CALLA)
        decoded = architecture.decode(call_bytes, HIGH_BANK_CALLA_ADDRESS)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.mnemonic, "calla")
        self.assertEqual(decoded.src.value, HIGH_BANK_FUNCTION_ADDRESS)

        call_il = caller.get_low_level_il_at(HIGH_BANK_CALLA_ADDRESS)
        self.assertIsNotNone(call_il)
        self.assertEqual(
            call_il.operation,
            LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
        )
        references = tuple(self.view.get_code_refs(HIGH_BANK_FUNCTION_ADDRESS))
        self.assertIn(HIGH_BANK_CALLA_ADDRESS, {reference.address for reference in references})

    def test_indirect_calla_seeds_full_twenty_bit_target_and_keeps_fallthrough(self):
        self.assertEqual(self.address_word_recovery, (1, 1, 1))
        self.assertEqual(
            bytes(
                self.view.read(
                    HIGH_BANK_INDIRECT_CALLA_WRAPPER_ADDRESS,
                    len(HIGH_BANK_INDIRECT_CALLA_WRAPPER),
                )
            ),
            HIGH_BANK_INDIRECT_CALLA_WRAPPER,
        )
        call_bytes = bytes(
            self.view.read(
                HIGH_BANK_INDIRECT_CALLA_ADDRESS,
                len(HIGH_BANK_INDIRECT_CALLA),
            )
        )
        self.assertEqual(call_bytes, HIGH_BANK_INDIRECT_CALLA)
        decoded = architecture.decode(
            call_bytes,
            HIGH_BANK_INDIRECT_CALLA_ADDRESS,
        )
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.mnemonic, "calla")
        self.assertEqual(decoded.src.kind, "mem")
        self.assertEqual(
            decoded.src.addr,
            HIGH_BANK_INDIRECT_CALLA_POINTER_ADDRESS,
        )
        self.assertEqual(
            architecture.decoded_branch_edges(
                decoded,
                HIGH_BANK_INDIRECT_CALLA_ADDRESS,
            ),
            (("call", None),),
        )

        pointer = bytes(
            self.view.read(
                HIGH_BANK_INDIRECT_CALLA_POINTER_ADDRESS,
                len(HIGH_BANK_INDIRECT_CALLA_POINTER),
            )
        )
        self.assertEqual(pointer, HIGH_BANK_INDIRECT_CALLA_POINTER)
        self.assertTrue(
            all(
                memory_map._is_file_backed_byte(self.view, address)
                for address in range(
                    HIGH_BANK_INDIRECT_CALLA_POINTER_ADDRESS,
                    HIGH_BANK_INDIRECT_CALLA_POINTER_ADDRESS + len(pointer),
                )
            )
        )
        target = int.from_bytes(pointer[:2], "little") | (
            (int.from_bytes(pointer[2:], "little") & 0xF) << 16
        )
        self.assertEqual(target, HIGH_BANK_INDIRECT_CALLA_TARGET_ADDRESS)
        self.assertGreater(target, 0xFFFF)
        self.assertEqual(
            bytes(
                self.view.read(
                    target,
                    len(HIGH_BANK_INDIRECT_CALLA_TARGET),
                )
            ),
            HIGH_BANK_INDIRECT_CALLA_TARGET,
        )

        wrapper = self.view.get_function_at(
            HIGH_BANK_INDIRECT_CALLA_WRAPPER_ADDRESS
        )
        self.assertIsNotNone(wrapper)
        call_ils = wrapper.get_low_level_ils_at(
            HIGH_BANK_INDIRECT_CALLA_ADDRESS
        )
        ret_il = wrapper.get_low_level_il_at(
            HIGH_BANK_INDIRECT_CALLA_ADDRESS + len(HIGH_BANK_INDIRECT_CALLA)
        )
        self.assertIn(
            LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
            {instruction.operation for instruction in call_ils},
        )
        self.assertIsNotNone(ret_il)
        self.assertEqual(ret_il.operation, LowLevelILOperation.LLIL_RET)
        self.assertTrue(wrapper.can_return.value)

        self.assertIsNotNone(self.view.get_function_at(target))
        self.assertIsNone(self.view.get_function_at(target & 0xFFFF))
        indirect_targets = {
            branch.dest_addr
            for branch in wrapper.get_indirect_branches_at(
                HIGH_BANK_INDIRECT_CALLA_ADDRESS
            )
        }
        self.assertIn(target, indirect_targets)

    def test_erased_and_unbacked_high_bank_ranges_are_not_executable(self):
        erased = self.view.get_segment_at(HIGH_BANK_BACKED_ERASED_ADDRESS)
        self.assertIsNotNone(erased)
        self.assertFalse(erased.executable)
        self.assertGreater(erased.data_length, 0)
        self.assertEqual(
            bytes(self.view.read(HIGH_BANK_BACKED_ERASED_ADDRESS, 32)),
            b"\xff" * 32,
        )

        unbacked = self.view.get_segment_at(HIGH_BANK_UNBACKED_ADDRESS)
        self.assertIsNotNone(unbacked)
        self.assertFalse(unbacked.executable)
        self.assertEqual(unbacked.data_length, 0)

    def test_high_bank_string_and_lookup_table_remain_data(self):
        self.assertEqual(
            bytes(self.view.read(HIGH_BANK_STRING_ADDRESS, len(HIGH_BANK_STRING))),
            HIGH_BANK_STRING,
        )
        self.assertEqual(
            bytes(
                self.view.read(
                    HIGH_BANK_LOOKUP_TABLE_ADDRESS,
                    len(HIGH_BANK_LOOKUP_TABLE),
                )
            ),
            HIGH_BANK_LOOKUP_TABLE,
        )
        self.assertIsNotNone(self.view.get_data_var_at(HIGH_BANK_STRING_ADDRESS))
        self.assertIsNotNone(
            self.view.get_data_var_at(HIGH_BANK_LOOKUP_TABLE_ADDRESS)
        )

        data_ranges = (
            (
                HIGH_BANK_STRING_ADDRESS,
                HIGH_BANK_STRING_ADDRESS + len(HIGH_BANK_STRING),
            ),
            (
                HIGH_BANK_LOOKUP_TABLE_ADDRESS,
                HIGH_BANK_LOOKUP_TABLE_ADDRESS + len(HIGH_BANK_LOOKUP_TABLE),
            ),
        )
        function_starts = {function.start for function in self.view.functions}
        for start, end in data_ranges:
            self.assertFalse(any(start <= address < end for address in function_starts))

    def test_unreferenced_high_bank_prologue_shaped_data_is_not_a_function(self):
        self.assertEqual(
            bytes(
                self.view.read(
                    HIGH_BANK_PROLOGUE_DATA_ADDRESS,
                    len(HIGH_BANK_PROLOGUE_DATA),
                )
            ),
            HIGH_BANK_PROLOGUE_DATA,
        )
        self.assertTrue(
            memory_map._looks_like_msp430_function_entry(HIGH_BANK_PROLOGUE_DATA)
        )
        routine = memory_map._decode_msp430_routine(
            HIGH_BANK_PROLOGUE_DATA,
            HIGH_BANK_PROLOGUE_DATA_ADDRESS,
        )
        self.assertIsNotNone(routine)
        self.assertEqual(routine.length, len(HIGH_BANK_PROLOGUE_DATA))
        self.assertEqual(routine.termination_kind, "ret")

        segment = self.view.get_segment_at(HIGH_BANK_PROLOGUE_DATA_ADDRESS)
        self.assertIsNotNone(segment)
        self.assertGreater(segment.data_length, 0)
        self.assertEqual(
            tuple(self.view.get_code_refs(HIGH_BANK_PROLOGUE_DATA_ADDRESS)),
            (),
        )
        self.assertIsNone(
            self.view.get_function_at(HIGH_BANK_PROLOGUE_DATA_ADDRESS)
        )


if __name__ == "__main__":
    unittest.main()
