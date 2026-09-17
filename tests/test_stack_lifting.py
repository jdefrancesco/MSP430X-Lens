import unittest
from unittest import mock

from binaryninja import Architecture, BinaryView, LowLevelILOperation

import msp430f5438_memory_map as memory_map
import msp430x_arch  # noqa: F401


FUNCTION_ADDRESS = 0x100

# push r9; push r10; nop; pop r10; pop r9; ret
CALLEE_SAVE_BYTES = bytes.fromhex(
    "09 12 "
    "0a 12 "
    "03 43 "
    "3a 41 "
    "39 41 "
    "30 41"
)

# push r9; mov r9,r12; pop r9; ret
SEMANTIC_R9_BYTES = bytes.fromhex("09 12 0c 49 39 41 30 41")

# push r9; bit #1,r4; subc r9,r9; xor #-1,r9; addc r9,r9; pop r9;
# ret. Carry is dynamic, but the old R9 value still cancels in SUBC.
SELF_SUBC_SAVE_BYTES = bytes.fromhex(
    "09 12 14 b3 09 79 39 e3 09 69 39 41 30 41"
)


class StackLiftingTests(unittest.TestCase):
    def setUp(self):
        self.arch = Architecture["msp430x"]

    def test_classic_push_pop_pair_does_not_invent_r9_r10_parameters(self):
        backing = bytearray(b"\xff" * 0x200)
        end = FUNCTION_ADDRESS + len(CALLEE_SAVE_BYTES)
        backing[FUNCTION_ADDRESS:end] = CALLEE_SAVE_BYTES
        view = BinaryView.new(bytes(backing))
        view.platform = self.arch.standalone_platform
        try:
            self.assertIsNotNone(view.add_function(FUNCTION_ADDRESS))
            view.update_analysis_and_wait()

            function = view.get_function_at(FUNCTION_ADDRESS)
            self.assertEqual(
                memory_map._register_parameter_names(function),
                {"r9", "r10"},
            )
            self.assertEqual(
                memory_map._remove_false_callee_saved_parameters(view),
                2,
            )
            view.update_analysis_and_wait()

            function = view.get_function_at(FUNCTION_ADDRESS)
            self.assertEqual(tuple(function.type.parameters), ())
            self.assertEqual(
                memory_map._remove_false_callee_saved_parameters(view),
                0,
            )
            operations = [
                expression.operation
                for instruction in function.low_level_il.instructions
                for expression in instruction.traverse(lambda item: item)
            ]
            self.assertEqual(
                operations.count(LowLevelILOperation.LLIL_PUSH),
                2,
            )
            # Two register restores plus the return-address pop inside RET.
            self.assertEqual(
                operations.count(LowLevelILOperation.LLIL_POP),
                3,
            )
        finally:
            view.file.close()

    def test_classic_register_pop_uses_alias_text(self):
        tokens, length = self.arch.get_instruction_text(
            bytes.fromhex("39 41"),
            FUNCTION_ADDRESS,
        )

        self.assertEqual(length, 2)
        self.assertEqual("".join(token.text for token in tokens), "pop r9")

    def test_semantically_used_r9_remains_a_parameter(self):
        backing = bytearray(b"\xff" * 0x200)
        end = FUNCTION_ADDRESS + len(SEMANTIC_R9_BYTES)
        backing[FUNCTION_ADDRESS:end] = SEMANTIC_R9_BYTES
        view = BinaryView.new(bytes(backing))
        view.platform = self.arch.standalone_platform
        try:
            self.assertIsNotNone(view.add_function(FUNCTION_ADDRESS))
            view.update_analysis_and_wait()

            function = view.get_function_at(FUNCTION_ADDRESS)
            self.assertEqual(
                memory_map._register_parameter_names(function),
                {"r9"},
            )
            self.assertEqual(
                memory_map._remove_false_callee_saved_parameters(view),
                0,
            )
            self.assertEqual(
                memory_map._register_parameter_names(function),
                {"r9"},
            )
        finally:
            view.file.close()

    def test_self_subc_does_not_keep_a_false_r9_parameter(self):
        backing = bytearray(b"\xff" * 0x200)
        end = FUNCTION_ADDRESS + len(SELF_SUBC_SAVE_BYTES)
        backing[FUNCTION_ADDRESS:end] = SELF_SUBC_SAVE_BYTES
        view = BinaryView.new(bytes(backing))
        view.platform = self.arch.standalone_platform
        try:
            self.assertIsNotNone(view.add_function(FUNCTION_ADDRESS))
            view.update_analysis_and_wait()

            function = view.get_function_at(FUNCTION_ADDRESS)
            self.assertEqual(
                memory_map._register_parameter_names(function),
                {"r9"},
            )
            self.assertEqual(
                memory_map._remove_false_callee_saved_parameters(view),
                1,
            )
            view.update_analysis_and_wait()
            self.assertEqual(
                memory_map._register_parameter_names(function),
                set(),
            )
        finally:
            view.file.close()

    def test_user_function_type_is_never_cleaned(self):
        backing = bytearray(b"\xff" * 0x200)
        end = FUNCTION_ADDRESS + len(CALLEE_SAVE_BYTES)
        backing[FUNCTION_ADDRESS:end] = CALLEE_SAVE_BYTES
        view = BinaryView.new(bytes(backing))
        view.platform = self.arch.standalone_platform
        try:
            self.assertIsNotNone(view.add_function(FUNCTION_ADDRESS))
            view.update_analysis_and_wait()

            function = view.get_function_at(FUNCTION_ADDRESS)
            function.set_user_type(function.type)
            view.update_analysis_and_wait()
            self.assertTrue(function.has_user_type)
            self.assertEqual(
                memory_map._remove_false_callee_saved_parameters(view),
                0,
            )
            self.assertEqual(
                memory_map._register_parameter_names(function),
                {"r9", "r10"},
            )
        finally:
            view.file.close()

    def test_signature_cleanup_runs_to_a_bounded_fixed_point(self):
        view = object()
        with mock.patch.object(
            memory_map,
            "_remove_false_callee_saved_parameters",
            side_effect=(2, 1, 0),
        ) as cleanup, mock.patch.object(
            memory_map,
            "_update_analysis",
        ) as update:
            passes = memory_map._stabilize_false_callee_saved_parameters(view)

        self.assertEqual(passes, (2, 1, 0))
        self.assertEqual(cleanup.call_count, 3)
        self.assertEqual(update.call_count, 2)

    def test_signature_cleanup_stops_at_its_analysis_pass_limit(self):
        view = object()
        with mock.patch.object(
            memory_map,
            "_remove_false_callee_saved_parameters",
            return_value=1,
        ) as cleanup, mock.patch.object(
            memory_map,
            "_update_analysis",
        ) as update, mock.patch.object(memory_map, "log_warn") as warn:
            passes = memory_map._stabilize_false_callee_saved_parameters(
                view,
                max_passes=3,
            )

        self.assertEqual(passes, (1, 1, 1))
        self.assertEqual(cleanup.call_count, 3)
        self.assertEqual(update.call_count, 3)
        warn.assert_called_once()


if __name__ == "__main__":
    unittest.main()
