import unittest

from binaryninja import Architecture, BinaryView, LowLevelILOperation

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
            self.assertEqual(tuple(function.type.parameters), ())
            operations = [
                expression.operation
                for instruction in function.low_level_il.instructions
                for expression in instruction.traverse(lambda item: item)
            ]
            self.assertEqual(
                operations.count(LowLevelILOperation.LLIL_PUSH),
                2,
            )
            self.assertEqual(
                operations.count(LowLevelILOperation.LLIL_POP),
                2,
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


if __name__ == "__main__":
    unittest.main()
