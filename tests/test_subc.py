import unittest

from binaryninja import Architecture, BinaryView
from binaryninja.enums import RegisterValueType
from binaryninja.lowlevelil import LowLevelILFunction

import msp430x_arch as architecture


class SubcTests(unittest.TestCase):
    def setUp(self):
        self.arch = Architecture["msp430x"]

    def _lift(self, data: bytes, addr: int = 0x6000):
        il = LowLevelILFunction(self.arch)
        length = self.arch.get_instruction_low_level_il(data, addr, il)
        il.finalize()
        self.assertEqual(length, len(data))
        return il

    @staticmethod
    def _nested_operations(il):
        for instruction_index, instruction in enumerate(il.instructions):
            for node in instruction.traverse(lambda item: item):
                yield instruction_index, node

    def _carry_reads(self, il):
        return [
            (instruction_index, str(node))
            for instruction_index, node in self._nested_operations(il)
            if node.operation.name == "LLIL_FLAG" and str(node) == "flag:c"
        ]

    @staticmethod
    def _flag_write(il, name: str):
        writes = [
            instruction
            for instruction in il.instructions
            if instruction.operation.name == "LLIL_SET_FLAG" and instruction.dest.name == name
        ]
        if len(writes) != 1:
            raise AssertionError(f"expected one write to {name}, got {len(writes)}")
        return writes[0]

    def _reg_value_after(self, data: bytes, addr: int, reg: str):
        view = BinaryView.new(data)
        try:
            view.platform = self.arch.standalone_platform
            function = view.add_function(0)
            self.assertIsNotNone(function)
            view.update_analysis_and_wait()
            function = view.get_function_at(0)
            self.assertIsNotNone(function)
            value = function.get_reg_value_after(addr, reg)
            self.assertEqual(value.type, RegisterValueType.ConstantValue)
            return value
        finally:
            view.file.close()

    def test_subc_widths_decode_render_and_lift(self):
        cases = (
            ("05 74", "subc r4, r5", 2),
            ("45 74", "subc.b r4, r5", 1),
            ("00 18 45 74", "subcx.a r4, r5", 4),
            ("40 18 05 74", "subcx.w r4, r5", 2),
            ("40 18 45 74", "subcx.b r4, r5", 1),
        )

        for encoded, expected_text, expected_size in cases:
            with self.subTest(encoded=encoded):
                data = bytes.fromhex(encoded)
                instruction = architecture.decode(data, 0x6000)
                self.assertIsNotNone(instruction)
                self.assertEqual(instruction.mnemonic, "subc")
                self.assertEqual(instruction.size, expected_size)

                tokens, length = self.arch.get_instruction_text(data, 0x6000)
                self.assertEqual(length, len(data))
                self.assertEqual("".join(token.text for token in tokens), expected_text)

                il = self._lift(data)
                operations = {node.operation.name for _, node in self._nested_operations(il)}
                self.assertNotIn("LLIL_UNIMPL", operations)
                self.assertEqual(
                    [
                        instruction.dest.name
                        for instruction in il.instructions
                        if instruction.operation.name == "LLIL_SET_FLAG"
                    ],
                    ["z", "n", "c", "v"],
                )

    def test_subc_snapshots_input_carry_before_writing_flags(self):
        il = self._lift(bytes.fromhex("05 74"))

        self.assertEqual(self._carry_reads(il), [(0, "flag:c")])
        self.assertEqual(il[0].operation.name, "LLIL_SET_REG")
        self.assertEqual(str(il[0].dest), "temp51")

    def test_subc_uses_full_precision_carry_and_original_source_for_overflow(self):
        cases = (
            ("76 73", "0xff", "0x80"),
            ("36 73", "0xffff", "0x8000"),
            ("00 18 45 74", "0xfffff", "0x80000"),
        )

        for encoded, mask, sign in cases:
            with self.subTest(encoded=encoded):
                il = self._lift(bytes.fromhex(encoded))
                carry = str(self._flag_write(il, "c").src)
                overflow = str(self._flag_write(il, "v").src)

                self.assertIn(f"u> {mask}", carry)
                self.assertIn("temp18", overflow)
                self.assertIn("temp19", overflow)
                self.assertIn("temp20", overflow)
                self.assertIn(sign, overflow)

    def test_subc_result_does_not_reuse_new_carry(self):
        # MOV #0,R4; CMP #1,R4 sets C=0. Then 1 - 0 - 1 must store zero.
        program = bytes.fromhex("04 43 14 93 15 43 04 43 05 74 30 41")

        value = self._reg_value_after(program, 0x8, "r5")

        self.assertEqual(value.value, 0)

    def test_subc_all_ones_source_keeps_modular_result(self):
        # With C=0, 0x1234 - 0xffff - 1 wraps back to 0x1234 and clears C.
        program = bytes.fromhex("04 43 14 93 35 40 34 12 34 40 ff ff 05 74 30 41")

        value = self._reg_value_after(program, 0xC, "r5")

        self.assertEqual(value.value, 0x1234)

    def test_subcx_address_underflow_is_canonicalized_to_twenty_bits(self):
        # MOV #0,R4; CMP #1,R4 establishes C=0 before 0 - 0 - 1.
        program = bytes.fromhex("04 43 14 93 05 43 00 18 45 74 30 41")

        value = self._reg_value_after(program, 0x6, "r5")

        self.assertEqual(value.value, 0xFFFFF)

    def test_subcx_zero_carry_is_visible_and_ignores_input_carry(self):
        data = bytes.fromhex("00 19 45 74")
        instruction = architecture.decode(data, 0x6000)
        self.assertIsNotNone(instruction)
        self.assertTrue(instruction.subc_zero_carry)

        tokens, _ = self.arch.get_instruction_text(data, 0x6000)
        self.assertEqual("".join(token.text for token in tokens), "rptz #1; subcx.a r4, r5")
        self.assertEqual(self._carry_reads(self._lift(data)), [])

        # Incoming C is unknown, but ZC forces 1 - 0 - 1 to the constant zero.
        program = bytes.fromhex("15 43 04 43 00 19 45 74 30 41")
        value = self._reg_value_after(program, 0x4, "r5")
        self.assertEqual(value.value, 0)

    def test_subcx_zero_carry_applies_to_every_repeat(self):
        data = bytes.fromhex("01 19 45 74")
        instruction = architecture.decode(data, 0x6000)
        self.assertIsNotNone(instruction)
        self.assertTrue(instruction.subc_zero_carry)
        self.assertEqual(instruction.rpt_count, 2)

        tokens, _ = self.arch.get_instruction_text(data, 0x6000)
        self.assertEqual("".join(token.text for token in tokens), "rptz #2; subcx.a r4, r5")
        il = self._lift(data)
        self.assertEqual(self._carry_reads(il), [])
        self.assertNotIn("rpt_subc", "\n".join(str(item) for item in il.instructions))

        # Each iteration uses C=0: 2 -> 1 -> 0. Chaining the first C-out would
        # incorrectly leave one after the second iteration.
        program = bytes.fromhex("25 43 04 43 01 19 45 74 30 41")
        value = self._reg_value_after(program, 0x4, "r5")
        self.assertEqual(value.value, 0)

    def test_subcx_repeat_survives_constant_generator_normalization(self):
        data = bytes.fromhex("01 19 45 73")
        instruction = architecture.decode(data, 0x6000)
        self.assertIsNotNone(instruction)
        self.assertTrue(instruction.subc_zero_carry)
        self.assertEqual(instruction.rpt_count, 2)

        tokens, _ = self.arch.get_instruction_text(data, 0x6000)
        self.assertEqual("".join(token.text for token in tokens), "rptz #2; subcx.a #0, r5")

        # R3/As=0 decodes as #0 after the extension format has already selected
        # register mode. Both ZC repetitions still need to execute: 2 -> 1 -> 0.
        program = bytes.fromhex("25 43 01 19 45 73 30 41")
        value = self._reg_value_after(program, 0x2, "r5")
        self.assertEqual(value.value, 0)

    def test_repeat_subc_with_status_register_operand_is_not_folded(self):
        cases = (
            "41 18 05 72",  # RPT #2; SUBCX.W SR,R5
            "41 18 02 74",  # RPT #2; SUBCX.W R4,SR
            "41 18 03 74",  # RPT #2; SUBCX.W R4,R3
        )

        for encoded in cases:
            with self.subTest(encoded=encoded):
                il = self._lift(bytes.fromhex(encoded))
                self.assertNotIn("rpt_subc", "\n".join(str(item) for item in il.instructions))

    def test_nonregister_extension_bit_eight_is_not_zero_carry(self):
        # Bit 8 extends the source address to bank 2 in a non-register
        # extension word; it is not the register-mode ZC bit.
        data = bytes.fromhex("00 19 55 72 56 34")
        instruction = architecture.decode(data, 0x6000)
        self.assertIsNotNone(instruction)
        self.assertFalse(instruction.subc_zero_carry)
        self.assertEqual(self._carry_reads(self._lift(data)), [(1, "flag:c")])


if __name__ == "__main__":
    unittest.main()
