import unittest

from binaryninja import Architecture
from binaryninja.lowlevelil import LowLevelILFunction

import msp430x_arch as architecture


class ExtendedFormatIITests(unittest.TestCase):
    def setUp(self):
        self.arch = Architecture["msp430x"]

    def _text(self, encoded: str, addr: int = 0x6000):
        data = bytes.fromhex(encoded)
        tokens, length = self.arch.get_instruction_text(data, addr)
        return "".join(token.text for token in tokens), length

    def _lift(self, encoded: str, addr: int = 0x6000):
        data = bytes.fromhex(encoded)
        il = LowLevelILFunction(self.arch)
        length = self.arch.get_instruction_low_level_il(data, addr, il)
        il.finalize()
        self.assertEqual(length, len(data))
        return il

    @staticmethod
    def _operations(il):
        return {
            node.operation.name
            for instruction in il.instructions
            for node in instruction.traverse(lambda item: item)
        }

    def test_nonregister_operands_take_high_address_bits_from_low_nibble(self):
        cases = (
            ("03 18 52 10 34 12", "rrcx", "rrcx.a &0x31234", 0x31234, 4),
            ("0a 18 52 11 78 56", "rrax", "rrax.a &0xa5678", 0xA5678, 4),
            ("0b 18 92 10 45 23", "swpb", "swpbx.a &0xb2345", 0xB2345, 4),
            ("0c 18 92 11 56 34", "sxt", "sxtx.a &0xc3456", 0xC3456, 4),
            ("0d 18 52 12 67 45", "push", "pushx.a &0xd4567", 0xD4567, 4),
        )

        for encoded, mnemonic, expected_text, expected_address, expected_size in cases:
            with self.subTest(encoded=encoded):
                data = bytes.fromhex(encoded)
                instruction = architecture.decode(data, 0x6000)

                self.assertIsNotNone(instruction)
                self.assertEqual(instruction.fmt, "single")
                self.assertEqual(instruction.mnemonic, mnemonic)
                self.assertEqual(instruction.size, expected_size)
                self.assertEqual(instruction.length, len(data))
                self.assertEqual(instruction.src.kind, "mem")
                self.assertEqual(instruction.src.addr, expected_address)
                self.assertIsNone(instruction.rpt_count)
                self.assertIsNone(instruction.rpt_reg)
                self.assertEqual(self._text(encoded), (expected_text, len(data)))

    def test_high_bank_rrcx_lifts_the_full_address_without_a_repeat(self):
        encoded = "03 18 52 10 34 12"
        il = self._lift(encoded)
        text = "\n".join(str(instruction) for instruction in il.instructions)

        self.assertNotIn("LLIL_UNIMPL", self._operations(il))
        self.assertIn("0x31234", text)
        self.assertNotIn("0x1234", text.replace("0x31234", ""))
        self.assertNotIn("rpt_rrcx", text)

    def test_nonregister_high_address_is_preserved_at_each_data_width(self):
        cases = (
            ("03 18 52 10 34 12", "rrcx.a &0x31234", 4),
            ("43 18 12 10 34 12", "rrcx.w &0x31234", 2),
            ("43 18 52 10 34 12", "rrcx.b &0x31234", 1),
            ("43 18 92 10 34 12", "swpbx.w &0x31234", 2),
            ("43 18 92 11 34 12", "sxtx.w &0x31234", 2),
        )

        for encoded, expected_text, expected_size in cases:
            with self.subTest(encoded=encoded):
                instruction = architecture.decode(bytes.fromhex(encoded), 0x6000)

                self.assertIsNotNone(instruction)
                self.assertEqual(instruction.fmt, "single")
                self.assertEqual(instruction.size, expected_size)
                self.assertEqual(instruction.src.addr, 0x31234)
                self.assertEqual(self._text(encoded), (expected_text, 6))

    def test_indexed_symbolic_and_immediate_forms_use_the_same_low_nibble(self):
        cases = (
            (
                "05 18 54 10 34 12",
                "indexed",
                0x51234,
                "rrcx.a 0x51234(r4)",
            ),
            (
                "0f 18 54 10 f0 ff",
                "indexed",
                -0x10,
                "rrcx.a -0x10(r4)",
            ),
            (
                "03 18 50 10 34 12",
                "mem",
                0x3723A,
                "rrcx.a 0x3723a",
            ),
            (
                "09 18 70 12 34 12",
                "imm",
                0x91234,
                "pushx.a #0x91234",
            ),
        )

        for encoded, kind, value, expected_text in cases:
            with self.subTest(encoded=encoded):
                instruction = architecture.decode(bytes.fromhex(encoded), 0x6000)

                self.assertIsNotNone(instruction)
                self.assertEqual(instruction.fmt, "single")
                self.assertEqual(instruction.src.kind, kind)
                actual = (
                    instruction.src.addr
                    if kind == "mem"
                    else instruction.src.value
                )
                self.assertEqual(actual, value)
                self.assertIsNone(instruction.rpt_count)
                self.assertIsNone(instruction.rpt_reg)
                self.assertEqual(self._text(encoded), (expected_text, 6))

    def test_register_mode_low_nibble_remains_the_repeat_field(self):
        cases = (
            ("03 18 44 10", "rpt #4; rrcx.a r4", "rrcx", 4),
            ("03 18 44 11", "rpt #4; rrax.a r4", "rrax", 4),
            ("00 19 44 10", "rrux.a r4", "rrux", None),
        )

        for encoded, expected_text, mnemonic, repeat_count in cases:
            with self.subTest(encoded=encoded):
                instruction = architecture.decode(bytes.fromhex(encoded), 0x6000)

                self.assertIsNotNone(instruction)
                self.assertEqual(instruction.fmt, "single")
                self.assertEqual(instruction.mnemonic, mnemonic)
                self.assertEqual(instruction.rpt_count, repeat_count)
                self.assertEqual(self._text(encoded), (expected_text, 4))

    def test_reserved_extended_format_ii_encodings_remain_fallbacks(self):
        cases = (
            "00 18 04 10",  # RRCX with reserved A/L=0, B/W=0.
            "03 18 12 10 34 12",  # Same reserved width in absolute mode.
            "00 18 c4 10",  # SWPBX does not have a B/W=1 form.
            "40 18 c4 11",  # SXTX does not have a byte form.
            "03 19 52 10 34 12",  # RRUX is register-only.
            "00 1a 44 10",  # Register-mode extension bit 9 is reserved.
            "80 18 52 10 34 12",  # Non-register extension bits 10:7 are reserved.
            "00 18 84 12",  # Extended CALL is not CALLA.
            "00 18 00 13",  # RETI has no extension-word form.
            "00 18 00 3c",  # Jumps have no extension-word form.
        )

        for encoded in cases:
            with self.subTest(encoded=encoded):
                data = bytes.fromhex(encoded)
                instruction = architecture.decode(data, 0x6000)

                self.assertIsNotNone(instruction)
                self.assertEqual(instruction.fmt, "cpux")
                self.assertEqual(instruction.length, 2)
                extension = int.from_bytes(data[:2], "little")
                self.assertEqual(
                    self._text(encoded),
                    (f"cpux {extension:#06x}", 2),
                )


if __name__ == "__main__":
    unittest.main()
