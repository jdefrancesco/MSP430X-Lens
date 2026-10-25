import unittest

from binaryninja import Architecture
from binaryninja.lowlevelil import LowLevelILFunction

import msp430x_arch as architecture
from tests.readability_pseudo_fixtures import (
    UNSIGNED_INDEX_WORDS,
    aligned_advance_words,
    encode_words,
    msb_mask_words,
    signed_index_words,
    wordpair_load_words,
)


PSEUDO_CONTRACTS = (
    (signed_index_words(14, 12), ("r14", "r12"), ("z", "n", "c", "v")),
    (UNSIGNED_INDEX_WORDS, ("r13", "r14", "r15", "r12"), ()),
    (wordpair_load_words(10, 14, 12), ("r14", "r12", "r10"), ("z", "n", "c", "v")),
    ((0x035D, 0x005C, 0x035D, 0x005C), ("r12", "r13"), ("z", "n", "c", "v")),
    ((0x025C, 0x6D0D, 0x025C, 0x6D0D), ("r12", "r13"), ("z", "n", "c", "v")),
    (msb_mask_words(12, 13, 14), ("r13", "r14"), ("z", "n", "c", "v")),
    (aligned_advance_words(14, 12, 15), ("r14", "r12", "r15"), ("z", "n", "c", "v")),
    ((0x0E4C, 0x0D4C), ("r12",), ("z", "n", "c", "v")),
)


def emulate_repeated_addx20_flags(high_word: int) -> dict[str, bool]:
    """Execute the flag-producing RPT #16; ADDX.A high,high sequence."""

    value = high_word & 0xFFFF
    flags = {}
    for _ in range(16):
        old_value = value
        full_result = old_value + old_value
        value = full_result & 0xFFFFF
        flags = {
            "z": value == 0,
            "n": bool(value & 0x80000),
            "c": full_result > 0xFFFFF,
            "v": bool((old_value ^ value) & 0x80000),
        }
    return flags


def evaluate_flag_expression(expr, registers: dict[str, int]):
    """Evaluate the small LLIL subset used by pseudo-instruction flag writes."""

    operation = expr.operation.name
    if operation == "LLIL_CONST":
        return int(expr.constant)
    if operation == "LLIL_REG":
        return registers[str(expr.src)]
    if operation == "LLIL_AND":
        return evaluate_flag_expression(expr.left, registers) & evaluate_flag_expression(
            expr.right,
            registers,
        )
    if operation == "LLIL_OR":
        return evaluate_flag_expression(expr.left, registers) | evaluate_flag_expression(
            expr.right,
            registers,
        )
    if operation == "LLIL_XOR":
        return evaluate_flag_expression(expr.left, registers) ^ evaluate_flag_expression(
            expr.right,
            registers,
        )
    if operation == "LLIL_ADD":
        value = evaluate_flag_expression(expr.left, registers) + evaluate_flag_expression(
            expr.right,
            registers,
        )
        return value & ((1 << (expr.size * 8)) - 1)
    if operation == "LLIL_LSL":
        value = evaluate_flag_expression(expr.left, registers) << evaluate_flag_expression(
            expr.right,
            registers,
        )
        return value & ((1 << (expr.size * 8)) - 1)
    if operation == "LLIL_LSR":
        return evaluate_flag_expression(expr.left, registers) >> evaluate_flag_expression(
            expr.right,
            registers,
        )
    if operation in ("LLIL_LOW_PART", "LLIL_ZX"):
        value = evaluate_flag_expression(expr.src, registers)
        return value & ((1 << (expr.size * 8)) - 1)
    if operation == "LLIL_CMP_E":
        return evaluate_flag_expression(expr.left, registers) == evaluate_flag_expression(
            expr.right,
            registers,
        )
    if operation == "LLIL_CMP_NE":
        return evaluate_flag_expression(expr.left, registers) != evaluate_flag_expression(
            expr.right,
            registers,
        )
    raise AssertionError(f"unsupported flag expression operation: {operation}")


class ReadabilityPseudoSemanticTests(unittest.TestCase):
    def setUp(self):
        self.arch = Architecture["msp430x"]

    def _lift(self, words: tuple[int, ...]):
        data = encode_words(*words)
        instruction = architecture.decode(data, 0x6000)
        self.assertIsNotNone(instruction)
        il = LowLevelILFunction(self.arch)
        length = self.arch.get_instruction_low_level_il(data, 0x6000, il)
        il.finalize()
        self.assertEqual(length, instruction.length)
        return il

    @staticmethod
    def _flag_write(il, name: str):
        writes = [
            instruction
            for instruction in il.instructions
            if instruction.operation.name == "LLIL_SET_FLAG"
            and instruction.dest.name == name
        ]
        if len(writes) != 1:
            raise AssertionError(f"expected one write to {name}, got {len(writes)}")
        return writes[0]

    def _flag_values(self, il, registers: dict[str, int]) -> dict[str, bool]:
        return {
            name: bool(
                evaluate_flag_expression(
                    self._flag_write(il, name).src,
                    registers,
                )
            )
            for name in ("z", "n", "c", "v")
        }

    def test_pseudos_preserve_their_register_and_flag_write_contracts(self):
        for words, expected_registers, expected_flags in PSEUDO_CONTRACTS:
            with self.subTest(first_word=f"{words[0]:#06x}"):
                il = self._lift(words)
                registers = tuple(
                    str(instruction.dest)
                    for instruction in il.instructions
                    if instruction.operation.name == "LLIL_SET_REG"
                    and not str(instruction.dest).startswith("temp")
                )
                flags = tuple(
                    instruction.dest.name
                    for instruction in il.instructions
                    if instruction.operation.name == "LLIL_SET_FLAG"
                )

                self.assertEqual(registers, expected_registers)
                self.assertEqual(flags, expected_flags)

    def test_pseudo_value_flow_stays_free_of_exposed_twenty_bit_masks(self):
        for words, _expected_registers, _expected_flags in PSEUDO_CONTRACTS:
            with self.subTest(first_word=f"{words[0]:#06x}"):
                il = self._lift(words)
                il_text = "\n".join(
                    str(instruction) for instruction in il.instructions
                )
                self.assertNotIn("0xfffff", il_text.lower())

    def test_ld20_flags_match_the_unfolded_repeated_addx_sequence(self):
        il = self._lift(wordpair_load_words(10, 14, 12))
        flag_expressions = {
            name: self._flag_write(il, name).src
            for name in ("z", "n", "c", "v")
        }

        for high_word in (0, 1, 7, 8, 0xF, 0x10, 0x18, 0x1F, 0xFFFF):
            expected = emulate_repeated_addx20_flags(high_word)
            for low_word in (0, 1, 0x8000, 0xFFFF):
                reconstructed = ((high_word & 0xF) << 16) | low_word
                registers = {
                    "temp30": reconstructed,
                    "temp35": high_word,
                }
                actual = {
                    name: bool(evaluate_flag_expression(expr, registers))
                    for name, expr in flag_expressions.items()
                }
                with self.subTest(high=high_word, low=low_word):
                    self.assertEqual(actual, expected)

    def test_wordpair_shift_flags_match_independent_32bit_emulation(self):
        cases = (
            (
                (0x035D, 0x005C, 0x035D, 0x005C),
                "right",
                ("temp41", "temp42", "temp40"),
            ),
            (
                (0x025C, 0x6D0D, 0x025C, 0x6D0D),
                "left",
                ("temp44", "temp45", "temp43"),
            ),
        )
        values = (
            (0, 0),
            (1, 0),
            (0x8000, 0),
            (0xFFFF, 0),
            (0, 1),
            (0, 0x4000),
            (0, 0x8000),
            (0xFFFF, 0xFFFF),
        )

        for words, direction, temps in cases:
            il = self._lift(words)
            low_temp, high_temp, result_temp = temps
            for low_word, high_word in values:
                combined = (high_word << 16) | low_word
                if direction == "right":
                    result = combined >> 2
                    expected = {
                        "z": (result & 0xFFFF) == 0,
                        "n": bool(result & 0x8000),
                        "c": bool(combined & 0x2),
                        "v": False,
                    }
                else:
                    result = (combined << 2) & 0xFFFFFFFF
                    expected = {
                        "z": ((result >> 16) & 0xFFFF) == 0,
                        "n": bool(result & 0x80000000),
                        "c": bool(combined & 0x40000000),
                        "v": bool(combined & 0x40000000)
                        != bool(combined & 0x20000000),
                    }
                registers = {
                    low_temp: low_word,
                    high_temp: high_word,
                    result_temp: result,
                }
                with self.subTest(
                    direction=direction,
                    low=low_word,
                    high=high_word,
                ):
                    self.assertEqual(self._flag_values(il, registers), expected)

    def test_pointer_updates_use_clean_twenty_bit_addition(self):
        cases = (
            (wordpair_load_words(10, 14, 12), 1),
            (aligned_advance_words(14, 12, 15), 2),
        )

        for words, expected_adds in cases:
            with self.subTest(first_word=f"{words[0]:#06x}"):
                il = self._lift(words)
                il_text = "\n".join(
                    str(instruction) for instruction in il.instructions
                )
                self.assertEqual(il_text.count("add20"), expected_adds)
                self.assertNotIn("0xfffff", il_text.lower())


if __name__ == "__main__":
    unittest.main()
