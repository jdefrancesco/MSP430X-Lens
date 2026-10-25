import unittest

from binaryninja import Architecture
from binaryninja.lowlevelil import LowLevelILFunction

import msp430x_arch as architecture


def encode_words(*words: int) -> bytes:
    return b"".join(word.to_bytes(2, "little") for word in words)


def signed_index_words(src: int, dst: int, bias: int = 0x24) -> tuple[int, ...]:
    return (
        (src << 8) | 0xC0 | dst,
        0x0650 | dst,
        0x0250 | src,
        0x5000 | (src << 8) | dst,
        0x5030 | dst,
        bias,
        0x0E40 | dst,
        0x0D40 | dst,
    )


def wordpair_load_words(base: int, low: int, dst: int) -> tuple[int, ...]:
    return (
        0x4030 | (base << 8) | low,
        0x4030 | (base << 8) | dst,
        0x180F,
        0x5040 | (dst << 8) | dst,
        0x1800,
        0xD040 | (low << 8) | dst,
    )


def msb_mask_words(src: int, scratch: int, dst: int) -> tuple[int, ...]:
    return (
        0x00C0 | (src << 8) | scratch,
        0xB030 | scratch,
        0x8000,
        0x7000 | (dst << 8) | dst,
        0xE330 | dst,
    )


def aligned_advance_words(offset: int, base: int, dst: int) -> tuple[int, ...]:
    return (
        0x0E40 | offset,
        0x0D40 | offset,
        (offset << 8) | 0x00E0 | base,
        0x00C0 | (base << 8) | dst,
        0x00A0 | dst,
        0x0001,
        0x1F80,
        0xF070 | dst,
        0xFFFE,
    )


UNSIGNED_INDEX_WORDS = (
    0x430C,
    0x0FCD,
    0x0CCE,
    0x025D,
    0x6E0E,
    0x025F,
    0x6C0C,
    0x025F,
    0x6C0C,
    0x5D0F,
    0x6E0C,
    0x180F,
    0x5C4C,
    0x1800,
    0xDF4C,
    0x00AC,
    0x7000,
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
                il_text = "\n".join(str(instruction) for instruction in self._lift(words))
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


if __name__ == "__main__":
    unittest.main()
