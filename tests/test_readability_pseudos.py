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


class ReadabilityPseudoTests(unittest.TestCase):
    def setUp(self):
        self.arch = Architecture["msp430x"]

    def _text(self, data: bytes, addr: int = 0x6000) -> tuple[str, int]:
        tokens, length = self.arch.get_instruction_text(data, addr)
        return "".join(token.text for token in tokens), length

    def _lift_text(self, data: bytes, addr: int = 0x6000) -> tuple[str, int]:
        il = LowLevelILFunction(self.arch)
        length = self.arch.get_instruction_low_level_il(data, addr, il)
        il.finalize()
        operations = {
            node.operation.name
            for instruction in il.instructions
            for node in instruction.traverse(lambda item: item)
        }
        self.assertNotIn("LLIL_UNIMPL", operations)
        return "\n".join(str(instruction) for instruction in il.instructions), length

    def assert_not_pseudo(self, words: tuple[int, ...], mnemonic: str) -> None:
        instruction = architecture.decode(encode_words(*words), 0x6000)
        if instruction is not None:
            self.assertNotEqual(instruction.mnemonic, mnemonic)

    def test_exact_sequences_decode_render_and_lift_as_named_pseudos(self):
        cases = (
            (
                signed_index_words(14, 12),
                "sxtidx6.w",
                "sxtidx6.w r14, #0x24, r12",
                16,
                ("sxtidx6w",),
            ),
            (
                UNSIGNED_INDEX_WORDS,
                "idx6.w",
                "idx6.w r15, r12",
                30,
                ("idx6w",),
            ),
            (
                wordpair_load_words(10, 14, 12),
                "ld20.w",
                "ld20.w @r10+, r12",
                12,
                ("wordpair20w",),
            ),
            (
                (0x035D, 0x005C, 0x035D, 0x005C),
                "lsr32.w",
                "lsr32.w #0x2, r13:r12",
                8,
                ("lsr32w",),
            ),
            (
                (0x025C, 0x6D0D, 0x025C, 0x6D0D),
                "lsl32.w",
                "lsl32.w #0x2, r13:r12",
                8,
                ("lsl32w",),
            ),
            (
                msb_mask_words(12, 13, 14),
                "msbmask.w",
                "msbmask.w r12, r13, r14",
                10,
                ("msbmaskw",),
            ),
            (
                aligned_advance_words(14, 12, 15),
                "advptr20.w",
                "advptr20.w r12, r14, r15",
                18,
                ("sext20w", "align2_20"),
            ),
            (
                (0x0E4C, 0x0D4C),
                "sext20.w",
                "sext20.w r12",
                4,
                ("sext20w",),
            ),
        )

        for words, mnemonic, expected_text, expected_length, intrinsics in cases:
            with self.subTest(mnemonic=mnemonic):
                data = encode_words(*words)
                instruction = architecture.decode(data, 0x6000)

                self.assertIsNotNone(instruction)
                self.assertEqual(instruction.mnemonic, mnemonic)
                self.assertEqual(instruction.length, expected_length)
                self.assertEqual(self._text(data), (expected_text, expected_length))

                il_text, lifted_length = self._lift_text(data)
                self.assertEqual(lifted_length, expected_length)
                for intrinsic in intrinsics:
                    self.assertIn(intrinsic, il_text)

    def test_truncated_and_near_match_sequences_are_not_folded(self):
        cases = (
            (signed_index_words(14, 12), 3, "sxtidx6.w"),
            (UNSIGNED_INDEX_WORDS, 14, "idx6.w"),
            (wordpair_load_words(10, 14, 12), 3, "ld20.w"),
            ((0x035D, 0x005C, 0x035D, 0x005C), 3, "lsr32.w"),
            ((0x025C, 0x6D0D, 0x025C, 0x6D0D), 3, "lsl32.w"),
            (msb_mask_words(12, 13, 14), 1, "msbmask.w"),
            (aligned_advance_words(14, 12, 15), 7, "advptr20.w"),
            ((0x0E4C, 0x0D4C), 1, "sext20.w"),
        )

        for words, changed_index, mnemonic in cases:
            with self.subTest(mnemonic=mnemonic, case="near-match"):
                changed = list(words)
                changed[changed_index] ^= 1
                self.assert_not_pseudo(tuple(changed), mnemonic)

            with self.subTest(mnemonic=mnemonic, case="truncated"):
                self.assert_not_pseudo(words[:-1], mnemonic)

    def test_special_register_variants_are_not_folded(self):
        cases = (
            (signed_index_words(3, 12), "sxtidx6.w"),
            (signed_index_words(14, 0), "sxtidx6.w"),
            (wordpair_load_words(1, 14, 12), "ld20.w"),
            (wordpair_load_words(10, 2, 12), "ld20.w"),
            (wordpair_load_words(10, 14, 0), "ld20.w"),
            (msb_mask_words(2, 13, 14), "msbmask.w"),
            (msb_mask_words(12, 1, 14), "msbmask.w"),
            (msb_mask_words(12, 13, 0), "msbmask.w"),
            (aligned_advance_words(2, 12, 15), "advptr20.w"),
            (aligned_advance_words(14, 1, 15), "advptr20.w"),
            (aligned_advance_words(14, 12, 0), "advptr20.w"),
            ((0x0E40, 0x0D40), "sext20.w"),
        )

        for words, mnemonic in cases:
            with self.subTest(mnemonic=mnemonic, words=words):
                self.assert_not_pseudo(words, mnemonic)

    def test_unsafe_register_aliases_are_not_folded(self):
        cases = (
            (wordpair_load_words(10, 10, 12), "ld20.w"),
            (wordpair_load_words(10, 14, 10), "ld20.w"),
            (wordpair_load_words(10, 12, 12), "ld20.w"),
            (aligned_advance_words(12, 12, 15), "advptr20.w"),
        )

        for words, mnemonic in cases:
            with self.subTest(mnemonic=mnemonic, words=words):
                self.assert_not_pseudo(words, mnemonic)

    def test_semantically_safe_register_aliases_remain_folded(self):
        cases = (
            (msb_mask_words(12, 12, 12), "msbmask.w"),
            (aligned_advance_words(14, 12, 12), "advptr20.w"),
            (aligned_advance_words(14, 12, 14), "advptr20.w"),
        )

        for words, mnemonic in cases:
            with self.subTest(mnemonic=mnemonic, words=words):
                instruction = architecture.decode(encode_words(*words), 0x6000)
                self.assertIsNotNone(instruction)
                self.assertEqual(instruction.mnemonic, mnemonic)


if __name__ == "__main__":
    unittest.main()
