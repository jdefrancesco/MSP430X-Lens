import unittest

import msp430f5438_memory_map as memory_map
import msp430x_arch as architecture


DISPATCH_ADDRESS = 0x6000
VALID_ADDRESS_JUMP_TABLE = bytes.fromhex(
    "4c 0e 4c 05 00 18 50 4c 0a 60 "
    "00 62 00 00 00 63 00 00 00 64 00 00"
)
MALFORMED_ADDRESS_JUMP_TABLE = bytes.fromhex(
    "4c 0e 4c 05 00 18 50 4c 0a 60 "
    "00 62 10 00 00 63 00 00 00 64 00 00"
)


class AddressJumpTableTests(unittest.TestCase):
    def test_valid_two_word_targets_are_recognized(self):
        instruction = architecture.decode(
            VALID_ADDRESS_JUMP_TABLE,
            DISPATCH_ADDRESS,
        )

        self.assertIsNotNone(instruction)
        self.assertEqual(instruction.mnemonic, "brajt.a")
        self.assertEqual(instruction.targets, (0x6200, 0x6300, 0x6400))
        self.assertEqual(
            memory_map._address_jump_tables(
                VALID_ADDRESS_JUMP_TABLE,
                DISPATCH_ADDRESS,
            ),
            ((DISPATCH_ADDRESS, DISPATCH_ADDRESS + 10, instruction.targets),),
        )

    def test_reserved_high_word_bits_reject_the_table(self):
        instruction = architecture.decode(
            MALFORMED_ADDRESS_JUMP_TABLE,
            DISPATCH_ADDRESS,
        )

        self.assertIsNotNone(instruction)
        self.assertNotEqual(instruction.mnemonic, "brajt.a")
        self.assertEqual(instruction.targets, ())
        self.assertEqual(
            memory_map._address_jump_tables(
                MALFORMED_ADDRESS_JUMP_TABLE,
                DISPATCH_ADDRESS,
            ),
            (),
        )


if __name__ == "__main__":
    unittest.main()
