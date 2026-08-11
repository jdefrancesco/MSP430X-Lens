import unittest

from binaryninja import Architecture, BranchType

import msp430x_arch as architecture


class ControlFlowTests(unittest.TestCase):
    def setUp(self):
        self.arch = Architecture["msp430x"]

    def test_register_indirect_call_has_implicit_fallthrough(self):
        # call r11
        data = bytes.fromhex("8b 12")
        instruction = architecture.decode(data, 0x6D04)

        self.assertIsNotNone(instruction)
        self.assertEqual(
            architecture.decoded_branch_edges(instruction, 0x6D04),
            (("call", None),),
        )
        info = self.arch.get_instruction_info(data, 0x6D04)
        self.assertIsNotNone(info)
        self.assertEqual(info.length, len(data))
        self.assertEqual(info.branches, [])

    def test_direct_call_keeps_call_destination(self):
        # call #0x7de0
        data = bytes.fromhex("b0 12 e0 7d")
        instruction = architecture.decode(data, 0x5C00)

        self.assertIsNotNone(instruction)
        self.assertEqual(
            architecture.decoded_branch_edges(instruction, 0x5C00),
            (("call", 0x7DE0),),
        )
        info = self.arch.get_instruction_info(data, 0x5C00)
        self.assertIsNotNone(info)
        self.assertEqual(info.length, len(data))
        self.assertEqual(len(info.branches), 1)
        self.assertEqual(info.branches[0].type, BranchType.CallDestination)
        self.assertEqual(info.branches[0].target, 0x7DE0)


if __name__ == "__main__":
    unittest.main()
