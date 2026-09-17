import unittest

from binaryninja import Architecture, BinaryView, FunctionParameter, Type

import msp430f5438_memory_map as memory_map
import msp430x_arch  # noqa: F401


FUNCTION_ADDRESS = 0x100

# mov.b 2(r12), r13
# mov.w 4(r12), r14
# mov.w r15, 6(r12)
# mova 8(r12), r13
# mova r14, 0xc(r12)
# ret
MIXED_STRUCT_BYTES = bytes.fromhex(
    "5d 4c 02 00 "
    "1e 4c 04 00 "
    "8c 4f 06 00 "
    "3d 0c 08 00 "
    "7c 0e 0c 00 "
    "30 41"
)

# mov r12, r11
# mov.b 2(r11), r13
# mov.w 4(r11), r14
# ret
ALIASED_SMALL_POINTER_BYTES = bytes.fromhex(
    "0b 4c "
    "5d 4b 02 00 "
    "1e 4b 04 00 "
    "30 41"
)

# Three equal-width, regularly spaced reads are stronger evidence of an array
# than a heterogeneous record.
ARRAY_SHAPED_BYTES = bytes.fromhex(
    "1d 4c 00 00 "
    "1e 4c 02 00 "
    "1f 4c 04 00 "
    "30 41"
)

# The byte and word reads disagree at offset 2. The one remaining unambiguous
# field is insufficient to synthesize a structure.
CONFLICTING_FIELD_BYTES = bytes.fromhex(
    "5d 4c 02 00 "
    "1e 4c 02 00 "
    "1f 4c 06 00 "
    "30 41"
)


class StructRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.arch = Architecture["msp430x"]

    def _new_view(self, code):
        backing = bytearray(b"\xff" * 0x300)
        backing[FUNCTION_ADDRESS:FUNCTION_ADDRESS + len(code)] = code
        view = BinaryView.new(bytes(backing))
        view.platform = self.arch.standalone_platform
        self.assertIsNotNone(view.add_function(FUNCTION_ADDRESS))
        view.update_analysis_and_wait()
        return view

    @staticmethod
    def _hlil_text(function):
        return "\n".join(
            str(instruction)
            for block in function.hlil
            for instruction in block
        )

    def test_mixed_parameter_accesses_create_clean_auto_structure(self):
        view = self._new_view(MIXED_STRUCT_BYTES)
        try:
            function = view.get_function_at(FUNCTION_ADDRESS)
            self.assertIn("void*", str(function.type.parameters[0].type))

            self.assertEqual(memory_map._recover_msp430x_structures(view), 1)
            view.update_analysis_and_wait()

            function = view.get_function_at(FUNCTION_ADDRESS)
            parameter_type = function.type.parameters[0].type
            self.assertEqual(
                str(parameter_type),
                "struct msp430x_auto_struct_00100_r12*",
            )
            structure = view.get_type_by_name("msp430x_auto_struct_00100_r12")
            self.assertIsNotNone(structure)
            self.assertEqual(
                [
                    (member.offset, member.type.width, member.name)
                    for member in structure.members
                ],
                [
                    (2, 1, "field_02"),
                    (4, 2, "field_04"),
                    (6, 2, "field_06"),
                    (8, 4, "field_08"),
                    (12, 4, "field_0c"),
                ],
            )

            hlil = self._hlil_text(function)
            # The field_02 read is dead and therefore intentionally absent
            # from HLIL, but mapped MLIL still supplied it to the structure.
            self.assertIn("arg1->field_04", hlil)
            self.assertIn("arg1->field_06", hlil)
            self.assertIn("load20(&arg1->field_08)", hlil)
            self.assertIn("store20(&arg1->field_0c", hlil)
            self.assertNotIn("fffff", hlil.lower())
            self.assertNotIn("0xffff", hlil.lower())

            self.assertEqual(memory_map._recover_msp430x_structures(view), 0)
        finally:
            view.file.close()

    def test_register_alias_is_traced_and_keeps_small_pointer_width(self):
        view = self._new_view(ALIASED_SMALL_POINTER_BYTES)
        try:
            function = view.get_function_at(FUNCTION_ADDRESS)
            self.assertEqual(function.type.parameters[0].type.width, 2)

            self.assertEqual(memory_map._recover_msp430x_structures(view), 1)
            view.update_analysis_and_wait()

            function = view.get_function_at(FUNCTION_ADDRESS)
            self.assertEqual(function.type.parameters[0].type.width, 2)
            structure = view.get_type_by_name("msp430x_auto_struct_00100_r12")
            self.assertEqual(
                [(member.offset, member.type.width) for member in structure.members],
                [(2, 1), (4, 2)],
            )
            hlil = self._hlil_text(function)
            # BN currently drops pointer provenance when a 16-bit pointer is
            # zero-extended through a 20-bit register alias. Recovery must not
            # expose the architecture's masks while retaining the ABI width.
            self.assertNotIn("fffff", hlil.lower())
            self.assertEqual(memory_map._recover_msp430x_structures(view), 0)
        finally:
            view.file.close()

    def test_array_shaped_accesses_are_not_misclassified(self):
        view = self._new_view(ARRAY_SHAPED_BYTES)
        try:
            self.assertEqual(memory_map._recover_msp430x_structures(view), 0)
            self.assertIsNone(
                view.get_type_by_name("msp430x_auto_struct_00100_r12")
            )
        finally:
            view.file.close()

    def test_conflicting_field_widths_are_not_invented(self):
        view = self._new_view(CONFLICTING_FIELD_BYTES)
        try:
            self.assertEqual(memory_map._recover_msp430x_structures(view), 0)
            self.assertIsNone(
                view.get_type_by_name("msp430x_auto_struct_00100_r12")
            )
        finally:
            view.file.close()

    def test_user_function_type_is_never_replaced(self):
        view = self._new_view(MIXED_STRUCT_BYTES)
        try:
            function = view.get_function_at(FUNCTION_ADDRESS)
            user_type = Type.function(
                Type.void(),
                [FunctionParameter(Type.int(4, False), "context")],
                calling_convention=self.arch.default_calling_convention,
            )
            function.set_user_type(user_type)
            view.update_analysis_and_wait()

            self.assertEqual(memory_map._recover_msp430x_structures(view), 0)
            function = view.get_function_at(FUNCTION_ADDRESS)
            self.assertTrue(function.has_user_type)
            self.assertEqual(function.type.parameters[0].name, "context")
            self.assertEqual(str(function.type.parameters[0].type), "uint32_t")
        finally:
            view.file.close()


if __name__ == "__main__":
    unittest.main()
