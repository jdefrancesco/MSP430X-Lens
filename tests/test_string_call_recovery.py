import unittest

from binaryninja import Architecture, BinaryView, FunctionParameter, Type

import msp430f5438_memory_map as memory_map
import msp430x_arch  # noqa: F401


CALLER_ADDRESS = 0x71E0
CALLEE_ADDRESS = 0x7AE0
STRING_ADDRESS = 0x30E69

# Exact bytes reduced from the UI failure.  The MOVA at 0x7200 loads the
# format string into R12 immediately before the direct CALL at 0x7204.
CALLER_BYTES = bytes.fromhex(
    "04 12 05 12 06 12 "
    "34 40 fc e4 "
    "15 42 04 1d "
    "36 40 04 00 "
    "04 55 "
    "34 e0 4d e8 "
    "84 10 "
    "15 53 "
    "16 83 "
    "f9 23 "
    "8c 03 69 0e "
    "b0 12 e0 7a "
    "82 44 04 1d "
    "36 41 35 41 34 41 30 41"
)
CALLEE_BYTES = bytes.fromhex(
    "04 12 05 12 06 12 36 41 35 41 34 41 30 41"
)
FORMAT_STRING = b"module=startup state=%u result=%u\x00"


class StringCallRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.arch = Architecture["msp430x"]

    def _new_view(self):
        backing = bytearray(b"\xff" * 0x31000)
        backing[CALLER_ADDRESS:CALLER_ADDRESS + len(CALLER_BYTES)] = CALLER_BYTES
        backing[CALLEE_ADDRESS:CALLEE_ADDRESS + len(CALLEE_BYTES)] = CALLEE_BYTES
        backing[STRING_ADDRESS:STRING_ADDRESS + len(FORMAT_STRING)] = FORMAT_STRING

        view = BinaryView.new(bytes(backing))
        view.platform = self.arch.standalone_platform
        self.assertIsNotNone(view.add_function(CALLER_ADDRESS))
        self.assertIsNotNone(view.add_function(CALLEE_ADDRESS))
        view.update_analysis_and_wait()
        return view

    @staticmethod
    def _hlil_text(function):
        return "\n".join(
            str(instruction)
            for block in function.hlil
            for instruction in block
        )

    def test_direct_r12_string_survives_in_pseudo_c(self):
        view = self._new_view()
        try:
            caller = view.get_function_at(CALLER_ADDRESS)
            callee = view.get_function_at(CALLEE_ADDRESS)
            self.assertIsNotNone(caller)
            self.assertIsNotNone(callee)

            # The decoder and LLIL already know R12.  It disappears only when
            # the callee's auto prototype omits that input.
            r12_at_call = caller.get_reg_value_at(0x7204, "r12")
            self.assertEqual(r12_at_call.value, STRING_ADDRESS)
            self.assertNotIn("module=startup", self._hlil_text(caller))
            self.assertEqual(
                memory_map._register_parameter_names(callee),
                {"r4", "r5", "r6"},
            )
            decoder, _ = memory_map._msp430x_decode_api()
            self.assertIn(0x7204, [site.address for site in caller.call_sites])
            self.assertEqual(
                memory_map._direct_msp430_call_target(view, 0x7204, decoder),
                CALLEE_ADDRESS,
            )
            self.assertEqual(
                memory_map._function_at_call_target(view, caller, CALLEE_ADDRESS).start,
                CALLEE_ADDRESS,
            )
            self.assertIn(
                r12_at_call.type,
                (
                    memory_map.RegisterValueType.ConstantValue,
                    memory_map.RegisterValueType.ConstantPointerValue,
                ),
            )
            self.assertEqual(
                memory_map._read_backed_ascii_c_string(view, STRING_ADDRESS),
                FORMAT_STRING[:-1].decode("ascii"),
            )
            self.assertIsNotNone(memory_map._preservable_auto_parameters(callee))
            self.assertEqual(tuple(callee.calling_convention.int_arg_regs)[0], "r12")

            self.assertEqual(
                memory_map._recover_direct_string_call_parameters(view),
                1,
            )
            view.update_analysis_and_wait()

            caller = view.get_function_at(CALLER_ADDRESS)
            callee = view.get_function_at(CALLEE_ADDRESS)
            self.assertIn("module=startup state=%u result=%u", self._hlil_text(caller))
            self.assertEqual(callee.type.parameters[0].name, "format")
            self.assertIn("char", str(callee.type.parameters[0].type))
            self.assertEqual(
                memory_map._register_parameter_names(callee),
                {"r4", "r5", "r6", "r12"},
            )
            self.assertTrue(callee.has_variable_arguments.value)

            # The recovered R12 parameter makes a second pass a no-op.
            self.assertEqual(
                memory_map._recover_direct_string_call_parameters(view),
                0,
            )
        finally:
            view.file.close()

    def test_user_function_type_is_never_replaced(self):
        view = self._new_view()
        try:
            callee = view.get_function_at(CALLEE_ADDRESS)
            user_type = Type.function(
                Type.void(),
                [FunctionParameter(Type.int(2, False), "event")],
                calling_convention=self.arch.default_calling_convention,
            )
            callee.set_user_type(user_type)
            view.update_analysis_and_wait()

            self.assertTrue(callee.has_user_type)
            self.assertEqual(
                memory_map._recover_direct_string_call_parameters(view),
                0,
            )
            self.assertEqual(callee.type.parameters[0].name, "event")
        finally:
            view.file.close()

    def test_explicit_zero_parameter_auto_type_is_not_guessed_over(self):
        view = self._new_view()
        try:
            callee = view.get_function_at(CALLEE_ADDRESS)
            callee.set_auto_type(
                Type.function(
                    Type.void(),
                    [],
                    calling_convention=self.arch.default_calling_convention,
                )
            )
            view.get_function_at(CALLER_ADDRESS).reanalyze()
            view.update_analysis_and_wait()

            self.assertFalse(callee.has_user_type)
            self.assertEqual(callee.type.parameters, [])
            self.assertEqual(
                memory_map._recover_direct_string_call_parameters(view),
                0,
            )
            self.assertEqual(callee.type.parameters, [])
        finally:
            view.file.close()

    def test_msp430_varargs_do_not_consume_remaining_argument_registers(self):
        self.assertFalse(self.arch.default_calling_convention.arg_regs_for_varargs)

    def test_format_detection_ignores_escaped_percent(self):
        self.assertTrue(memory_map._has_format_argument("result=%04x"))
        self.assertFalse(memory_map._has_format_argument("literal %%u"))
        self.assertTrue(memory_map._has_format_argument("literal %%%u then value"))


if __name__ == "__main__":
    unittest.main()
