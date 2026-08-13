import unittest
from unittest import mock

from binaryninja import Architecture, BinaryView, FunctionParameter, Type

import msp430f5438_memory_map as memory_map
import msp430x_arch  # noqa: F401


CALLER_ADDRESS = 0x7000
CALLEE_ADDRESS = 0x7120
STRING_ADDRESS = 0x30FF4
CALL_ADDRESS = 0x7024

# Exact bytes reduced from the UI failure. The MOVA at 0x7020 loads the
# format string into R12 immediately before the direct CALL at 0x7024.
CALLER_BYTES = bytes.fromhex(
    "04 12 05 12 06 12 "
    "34 40 c7 48 "
    "15 42 7a 40 "
    "36 40 05 00 "
    "04 55 "
    "34 e0 31 77 "
    "04 54 "
    "15 53 "
    "16 83 "
    "f9 23 "
    "8c 03 f4 0f "
    "b0 12 20 71 "
    "82 44 7a 40 "
    "36 41 35 41 34 41 30 41"
)
CALLEE_BYTES = bytes.fromhex(
    "04 12 05 12 06 12 "
    "34 40 c9 0b "
    "15 42 6a 40 "
    "36 40 03 00 "
    "04 55 "
    "34 e0 55 67 "
    "04 54 "
    "15 53 "
    "16 83 "
    "f9 23 "
    "8c 03 69 0e "
    "b0 12 00 8b "
    "82 44 6a 40 "
    "36 41 35 41 34 41 30 41"
)
FORMAT_STRING = b"boot_validate_header: enter seq=%u flags=%04x\x00"

ZERO_PARAM_CALLER_ADDRESS = 0x7D20
ZERO_PARAM_CALLEE_ADDRESS = 0xC100
ZERO_PARAM_STRING_ADDRESS = 0x30E04
ZERO_PARAM_CALL_ADDRESS = 0x7D44

# Exact caller bytes from the second UI failure. MOVA at 0x7d40 loads the
# format string, then CALL at 0x7d44 reaches a zero-parameter no-return target.
ZERO_PARAM_CALLER_BYTES = bytes.fromhex(
    "04 12 05 12 06 12 "
    "34 40 92 5e "
    "15 42 c6 41 "
    "36 40 07 00 "
    "04 55 "
    "34 e0 6b fa "
    "84 10 "
    "15 53 "
    "16 83 "
    "f9 23 "
    "8c 03 04 0e "
    "b0 12 00 c1 "
    "82 44 c6 41 "
    "36 41 35 41 34 41 30 41"
)
ZERO_PARAM_FORMAT_STRING = b"module=kernel state=%u result=%d\x00"


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

    def _new_zero_parameter_view(self):
        backing = bytearray(b"\xff" * 0x31000)
        caller_end = ZERO_PARAM_CALLER_ADDRESS + len(ZERO_PARAM_CALLER_BYTES)
        backing[ZERO_PARAM_CALLER_ADDRESS:caller_end] = ZERO_PARAM_CALLER_BYTES
        # A self-loop gives the target the same zero-parameter no-return shape
        # that Binary Ninja inferred for sub_c100 in the real firmware.
        backing[ZERO_PARAM_CALLEE_ADDRESS:ZERO_PARAM_CALLEE_ADDRESS + 2] = b"\xff\x3f"
        string_end = ZERO_PARAM_STRING_ADDRESS + len(ZERO_PARAM_FORMAT_STRING)
        backing[ZERO_PARAM_STRING_ADDRESS:string_end] = ZERO_PARAM_FORMAT_STRING

        view = BinaryView.new(bytes(backing))
        view.platform = self.arch.standalone_platform
        self.assertIsNotNone(view.add_function(ZERO_PARAM_CALLER_ADDRESS))
        callee = view.add_function(ZERO_PARAM_CALLEE_ADDRESS)
        self.assertIsNotNone(callee)
        view.update_analysis_and_wait()
        # Match the real sub_c100 effective type. The minimal self-loop alone
        # does not make BN 5.3 lower can_return automatically.
        callee.set_auto_can_return(False)
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
            original_callee_type = str(callee.type)

            # The decoder and LLIL already know R12.  It disappears only when
            # the callee's auto prototype omits that input.
            r12_at_call = caller.get_reg_value_at(CALL_ADDRESS, "r12")
            self.assertEqual(r12_at_call.value, STRING_ADDRESS)
            self.assertNotIn("boot_validate_header", self._hlil_text(caller))
            self.assertEqual(
                memory_map._register_parameter_names(callee),
                {"r4", "r5", "r6"},
            )
            decoder, _ = memory_map._msp430x_decode_api()
            self.assertIn(CALL_ADDRESS, [site.address for site in caller.call_sites])
            self.assertEqual(
                memory_map._direct_msp430_call_target(view, CALL_ADDRESS, decoder),
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
            self.assertIn(
                "boot_validate_header: enter seq=%u flags=%04x",
                self._hlil_text(caller),
            )
            call_adjustment = caller.get_call_type_adjustment(CALL_ADDRESS)
            self.assertIsNotNone(call_adjustment)
            self.assertEqual(call_adjustment.parameters[0].name, "format")
            self.assertIn("char", str(call_adjustment.parameters[0].type))
            self.assertTrue(call_adjustment.has_variable_arguments.value)

            # Evidence from one call site must not rewrite the callee globally.
            self.assertEqual(str(callee.type), original_callee_type)
            self.assertEqual(
                memory_map._register_parameter_names(callee),
                {"r4", "r5", "r6"},
            )

            # The durable call adjustment survives later analysis and makes a
            # second recovery pass a no-op.
            view.update_analysis_and_wait()
            self.assertEqual(
                memory_map._recover_direct_string_call_parameters(view),
                0,
            )
            self.assertIn(
                "boot_validate_header: enter seq=%u flags=%04x",
                self._hlil_text(caller),
            )

            # A full later caller reanalysis used to delete the private
            # automatic adjustment and make Pseudo C revert. The public local
            # adjustment must survive that lifecycle as well.
            caller.reanalyze()
            view.update_analysis_and_wait()
            self.assertIsNotNone(caller.get_call_type_adjustment(CALL_ADDRESS))
            self.assertIn(
                "boot_validate_header: enter seq=%u flags=%04x",
                self._hlil_text(caller),
            )
            self.assertEqual(
                memory_map._recover_direct_string_call_parameters(view),
                0,
            )
        finally:
            view.file.close()

    def test_existing_user_call_adjustment_is_never_replaced(self):
        view = self._new_view()
        try:
            caller = view.get_function_at(CALLER_ADDRESS)
            callee = view.get_function_at(CALLEE_ADDRESS)
            original_callee_type = str(callee.type)
            user_adjustment = Type.function(
                callee.return_type,
                [FunctionParameter(Type.int(2, False), "event")],
                calling_convention=self.arch.default_calling_convention,
            )
            caller.set_call_type_adjustment(CALL_ADDRESS, user_adjustment)
            view.update_analysis_and_wait()

            self.assertEqual(
                memory_map._recover_direct_string_call_parameters(view),
                0,
            )
            retained_adjustment = caller.get_call_type_adjustment(CALL_ADDRESS)
            self.assertIsNotNone(retained_adjustment)
            self.assertEqual(retained_adjustment.parameters[0].name, "event")
            self.assertEqual(str(callee.type), original_callee_type)
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

    def test_proven_string_call_recovers_zero_parameter_noreturn_auto_type(self):
        view = self._new_zero_parameter_view()
        try:
            caller = view.get_function_at(ZERO_PARAM_CALLER_ADDRESS)
            callee = view.get_function_at(ZERO_PARAM_CALLEE_ADDRESS)

            self.assertFalse(callee.has_user_type)
            self.assertEqual(callee.type.parameters, [])
            self.assertFalse(callee.can_return.value)
            self.assertEqual(
                caller.get_reg_value_at(ZERO_PARAM_CALL_ADDRESS, "r12").value,
                ZERO_PARAM_STRING_ADDRESS,
            )
            self.assertEqual(
                memory_map._recover_direct_string_call_parameters(view),
                1,
            )
            view.update_analysis_and_wait()

            adjustment = caller.get_call_type_adjustment(ZERO_PARAM_CALL_ADDRESS)
            self.assertIsNotNone(adjustment)
            self.assertEqual(adjustment.parameters[0].name, "format")
            self.assertFalse(adjustment.can_return.value)
            self.assertIn(
                "module=kernel state=%u result=%d",
                self._hlil_text(caller),
            )

            # Recovery is local to the proven call; the shared callee remains
            # an auto-inferred zero-parameter no-return function.
            self.assertEqual(callee.type.parameters, [])
            self.assertFalse(callee.has_user_type)
        finally:
            view.file.close()

    def test_msp430_varargs_do_not_consume_remaining_argument_registers(self):
        self.assertFalse(self.arch.default_calling_convention.arg_regs_for_varargs)

    def test_format_detection_ignores_escaped_percent(self):
        self.assertTrue(memory_map._has_format_argument("result=%04x"))
        self.assertFalse(memory_map._has_format_argument("literal %%u"))
        self.assertTrue(memory_map._has_format_argument("literal %%%u then value"))

    def test_affected_callers_are_refreshed_incrementally(self):
        updates = []

        class Caller:
            def reanalyze(self):
                raise AssertionError("full caller reanalysis must not be requested")

            def mark_updates_required(self, update_type):
                updates.append(update_type)

        callers = [Caller() for _ in range(3)]
        memory_map._mark_incremental_function_updates(callers)

        self.assertEqual(
            updates,
            [memory_map.FunctionUpdateType.IncrementalAutoFunctionUpdate] * 3,
        )

    def test_recovery_runs_to_a_bounded_fixed_point(self):
        view = object()
        with mock.patch.object(
            memory_map,
            "_recover_direct_string_call_parameters",
            side_effect=(109, 41, 0),
        ) as recover, mock.patch.object(memory_map, "_update_analysis") as update:
            passes = memory_map._stabilize_direct_string_call_parameters(view)

        self.assertEqual(passes, (109, 41, 0))
        self.assertEqual(recover.call_count, 3)
        self.assertEqual(update.call_count, 2)
        update.assert_has_calls([mock.call(view), mock.call(view)])

    def test_recovery_stops_at_its_analysis_pass_limit(self):
        view = object()
        with mock.patch.object(
            memory_map,
            "_recover_direct_string_call_parameters",
            return_value=1,
        ) as recover, mock.patch.object(
            memory_map,
            "_update_analysis",
        ) as update, mock.patch.object(memory_map, "log_warn") as warn:
            passes = memory_map._stabilize_direct_string_call_parameters(
                view,
                max_passes=3,
            )

        self.assertEqual(passes, (1, 1, 1))
        self.assertEqual(recover.call_count, 3)
        self.assertEqual(update.call_count, 3)
        warn.assert_called_once()


if __name__ == "__main__":
    unittest.main()
