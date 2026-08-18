import unittest
from unittest import mock

from binaryninja import (
    BinaryView,
    BinaryViewType,
    LowLevelILOperation,
    Settings,
    SettingsScope,
)

import msp430f5438_memory_map as memory_map
from tests.fixture_firmware import (
    CINIT_PAYLOAD_ADDRESSES,
    CINIT_RECORD_ADDRESSES,
    CINIT_TABLE_ADDRESS,
    CINIT_TABLE_END,
    ERASED_GAP_ADDRESS,
    EXACT_MIN_STRING,
    EXACT_MIN_STRING_ADDRESS,
    INDIRECT_CALL_TARGET_ADDRESS,
    INDIRECT_CALL_WRAPPER,
    INDIRECT_CALL_WRAPPER_ADDRESS,
    LONG_STRING,
    LONG_STRING_ADDRESS,
    MMIO_READ_FUNCTION,
    MMIO_READ_FUNCTION_ADDRESS,
    PACKED_ISR_ROUTINES,
    PACKED_ISR_STARTS,
    RESET_HANDLER,
    SHORT_JUNK_STRING,
    SHORT_JUNK_STRING_ADDRESS,
    SPARSE_FUNCTION,
    SPARSE_FUNCTION_ADDRESS,
    STRING_CALL_ARGUMENT,
    STRING_CALL_ARGUMENT_ADDRESS,
    STRING_CALLER_ADDRESS,
    STRING_CALL_TARGET_ADDRESS,
    build_sparse_raw_firmware,
)


class RawLoaderIntegrationTests(unittest.TestCase):
    def test_raw_view_recovers_unreferenced_sparse_function(self):
        raw = BinaryView.new(build_sparse_raw_firmware())
        try:
            view_type = BinaryViewType[memory_map.MSP430F5438BinaryView.name]
            self.assertTrue(view_type.is_valid_for_data(raw))
            scheduled_string_recoveries = []

            def capture_string_recovery(
                view,
                *,
                progress_text,
                action,
            ):
                scheduled_string_recoveries.append(
                    (view, progress_text, action)
                )

            inherited_minimum, inherited_scope = Settings().get_integer_with_scope(
                memory_map.AUTO_STRING_MIN_LENGTH_SETTING,
            )
            expected_minimum = inherited_minimum
            if (
                inherited_scope == SettingsScope.SettingsDefaultScope
                and inherited_minimum < memory_map.ASCII_STRING_MIN_LEN
            ):
                expected_minimum = memory_map.ASCII_STRING_MIN_LEN

            with mock.patch.object(
                memory_map,
                "_recover_direct_string_call_parameters",
                wraps=memory_map._recover_direct_string_call_parameters,
            ) as recover_string_calls, mock.patch.object(
                memory_map,
                "_run_background_analysis_command",
                side_effect=capture_string_recovery,
            ):
                view = view_type.create(raw)
                self.assertIsNotNone(view)
                string_minimum = Settings().get_integer(
                    memory_map.AUTO_STRING_MIN_LENGTH_SETTING,
                    view,
                )
                self.assertEqual(string_minimum, expected_minimum)
                view.update_analysis_and_wait()

                # Initial-analysis callbacks must only enqueue work. Running a
                # synchronous analysis drain inside the callback produces BN's
                # UI-thread wait warning and can deadlock UI callers.
                self.assertEqual(recover_string_calls.call_count, 0)
                self.assertEqual(len(scheduled_string_recoveries), 1)
                recovery_view, progress_text, recovery_action = (
                    scheduled_string_recoveries[0]
                )
                self.assertEqual(recovery_view, view)
                self.assertIn("R12", progress_text)

                # Execute the captured background action deterministically.
                # Its internal analysis update must not recursively fire the
                # one-shot initial-analysis callback.
                recovery_action(view)
                self.assertGreater(recover_string_calls.call_count, 0)
                self.assertEqual(len(scheduled_string_recoveries), 1)

            self.assertEqual(view.view_type, "MSP430F5438")
            self.assertEqual(str(view.arch), "msp430x")
            self.assertEqual(view.entry_point, RESET_HANDLER)
            tlv_result = memory_map._read_tlv_descriptor(view)
            self.assertEqual(tlv_result.status, "absent")
            self.assertIsNone(tlv_result.block)
            self.assertIsNone(view.get_data_var_at(memory_map.TLV_REGION_START))
            self.assertEqual(
                bytes(view.read(SPARSE_FUNCTION_ADDRESS, len(SPARSE_FUNCTION))),
                SPARSE_FUNCTION,
            )
            self.assertEqual(
                bytes(view.read(SHORT_JUNK_STRING_ADDRESS, len(SHORT_JUNK_STRING))),
                SHORT_JUNK_STRING,
            )
            self.assertEqual(
                bytes(view.read(EXACT_MIN_STRING_ADDRESS, len(EXACT_MIN_STRING))),
                EXACT_MIN_STRING,
            )
            self.assertEqual(
                bytes(view.read(LONG_STRING_ADDRESS, len(LONG_STRING))),
                LONG_STRING,
            )
            if string_minimum == memory_map.ASCII_STRING_MIN_LEN:
                self.assertIsNone(view.get_string_at(SHORT_JUNK_STRING_ADDRESS))
                self.assertIsNotNone(view.get_string_at(EXACT_MIN_STRING_ADDRESS))
                self.assertIsNotNone(view.get_string_at(LONG_STRING_ADDRESS))
            self.assertIsNone(view.get_data_var_at(SHORT_JUNK_STRING_ADDRESS))
            self.assertIsNotNone(view.get_data_var_at(EXACT_MIN_STRING_ADDRESS))
            self.assertIsNotNone(view.get_data_var_at(LONG_STRING_ADDRESS))
            self.assertTrue(view.get_segment_at(SPARSE_FUNCTION_ADDRESS).executable)
            self.assertFalse(view.get_segment_at(ERASED_GAP_ADDRESS).executable)
            self.assertIsNotNone(view.get_function_at(RESET_HANDLER))
            self.assertIsNotNone(view.get_function_at(SPARSE_FUNCTION_ADDRESS))
            for start in PACKED_ISR_STARTS:
                self.assertIsNotNone(view.get_function_at(start))
            self.assertEqual(
                bytes(view.read(PACKED_ISR_STARTS[0], sum(map(len, PACKED_ISR_ROUTINES)))),
                b"".join(PACKED_ISR_ROUTINES),
            )
            cinit_functions = sorted(
                function.start
                for function in view.functions
                if CINIT_TABLE_ADDRESS <= function.start < CINIT_TABLE_END
            )
            self.assertEqual(cinit_functions, [])
            for record in CINIT_RECORD_ADDRESSES:
                self.assertIsNotNone(view.get_data_var_at(record))
            for payload in CINIT_PAYLOAD_ADDRESSES:
                self.assertIsNone(view.get_function_at(payload))

            self.assertEqual(
                bytes(
                    view.read(
                        INDIRECT_CALL_WRAPPER_ADDRESS,
                        len(INDIRECT_CALL_WRAPPER),
                    )
                ),
                INDIRECT_CALL_WRAPPER,
            )
            wrapper = view.get_function_at(INDIRECT_CALL_WRAPPER_ADDRESS)
            self.assertIsNotNone(wrapper)
            self.assertIsNotNone(view.get_function_at(INDIRECT_CALL_TARGET_ADDRESS))
            call_il = wrapper.get_low_level_il_at(INDIRECT_CALL_WRAPPER_ADDRESS + 4)
            ret_il = wrapper.get_low_level_il_at(INDIRECT_CALL_WRAPPER_ADDRESS + 6)
            self.assertIsNotNone(call_il)
            self.assertEqual(
                call_il.operation,
                LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
            )
            self.assertIsNotNone(ret_il)
            self.assertEqual(ret_il.operation, LowLevelILOperation.LLIL_RET)
            self.assertTrue(wrapper.can_return.value)
            wrapper_hlil_text = "\n".join(
                str(instruction)
                for block in wrapper.hlil
                for instruction in block
            )
            self.assertNotIn("mmio_read", wrapper_hlil_text)

            self.assertEqual(
                bytes(
                    view.read(
                        STRING_CALL_ARGUMENT_ADDRESS,
                        len(STRING_CALL_ARGUMENT),
                    )
                ),
                STRING_CALL_ARGUMENT,
            )
            string_caller = view.get_function_at(STRING_CALLER_ADDRESS)
            string_target = view.get_function_at(STRING_CALL_TARGET_ADDRESS)
            self.assertIsNotNone(string_caller)
            self.assertIsNotNone(string_target)
            string_call_address = STRING_CALLER_ADDRESS + 0xA
            original_string_target_type = str(string_target.type)
            recovered_hlil_text = "\n".join(
                str(instruction)
                for block in string_caller.hlil
                for instruction in block
            )
            self.assertIn(
                STRING_CALL_ARGUMENT[:-1].decode("ascii"),
                recovered_hlil_text,
            )
            call_adjustment = string_caller.get_call_type_adjustment(
                string_call_address
            )
            self.assertIsNotNone(call_adjustment)
            self.assertEqual(call_adjustment.parameters[0].name, "format")
            self.assertEqual(str(string_target.type), original_string_target_type)
            self.assertNotIn(
                "r12",
                memory_map._register_parameter_names(string_target),
            )
            self.assertEqual(
                memory_map._recover_direct_string_call_parameters(view),
                0,
            )

            mmio_read = view.get_function_at(MMIO_READ_FUNCTION_ADDRESS)
            self.assertIsNotNone(mmio_read)
            self.assertEqual(
                bytes(
                    view.read(
                        MMIO_READ_FUNCTION_ADDRESS,
                        len(MMIO_READ_FUNCTION),
                    )
                ),
                MMIO_READ_FUNCTION,
            )
            dmactl0 = view.get_data_var_at(0x0500)
            self.assertIsNotNone(dmactl0)
            self.assertEqual(dmactl0.type.width, 2)
            self.assertTrue(dmactl0.type.volatile.value)
            mmio_hlil_text = "\n".join(
                str(instruction)
                for block in mmio_read.hlil
                for instruction in block
            )
            self.assertIn("mmio_read16", mmio_hlil_text)
            self.assertIn("DMACTL0", mmio_hlil_text)
        finally:
            raw.file.close()


if __name__ == "__main__":
    unittest.main()
