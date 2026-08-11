import unittest

from binaryninja import BinaryView, BinaryViewType, LowLevelILOperation

import msp430f5438_memory_map as memory_map
from tests.fixture_firmware import (
    CINIT_PAYLOAD_ADDRESSES,
    CINIT_RECORD_ADDRESSES,
    CINIT_TABLE_ADDRESS,
    CINIT_TABLE_END,
    ERASED_GAP_ADDRESS,
    INDIRECT_CALL_TARGET_ADDRESS,
    INDIRECT_CALL_WRAPPER,
    INDIRECT_CALL_WRAPPER_ADDRESS,
    PACKED_ISR_ROUTINES,
    PACKED_ISR_STARTS,
    RESET_HANDLER,
    SPARSE_FUNCTION,
    SPARSE_FUNCTION_ADDRESS,
    build_sparse_raw_firmware,
)


class RawLoaderIntegrationTests(unittest.TestCase):
    def test_raw_view_recovers_unreferenced_sparse_function(self):
        raw = BinaryView.new(build_sparse_raw_firmware())
        try:
            view_type = BinaryViewType[memory_map.MSP430F5438BinaryView.name]
            self.assertTrue(view_type.is_valid_for_data(raw))

            view = view_type.create(raw)
            self.assertIsNotNone(view)
            view.update_analysis_and_wait()

            self.assertEqual(view.view_type, "MSP430F5438")
            self.assertEqual(str(view.arch), "msp430x")
            self.assertEqual(view.entry_point, RESET_HANDLER)
            self.assertEqual(
                bytes(view.read(SPARSE_FUNCTION_ADDRESS, len(SPARSE_FUNCTION))),
                SPARSE_FUNCTION,
            )
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
        finally:
            raw.file.close()


if __name__ == "__main__":
    unittest.main()
