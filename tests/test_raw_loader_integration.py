import unittest

from binaryninja import BinaryView, BinaryViewType

import msp430f5438_memory_map as memory_map
from tests.fixture_firmware import (
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
            self.assertIsNotNone(view.get_function_at(RESET_HANDLER))
            self.assertIsNotNone(view.get_function_at(SPARSE_FUNCTION_ADDRESS))
        finally:
            raw.file.close()


if __name__ == "__main__":
    unittest.main()
