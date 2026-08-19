import io
import unittest
from contextlib import redirect_stdout

from binaryninja import Architecture, BinaryView

import msp430f5438_memory_map as memory_map
import msp430x_arch  # noqa: F401


CALLER_A = 0x100
CALLER_B = 0x120
CALLER_C = 0x140
HELPER_TARGET = 0x180
ONE_OFF_TARGET = 0x1A0


def _direct_call(target: int) -> bytes:
    return b"\xb0\x12" + target.to_bytes(2, "little")


class RawHelperCandidateTests(unittest.TestCase):
    def setUp(self):
        self.arch = Architecture["msp430x"]

    def _new_view(self):
        backing = bytearray(b"\xff" * 0x300)
        backing[CALLER_A:CALLER_A + 6] = _direct_call(HELPER_TARGET) + b"\x30\x41"
        backing[CALLER_B:CALLER_B + 6] = _direct_call(HELPER_TARGET) + b"\x30\x41"
        backing[CALLER_C:CALLER_C + 6] = _direct_call(ONE_OFF_TARGET) + b"\x30\x41"
        backing[HELPER_TARGET:HELPER_TARGET + 2] = b"\x30\x41"
        backing[ONE_OFF_TARGET:ONE_OFF_TARGET + 2] = b"\x30\x41"

        view = BinaryView.new(bytes(backing))
        view.platform = self.arch.standalone_platform
        for addr in (CALLER_A, CALLER_B, CALLER_C, HELPER_TARGET, ONE_OFF_TARGET):
            self.assertIsNotNone(view.add_function(addr))
        view.update_analysis_and_wait()
        return view

    def test_collects_high_fan_in_default_named_direct_call_targets(self):
        view = self._new_view()
        try:
            candidates = memory_map._raw_msp430_helper_candidates(
                view,
                min_call_sites=2,
            )

            self.assertEqual(len(candidates), 1)
            candidate = candidates[0]
            self.assertEqual(candidate.target, HELPER_TARGET)
            self.assertEqual(candidate.call_count, 2)
            self.assertEqual(
                [site.call_addr for site in candidate.call_sites],
                [CALLER_A, CALLER_B],
            )
            self.assertEqual(
                [site.caller_start for site in candidate.call_sites],
                [CALLER_A, CALLER_B],
            )
        finally:
            view.file.close()

    def test_skips_targets_that_already_have_meaningful_names(self):
        view = self._new_view()
        try:
            helper = view.get_function_at(HELPER_TARGET)
            self.assertIsNotNone(helper)
            helper.name = "named_common_routine"
            view.update_analysis_and_wait()

            self.assertEqual(
                memory_map._raw_msp430_helper_candidates(
                    view,
                    min_call_sites=2,
                ),
                (),
            )
        finally:
            view.file.close()

    def test_report_includes_callers_and_editable_import_template(self):
        view = self._new_view()
        try:
            output = io.StringIO()
            with redirect_stdout(output):
                memory_map.report_raw_msp430_helper_candidates(
                    view,
                    min_call_sites=2,
                )

            text = output.getvalue()
            self.assertIn("raw MSP430 helper candidate", text)
            self.assertIn("0x000180", text)
            self.assertIn("calls=2", text)
            self.assertIn("0x000100", text)
            self.assertIn("0x000120", text)
            self.assertIn("valid __MSP430_* suffixes", text)
            self.assertIn("template: 0x000180 __MSP430_<helper_name>", text)
        finally:
            view.file.close()


if __name__ == "__main__":
    unittest.main()
