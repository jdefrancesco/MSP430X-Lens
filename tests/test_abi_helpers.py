import unittest
from contextlib import redirect_stdout
import io

from binaryninja import Architecture, BinaryView

import msp430f5438_memory_map as memory_map
import msp430x_arch  # noqa: F401


class AbiHelperMetadataTests(unittest.TestCase):
    def setUp(self):
        self.arch = Architecture["msp430x"]

    def _new_view_with_function(self, addr=0x100, code=b"\x30\x41"):
        backing = bytearray(b"\xff" * 0x200)
        backing[addr:addr + len(code)] = code
        view = BinaryView.new(bytes(backing))
        view.platform = self.arch.standalone_platform
        function = view.add_function(addr)
        self.assertIsNotNone(function)
        view.update_analysis_and_wait()
        return view, function

    def test_catalog_contains_all_pdf_helper_families_and_aliases(self):
        names = {
            definition.canonical_name
            for definition in memory_map.MSP430_ABI_HELPER_DEFINITIONS
        }

        self.assertIn("__mspabi_cvtdf", names)
        self.assertIn("__mspabi_cmpd", names)
        self.assertIn("__mspabi_mpyi", names)
        self.assertIn("__mspabi_divull", names)
        self.assertIn("__mspabi_srll_15", names)
        self.assertIn("__mspabi_func_epilog_7", names)
        self.assertIn("__mspabi_fpclassifyf", names)
        self.assertIn("_abort_msg", names)

        self.assertEqual(
            memory_map._abi_helper_definition_for_name("__MSP430_mpyi").canonical_name,
            "__mspabi_mpyi",
        )
        self.assertEqual(
            memory_map._abi_helper_definition_for_name("__mspabi_divllu").canonical_name,
            "__mspabi_divull",
        )
        for count in range(1, 16):
            self.assertIn(f"__mspabi_slli_{count}", names)
            self.assertIn(f"__mspabi_sral_{count}", names)

    def test_helper_catalog_report_includes_pdf_aliases_and_canonical_names(self):
        text = memory_map._format_msp430_abi_helper_catalog()

        self.assertIn("MSP430 ABI helper name catalog", text)
        self.assertIn("__MSP430_cvtdf", text)
        self.assertIn("__mspabi_cvtdf", text)
        self.assertIn("float32 __mspabi_cvtdf(float64 x)", text)
        self.assertIn("__MSP430_cmpd", text)
        self.assertIn("Double-precision comparison", text)
        self.assertIn("__MSP430_mpyi", text)

    def test_helper_catalog_report_prints_catalog(self):
        output = io.StringIO()
        with redirect_stdout(output):
            memory_map.report_msp430_abi_helper_names()

        text = output.getvalue()
        self.assertIn("__MSP430_cvtdf", text)
        self.assertIn("__mspabi_cvtdf", text)

    def test_alias_named_helper_is_renamed_typed_and_commented(self):
        view, function = self._new_view_with_function(code=b"\xff\x3f")  # jmp $
        try:
            function.name = "__MSP430_mpyi"

            self.assertEqual(
                memory_map._apply_msp430_abi_helper_metadata(view),
                1,
            )
            view.update_analysis_and_wait()

            function = view.get_function_at(0x100)
            self.assertEqual(function.name, "__mspabi_mpyi")
            self.assertEqual(function.type.parameters[0].name, "x")
            self.assertEqual(function.type.parameters[1].name, "y")
            self.assertIn(
                "Multiply int by int",
                view.get_comment_at(0x100),
            )
        finally:
            view.file.close()

    def test_special_two_64_helper_is_not_forced_to_wrong_type(self):
        view, function = self._new_view_with_function()
        try:
            original_type = str(function.type)
            function.name = "__mspabi_mpyll"

            self.assertEqual(
                memory_map._apply_msp430_abi_helper_metadata(view),
                1,
            )
            view.update_analysis_and_wait()

            function = view.get_function_at(0x100)
            self.assertEqual(function.name, "__mspabi_mpyll")
            self.assertEqual(str(function.type), original_type)
            self.assertIn(
                "R8::R11",
                view.get_comment_at(0x100),
            )
        finally:
            view.file.close()

    def test_abort_msg_is_marked_noreturn(self):
        view, function = self._new_view_with_function()
        try:
            function.name = "_abort_msg"

            self.assertEqual(
                memory_map._apply_msp430_abi_helper_metadata(view),
                1,
            )
            view.update_analysis_and_wait()

            function = view.get_function_at(0x100)
            self.assertFalse(function.can_return.value)
            self.assertEqual(function.type.parameters[0].name, "string")
        finally:
            view.file.close()

    def test_parse_helper_symbols_from_map_like_text(self):
        symbols = memory_map._parse_msp430_abi_helper_symbols(
            """
            00008c20 T __MSP430_mpyi
            0x08c22,__mspabi_divu
            .text.__mspabi_divllu 0x00008c24 0x00000020
            0x08c25 __mspabi_mpyi
            00008c28 ordinary_function
            00008c2a __mspabi_mpyi __mspabi_divu
            """
        )

        self.assertEqual(
            symbols,
            (
                ("__mspabi_mpyi", 0x8C20),
                ("__mspabi_divu", 0x8C22),
                ("__mspabi_divull", 0x8C24),
            ),
        )

    def test_import_helper_symbols_creates_function_and_applies_metadata(self):
        backing = bytearray(b"\xff" * 0x200)
        backing[0x100:0x102] = b"\x30\x41"  # ret
        view = BinaryView.new(bytes(backing))
        view.platform = self.arch.standalone_platform
        try:
            self.assertEqual(
                memory_map.import_msp430_abi_helper_symbols(
                    view,
                    text="0x0100 __MSP430_mpyi",
                    verbose=False,
                ),
                1,
            )
            view.update_analysis_and_wait()

            function = view.get_function_at(0x100)
            self.assertIsNotNone(function)
            self.assertEqual(function.name, "__mspabi_mpyi")
            self.assertEqual(function.type.parameters[0].name, "x")
            self.assertEqual(function.type.parameters[1].name, "y")
            self.assertIn(
                "Multiply int by int",
                view.get_comment_at(0x100),
            )
        finally:
            view.file.close()


if __name__ == "__main__":
    unittest.main()
