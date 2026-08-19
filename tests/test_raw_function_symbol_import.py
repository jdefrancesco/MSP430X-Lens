import unittest
import io
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

from binaryninja import Architecture, BinaryView

import msp430f5438_memory_map as memory_map
import msp430x_arch  # noqa: F401


class RawFunctionSymbolImportTests(unittest.TestCase):
    def setUp(self):
        self.arch = Architecture["msp430x"]

    def _new_view(self):
        backing = bytearray(b"\xff" * 0x300)
        backing[0x100:0x102] = b"\x30\x41"
        backing[0x120:0x122] = b"\x30\x41"
        view = BinaryView.new(bytes(backing))
        view.platform = self.arch.standalone_platform
        view.update_analysis_and_wait()
        return view

    def test_parse_raw_function_symbols_accepts_common_confirmed_formats(self):
        symbols = memory_map._parse_raw_msp430_function_symbols(
            """
            0x008c20 journal_append
            0000c100 T panic_or_abort
            .text.__MSP430_mpyi 0x0000a000 0x20
            #define WDTCTL_ 0x015c
            template: 0x000180 __mspabi_<helper_name>
            0x00b501 odd_function
            0x200000 too_far
            0x00c000 first_name second_name
            """
        )

        self.assertEqual(
            symbols,
            (
                ("journal_append", 0x8C20),
                ("panic_or_abort", 0xC100),
                ("__MSP430_mpyi", 0xA000),
            ),
        )

    def test_import_raw_function_symbols_names_functions_and_applies_abi_metadata(self):
        view = self._new_view()
        try:
            self.assertEqual(
                memory_map.import_raw_msp430_function_symbols(
                    view,
                    text="""
                    0x0100 journal_append
                    0x0120 __MSP430_mpyi
                    """,
                    verbose=False,
                ),
                2,
            )
            view.update_analysis_and_wait()

            journal = view.get_function_at(0x100)
            helper = view.get_function_at(0x120)
            self.assertIsNotNone(journal)
            self.assertIsNotNone(helper)
            self.assertEqual(journal.name, "journal_append")
            self.assertEqual(helper.name, "__mspabi_mpyi")
            self.assertEqual(helper.type.parameters[0].name, "x")
            self.assertEqual(helper.type.parameters[1].name, "y")
        finally:
            view.file.close()

    def test_import_raw_function_symbols_preserves_existing_meaningful_names(self):
        view = self._new_view()
        try:
            function = view.add_function(0x100)
            self.assertIsNotNone(function)
            function.name = "already_named"
            view.update_analysis_and_wait()

            self.assertEqual(
                memory_map.import_raw_msp430_function_symbols(
                    view,
                    text="0x0100 journal_append",
                    verbose=False,
                ),
                0,
            )
            self.assertEqual(view.get_function_at(0x100).name, "already_named")
        finally:
            view.file.close()

    def test_import_raw_function_symbols_explains_catalog_rows_are_not_mappings(self):
        view = self._new_view()
        try:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    memory_map.import_raw_msp430_function_symbols(
                        view,
                        text=(
                            "__MSP430_addd | __mspabi_addd | "
                            "float64 __mspabi_addd(float64 x, float64 y) | "
                            "Add double-precision to double-precision"
                        ),
                    ),
                    0,
                )

            text = output.getvalue()
            self.assertIn("No raw MSP430 function symbols were imported", text)
            self.assertIn("catalog rows are only a name reference", text)
            self.assertIn("0x008c20 __MSP430_mpyi", text)
        finally:
            view.file.close()

    def test_paste_prompt_imports_multiline_symbol_text(self):
        view = self._new_view()
        try:
            captured = {}

            class FakeMultilineTextField:
                def __init__(self, prompt, default=None):
                    captured["prompt"] = prompt
                    captured["default"] = default
                    self.result = "0x0100 journal_append\n0x0120 __MSP430_mpyi\n"

            def fake_get_form_input(fields, title):
                captured["title"] = title
                captured["field_count"] = len(fields)
                return True

            fake_interaction = SimpleNamespace(
                MultilineTextField=FakeMultilineTextField,
                get_form_input=fake_get_form_input,
            )
            with mock.patch.dict(
                "sys.modules", {"binaryninja.interaction": fake_interaction}
            ):
                memory_map.prompt_paste_raw_msp430_function_symbols(view)

            view.update_analysis_and_wait()
            self.assertEqual(
                captured,
                {
                    "prompt": "Raw MSP430 function symbols",
                    "default": memory_map.RAW_FUNCTION_SYMBOL_PASTE_EXAMPLE,
                    "title": "Paste Raw MSP430 Function Symbols",
                    "field_count": 1,
                },
            )
            self.assertEqual(view.get_function_at(0x100).name, "journal_append")
            self.assertEqual(view.get_function_at(0x120).name, "__mspabi_mpyi")
        finally:
            view.file.close()


if __name__ == "__main__":
    unittest.main()
