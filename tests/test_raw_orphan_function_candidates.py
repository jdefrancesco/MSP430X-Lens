import io
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

from binaryninja import BinaryView, BinaryViewType

import msp430f5438_memory_map as memory_map
from tests.fixture_firmware import (
    HIGH_BANK_LOOKUP_TABLE,
    HIGH_BANK_LOOKUP_TABLE_ADDRESS,
    HIGH_BANK_ORPHAN_FUNCTION,
    HIGH_BANK_ORPHAN_FUNCTION_ADDRESS,
    HIGH_BANK_PROLOGUE_DATA,
    HIGH_BANK_PROLOGUE_DATA_ADDRESS,
    HIGH_BANK_STRING,
    HIGH_BANK_STRING_ADDRESS,
    build_high_bank_raw_firmware,
)


class RawOrphanFunctionCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = BinaryView.new(build_high_bank_raw_firmware())
        view_type = BinaryViewType[memory_map.MSP430F5438BinaryView.name]
        if not view_type.is_valid_for_data(cls.raw):
            cls.raw.file.close()
            raise AssertionError("high-bank fixture was not accepted by the raw loader")
        with mock.patch.object(
            memory_map,
            "_run_background_analysis_command",
            return_value=None,
        ):
            cls.view = view_type.create(cls.raw)
            if cls.view is None:
                cls.raw.file.close()
                raise AssertionError("raw loader did not create the high-bank view")
            cls.view.update_analysis_and_wait()
            recovered = memory_map._seed_referenced_address_word_targets(
                cls.view,
                verbose=False,
            )
            if recovered != (1, 1, 1):
                cls.raw.file.close()
                raise AssertionError(
                    f"address-word fixture recovery was {recovered!r}, "
                    "expected (1, 1, 1)"
                )
            cls.view.update_analysis_and_wait()

    @classmethod
    def tearDownClass(cls):
        cls.raw.file.close()

    def test_fixture_has_exact_code_and_data_discriminators(self):
        self.assertEqual(
            bytes(
                self.view.read(
                    HIGH_BANK_ORPHAN_FUNCTION_ADDRESS,
                    len(HIGH_BANK_ORPHAN_FUNCTION),
                )
            ),
            HIGH_BANK_ORPHAN_FUNCTION,
        )
        routine = memory_map._decode_msp430_routine(
            HIGH_BANK_ORPHAN_FUNCTION,
            HIGH_BANK_ORPHAN_FUNCTION_ADDRESS,
        )
        self.assertIsNotNone(routine)
        self.assertEqual(routine.length, len(HIGH_BANK_ORPHAN_FUNCTION))
        self.assertEqual(routine.termination_kind, "reta")
        self.assertEqual(routine.instruction_count, 7)
        nested_routine = memory_map._decode_msp430_routine(
            HIGH_BANK_ORPHAN_FUNCTION[2:],
            HIGH_BANK_ORPHAN_FUNCTION_ADDRESS + 2,
        )
        self.assertIsNotNone(nested_routine)
        self.assertEqual(nested_routine.termination_kind, "reta")
        self.assertEqual(
            nested_routine.length,
            len(HIGH_BANK_ORPHAN_FUNCTION) - 2,
        )

        self.assertEqual(
            bytes(
                self.view.read(
                    HIGH_BANK_STRING_ADDRESS,
                    len(HIGH_BANK_STRING),
                )
            ),
            HIGH_BANK_STRING,
        )
        self.assertTrue(HIGH_BANK_STRING[:-1].decode("ascii").isprintable())
        self.assertEqual(
            bytes(
                self.view.read(
                    HIGH_BANK_LOOKUP_TABLE_ADDRESS,
                    len(HIGH_BANK_LOOKUP_TABLE),
                )
            ),
            HIGH_BANK_LOOKUP_TABLE,
        )
        self.assertEqual(HIGH_BANK_LOOKUP_TABLE, bytes(range(0x20)))

        ambiguous = memory_map._decode_msp430_routine(
            HIGH_BANK_PROLOGUE_DATA,
            HIGH_BANK_PROLOGUE_DATA_ADDRESS,
        )
        self.assertIsNotNone(ambiguous)
        self.assertEqual(ambiguous.termination_kind, "ret")

    def test_reports_strong_orphan_without_promoting_strings_or_tables(self):
        candidates = memory_map._raw_orphan_function_candidates(self.view)
        by_address = {candidate.address: candidate for candidate in candidates}

        self.assertIn(HIGH_BANK_ORPHAN_FUNCTION_ADDRESS, by_address)
        candidate = by_address[HIGH_BANK_ORPHAN_FUNCTION_ADDRESS]
        self.assertEqual(candidate.length, len(HIGH_BANK_ORPHAN_FUNCTION))
        self.assertEqual(candidate.termination_kind, "reta")
        self.assertEqual(candidate.instruction_count, 7)
        self.assertEqual(candidate.confidence, "strong")
        self.assertTrue(candidate.reasons)
        self.assertEqual(candidates[0].address, HIGH_BANK_ORPHAN_FUNCTION_ADDRESS)
        self.assertFalse(
            any(
                HIGH_BANK_ORPHAN_FUNCTION_ADDRESS < other.address
                < HIGH_BANK_ORPHAN_FUNCTION_ADDRESS + len(HIGH_BANK_ORPHAN_FUNCTION)
                for other in candidates
            ),
            "a prologue-shaped instruction inside the routine was reported twice",
        )
        self.assertEqual(
            memory_map._raw_orphan_function_candidates(self.view, max_results=1),
            (candidate,),
        )
        self.assertEqual(
            memory_map._raw_orphan_function_candidates(self.view, max_results=0.5),
            (),
        )

        excluded_ranges = (
            (
                HIGH_BANK_STRING_ADDRESS,
                HIGH_BANK_STRING_ADDRESS + len(HIGH_BANK_STRING),
            ),
            (
                HIGH_BANK_LOOKUP_TABLE_ADDRESS,
                HIGH_BANK_LOOKUP_TABLE_ADDRESS + len(HIGH_BANK_LOOKUP_TABLE),
            ),
        )
        for candidate in candidates:
            self.assertFalse(
                any(
                    candidate.address < end
                    and start < candidate.address + candidate.length
                    for start, end in excluded_ranges
                ),
                f"classified data was reported as code at {candidate.address:#x}",
            )

        ambiguous = by_address.get(HIGH_BANK_PROLOGUE_DATA_ADDRESS)
        self.assertIsNotNone(ambiguous)
        self.assertEqual(ambiguous.confidence, "ambiguous")
        self.assertTrue(ambiguous.reasons)

        self.assertIsNone(
            self.view.get_function_at(HIGH_BANK_ORPHAN_FUNCTION_ADDRESS)
        )
        self.assertIsNone(
            self.view.get_function_at(HIGH_BANK_PROLOGUE_DATA_ADDRESS)
        )

    def test_text_report_is_read_only(self):
        sentinel_key = "msp430xLens.tests.orphanReadOnlySentinel"
        sentinel_value = {"preserve": [0x11700, "unchanged"]}
        self.view.store_metadata(sentinel_key, sentinel_value, isAuto=False)
        function_state = tuple(
            sorted((function.start, function.name) for function in self.view.functions)
        )
        data_state = tuple(sorted(int(address) for address in self.view.data_vars))
        symbol_state = tuple(
            sorted(
                (symbol.address, symbol.name, str(symbol.type))
                for symbol in self.view.get_symbols()
            )
        )
        comments = {
            address: self.view.get_comment_at(address)
            for address in (
                HIGH_BANK_ORPHAN_FUNCTION_ADDRESS,
                HIGH_BANK_PROLOGUE_DATA_ADDRESS,
                HIGH_BANK_STRING_ADDRESS,
                HIGH_BANK_LOOKUP_TABLE_ADDRESS,
            )
        }
        segment_state = tuple(
            (
                segment.start,
                segment.end,
                segment.data_offset,
                segment.data_length,
                segment.readable,
                segment.writable,
                segment.executable,
            )
            for segment in self.view.segments
        )
        section_state = tuple(
            sorted(
                (
                    name,
                    section.start,
                    section.end,
                    str(section.semantics),
                )
                for name, section in self.view.sections.items()
            )
        )
        profile_state = (
            getattr(self.view, "spec", None),
            self.view.query_metadata(memory_map.DEVICE_VARIANT_METADATA_KEY),
        )
        backing_state = bytes(
            self.view.read(self.view.start, self.view.end - self.view.start)
        )

        outputs = []
        with mock.patch.object(
            memory_map,
            "_update_analysis",
            side_effect=AssertionError("read-only report must not update analysis"),
        ):
            for _pass in range(2):
                output = io.StringIO()
                with redirect_stdout(output):
                    memory_map.report_raw_orphan_function_candidates(self.view)
                outputs.append(output.getvalue())

        self.assertEqual(outputs[0], outputs[1])
        self.assertIn("orphan", outputs[0].lower())
        self.assertIn("11700", outputs[0])
        self.assertIn("<confirmed_function_name>", outputs[0])
        self.assertEqual(
            memory_map._parse_raw_msp430_function_symbols(outputs[0]),
            (),
            "unedited report templates must not create functions",
        )
        template = next(
            line.strip()
            for line in outputs[0].splitlines()
            if line.strip().endswith("<confirmed_function_name>")
        )
        self.assertEqual(
            memory_map._parse_raw_msp430_function_symbols(
                template.replace("<confirmed_function_name>", "confirmed_orphan")
            ),
            (("confirmed_orphan", HIGH_BANK_ORPHAN_FUNCTION_ADDRESS),),
        )

        limited_output = io.StringIO()
        with redirect_stdout(limited_output):
            memory_map.report_raw_orphan_function_candidates(
                self.view,
                max_results=1,
            )
        self.assertIn("additional candidates were omitted", limited_output.getvalue())
        self.assertEqual(
            tuple(
                sorted((function.start, function.name) for function in self.view.functions)
            ),
            function_state,
        )
        self.assertEqual(
            tuple(sorted(int(address) for address in self.view.data_vars)),
            data_state,
        )
        self.assertEqual(
            tuple(
                sorted(
                    (symbol.address, symbol.name, str(symbol.type))
                    for symbol in self.view.get_symbols()
                )
            ),
            symbol_state,
        )
        self.assertEqual(
            {
                address: self.view.get_comment_at(address)
                for address in comments
            },
            comments,
        )
        self.assertEqual(
            tuple(
                (
                    segment.start,
                    segment.end,
                    segment.data_offset,
                    segment.data_length,
                    segment.readable,
                    segment.writable,
                    segment.executable,
                )
                for segment in self.view.segments
            ),
            segment_state,
        )
        self.assertEqual(
            tuple(
                sorted(
                    (
                        name,
                        section.start,
                        section.end,
                        str(section.semantics),
                    )
                    for name, section in self.view.sections.items()
                )
            ),
            section_state,
        )
        self.assertEqual(
            (
                getattr(self.view, "spec", None),
                self.view.query_metadata(memory_map.DEVICE_VARIANT_METADATA_KEY),
            ),
            profile_state,
        )
        self.assertEqual(
            bytes(self.view.read(self.view.start, self.view.end - self.view.start)),
            backing_state,
        )
        self.assertEqual(self.view.query_metadata(sentinel_key), sentinel_value)

    def test_profile_fallback_does_not_persist_metadata(self):
        class BareMappedView:
            view_type = SimpleNamespace(name="MSP430F5438")

            def __init__(self):
                self.metadata_writes = []

            def query_metadata(self, _key):
                return None

            def store_metadata(self, *args, **kwargs):
                self.metadata_writes.append((args, kwargs))

        view = BareMappedView()
        with mock.patch.object(
            memory_map,
            "_device_spec_for_view",
            side_effect=AssertionError("read-only selection must not detect a profile"),
        ):
            self.assertIs(
                memory_map._selected_device_spec_read_only(view),
                memory_map.DEFAULT_DEVICE_SPEC,
            )

        self.assertFalse(hasattr(view, "spec"))
        self.assertEqual(view.metadata_writes, [])


if __name__ == "__main__":
    unittest.main()
