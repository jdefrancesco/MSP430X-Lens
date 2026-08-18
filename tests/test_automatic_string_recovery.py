import unittest
from unittest import mock

from binaryninja import BinaryViewType

import msp430f5438_memory_map as memory_map


class _FakeView:
    def __init__(
        self,
        view_type,
        *,
        arch="msp430x",
        elf_prepared=False,
        has_database=False,
        executable=True,
        relocatable=False,
    ):
        self.view_type = view_type
        self.arch = arch
        self._elf_prepared = elf_prepared
        self.has_database = has_database
        self.executable = executable
        self.relocatable = relocatable

    def query_metadata(self, key):
        if key == memory_map.ELF_PREPARED_METADATA_KEY and self._elf_prepared:
            return True
        raise KeyError(key)


class AutomaticStringRecoveryTests(unittest.TestCase):
    def test_automatic_recovery_accepts_plugin_mapped_raw_view(self):
        view = _FakeView("MSP430F5438")

        self.assertTrue(memory_map._is_automatic_string_recovery_view(view))

    def test_automatic_recovery_accepts_prepared_msp430x_elf(self):
        view = _FakeView("ELF", elf_prepared=True)

        self.assertTrue(memory_map._is_automatic_string_recovery_view(view))

    def test_automatic_recovery_accepts_reopened_executable_elf_database(self):
        view = _FakeView("ELF", has_database=True)

        self.assertTrue(memory_map._is_automatic_string_recovery_view(view))

    def test_automatic_recovery_rejects_unowned_or_wrong_architecture_views(self):
        views = (
            _FakeView("Raw"),
            _FakeView("ELF"),
            _FakeView("ELF", has_database=True, executable=False),
            _FakeView("ELF", has_database=True, relocatable=True),
            _FakeView("MSP430F5438", arch="msp430"),
            _FakeView("ELF", arch="msp430", elf_prepared=True),
        )

        for view in views:
            with self.subTest(view_type=view.view_type, arch=view.arch):
                self.assertFalse(
                    memory_map._is_automatic_string_recovery_view(view)
                )

    def test_initial_analysis_callback_only_dispatches_background_work(self):
        view = _FakeView("MSP430F5438")

        with mock.patch.object(
            memory_map,
            "_run_automatic_string_call_recovery",
        ) as action, mock.patch.object(
            memory_map,
            "_run_background_analysis_command",
        ) as dispatch, mock.patch.object(
            memory_map,
            "_update_analysis",
        ) as update:
            memory_map._schedule_automatic_string_call_recovery(view)

        action.assert_not_called()
        update.assert_not_called()
        dispatch.assert_called_once()
        args, kwargs = dispatch.call_args
        self.assertEqual(args, (view,))
        self.assertIs(kwargs["action"], action)
        self.assertIn("R12", kwargs["progress_text"])

    def test_initial_analysis_callback_ignores_unrelated_view(self):
        view = _FakeView("Raw")

        with mock.patch.object(
            memory_map,
            "_run_background_analysis_command",
        ) as dispatch:
            memory_map._schedule_automatic_string_call_recovery(view)

        dispatch.assert_not_called()

    def test_background_action_uses_only_bounded_string_recovery(self):
        view = object()

        with mock.patch.object(
            memory_map,
            "_stabilize_direct_string_call_parameters",
            return_value=(3, 0),
        ) as stabilize, mock.patch.object(
            memory_map,
            "_refresh_msp430x_analysis",
        ) as full_refresh:
            memory_map._run_automatic_string_call_recovery(view)

        stabilize.assert_called_once()
        self.assertIs(stabilize.call_args.args[0], view)
        full_refresh.assert_not_called()

    def test_initial_analysis_callback_registration_is_process_wide_and_once(self):
        marker = memory_map._AUTO_STRING_RECOVERY_MARKER

        with mock.patch.object(
            BinaryViewType,
            marker,
            False,
        ), mock.patch.object(
            BinaryViewType,
            "add_binaryview_initial_analysis_completion_event",
        ) as add_event:
            memory_map._register_automatic_string_call_recovery()
            memory_map._register_automatic_string_call_recovery()

        add_event.assert_called_once_with(
            memory_map._schedule_automatic_string_call_recovery
        )


if __name__ == "__main__":
    unittest.main()
