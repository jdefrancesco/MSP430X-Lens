import threading
import types
import unittest
from unittest import mock

import msp430f5438_memory_map as memory_map


class UiAnalysisCommandTests(unittest.TestCase):
    def test_plugin_callback_dispatches_without_running_action_inline(self):
        view = object()
        action = mock.Mock()
        progress_text = "Refreshing MSP430X analysis"
        callback = memory_map._background_command(action, progress_text)

        with mock.patch.object(
            memory_map,
            "_run_background_analysis_command",
        ) as dispatch:
            self.assertIsNone(callback(view))

        action.assert_not_called()
        dispatch.assert_called_once_with(
            view,
            progress_text=progress_text,
            action=action,
        )

    def test_background_dispatch_starts_and_returns_task(self):
        view = object()
        action = mock.Mock()
        progress_text = "Refreshing MSP430X analysis"

        with mock.patch.object(memory_map, "_Msp430xCommandTask") as task_type:
            task = task_type.return_value
            result = memory_map._run_background_analysis_command(
                view,
                progress_text=progress_text,
                action=action,
            )

        task_type.assert_called_once_with(progress_text, action, view)
        task.start.assert_called_once_with()
        self.assertIs(result, task)

    def test_background_task_runs_off_the_calling_thread(self):
        calling_thread = threading.current_thread()
        action_threads = []

        task = memory_map._run_background_analysis_command(
            object(),
            progress_text="Refreshing MSP430X analysis",
            action=lambda _view: action_threads.append(threading.current_thread()),
        )
        task.join(timeout=5)

        self.assertFalse(task.thread.is_alive())
        self.assertEqual(len(action_threads), 1)
        self.assertIsNot(action_threads[0], calling_thread)

    def test_background_task_runs_action_and_contains_errors(self):
        view = object()
        action = mock.Mock(side_effect=RuntimeError("analysis failed"))
        task = memory_map._Msp430xCommandTask(
            "Refreshing MSP430X analysis",
            action,
            view,
        )
        self.addCleanup(task.finish)

        with mock.patch.object(
            memory_map,
            "log_error_for_exception",
        ) as log_error, mock.patch.object(
            memory_map,
            "_schedule_ui_view_refresh",
        ) as refresh:
            task.run()

        action.assert_called_once_with(view)
        log_error.assert_called_once_with("Refreshing MSP430X analysis failed")
        refresh.assert_not_called()

    def test_successful_background_task_schedules_ui_refresh(self):
        view = object()
        action = mock.Mock()
        task = memory_map._Msp430xCommandTask(
            "Refreshing MSP430X analysis",
            action,
            view,
        )
        self.addCleanup(task.finish)

        with mock.patch.object(
            memory_map,
            "_schedule_ui_view_refresh",
        ) as refresh:
            task.run()

        action.assert_called_once_with(view)
        refresh.assert_called_once_with(view)

    def test_headless_ui_refresh_is_not_scheduled(self):
        view = object()
        with mock.patch.object(
            memory_map,
            "core_ui_enabled",
            return_value=False,
        ), mock.patch.object(
            memory_map,
            "execute_on_main_thread",
        ) as execute:
            memory_map._schedule_ui_view_refresh(view)

        execute.assert_not_called()

    def test_ui_refresh_is_scheduled_on_main_thread(self):
        view = object()
        scheduled = []
        with mock.patch.object(
            memory_map,
            "core_ui_enabled",
            return_value=True,
        ), mock.patch.object(
            memory_map,
            "execute_on_main_thread",
            side_effect=lambda callback: scheduled.append(callback),
        ) as execute, mock.patch.object(
            memory_map,
            "_refresh_matching_ui_views",
        ) as refresh:
            memory_map._schedule_ui_view_refresh(view)
            execute.assert_called_once()
            self.assertEqual(len(scheduled), 1)
            refresh.assert_not_called()
            scheduled[0]()
            refresh.assert_called_once_with(view)

    def test_refresh_matching_ui_views_refreshes_only_matching_frames(self):
        target = mock.Mock()
        target.file.session_id = 41

        matching_bv = mock.Mock()
        matching_bv.file.session_id = 41
        other_bv = mock.Mock()
        other_bv.file.session_id = 99

        matching_view = mock.Mock()
        matching_frame = mock.Mock()
        matching_frame.getCurrentBinaryView.return_value = matching_bv
        matching_frame.getCurrentViewInterface.return_value = matching_view

        other_view = mock.Mock()
        other_frame = mock.Mock()
        other_frame.getCurrentBinaryView.return_value = other_bv
        other_frame.getCurrentViewInterface.return_value = other_view

        context = mock.Mock()
        tab = object()
        context.getTabs.return_value = [tab]
        context.getAllViewFramesForTab.return_value = [matching_frame, other_frame]
        ui_context = mock.Mock()
        ui_context.allContexts.return_value = [context]
        fake_ui_module = types.SimpleNamespace(UIContext=ui_context)

        with mock.patch.dict("sys.modules", {"binaryninjaui": fake_ui_module}):
            memory_map._refresh_matching_ui_views(target)

        matching_view.refreshContents.assert_called_once_with()
        other_view.refreshContents.assert_not_called()

    def test_analysis_update_is_a_synchronous_drain(self):
        view = mock.Mock()

        memory_map._update_analysis(view)

        view.update_analysis_and_wait.assert_called_once_with()
        view.update_analysis.assert_not_called()


if __name__ == "__main__":
    unittest.main()
