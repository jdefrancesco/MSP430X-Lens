import unittest
from unittest import mock

import msp430f5438_memory_map as memory_map


class _FakePlatform:
    name = "msp430x"

    def __str__(self):
        return self.name


class _FakeArchitecture:
    name = "msp430x"

    def __init__(self):
        self.standalone_platform = _FakePlatform()

    def __str__(self):
        return self.name


class _FakeView:
    def __init__(self):
        self.arch = None
        self.platform = None


class PlatformAssignmentTests(unittest.TestCase):
    def test_binary_ninja_6_sets_default_platform(self):
        view = _FakeView()
        arch = _FakeArchitecture()

        with mock.patch.object(
            memory_map,
            "_find_msp430_arch",
            return_value=arch,
        ), mock.patch.object(
            memory_map,
            "core_version",
            return_value="6.0.10601 ultimate",
        ):
            selected_arch = memory_map._configure_architecture(
                view,
                "msp430x",
                verbose=False,
                set_platform=True,
            )

        self.assertIs(selected_arch, arch)
        self.assertIs(view.arch, arch)
        self.assertIs(view.platform, arch.standalone_platform)

    def test_binary_ninja_5_4_skips_default_platform_assignment(self):
        view = _FakeView()
        arch = _FakeArchitecture()

        with mock.patch.object(
            memory_map,
            "_find_msp430_arch",
            return_value=arch,
        ), mock.patch.object(
            memory_map,
            "core_version",
            return_value="5.4.9000-dev",
        ):
            selected_arch = memory_map._configure_architecture(
                view,
                "msp430x",
                verbose=False,
                set_platform=True,
            )

        self.assertIs(selected_arch, arch)
        self.assertIs(view.arch, arch)
        self.assertIsNone(view.platform)


if __name__ == "__main__":
    unittest.main()
