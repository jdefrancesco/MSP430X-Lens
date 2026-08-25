import unittest
from unittest.mock import patch

from binaryninja import SettingsScope

import msp430f5438_memory_map as memory_map
from tests.fixture_firmware import (
    EXACT_MIN_STRING,
    LONG_STRING,
    SHORT_JUNK_STRING,
)


class FakeSettings:
    def __init__(self, value, scope, inherited=None):
        self.value = value
        self.scope = scope
        self.inherited = inherited
        self.set_calls = []

    def get_integer_with_scope(self, key, resource, scope=None):
        if scope == SettingsScope.SettingsProjectScope and self.inherited is not None:
            return self.inherited
        return self.value, self.scope

    def set_integer(self, key, value, resource, scope):
        self.set_calls.append((key, value, resource, scope))
        self.value = value
        self.scope = scope
        return True


class AsciiStringTests(unittest.TestCase):
    def test_adjacent_aegis_strings_remain_separate_data_variables(self):
        base = 0x3091F
        command = b"get_version\x00"
        description = b"cmd get_version: request/response descriptor 15\x00"
        data = command + description
        description_start = base + len(command)
        expected = (
            (base, description_start),
            (description_start, base + len(data)),
        )

        with patch.object(
            memory_map,
            "_flash_backed_chunks",
            return_value=((base, data),),
        ):
            self.assertEqual(memory_map._flash_ascii_string_spans(object()), expected)

            class MockView:
                data_vars = {}

                def __init__(self):
                    self.definitions = []

                def get_data_var_at(self, _address):
                    return None

                def define_data_var(self, address, data_type, name):
                    self.definitions.append(
                        (address, getattr(data_type, "width", None), name)
                    )

            view = MockView()
            self.assertEqual(
                memory_map._define_ascii_string_data_vars(
                    view,
                    auto_defined=True,
                ),
                2,
            )

        self.assertEqual(
            view.definitions,
            [
                (base, len(command), f"str_{base:05x}"),
                (
                    description_start,
                    len(description),
                    f"str_{description_start:05x}",
                ),
            ],
        )

    def test_default_threshold_rejects_short_printable_noise(self):
        base = 0x6800

        self.assertEqual(memory_map.ASCII_STRING_MIN_LEN, 8)
        self.assertEqual(
            memory_map._ascii_string_spans(SHORT_JUNK_STRING, base),
            (),
        )
        self.assertEqual(
            memory_map._ascii_string_spans(
                SHORT_JUNK_STRING,
                base,
                min_len=5,
            ),
            ((base, base + len(SHORT_JUNK_STRING)),),
        )

    def test_default_threshold_keeps_boundary_and_long_strings(self):
        base = 0x6800
        separator = b"\xff"
        data = EXACT_MIN_STRING + separator + LONG_STRING
        long_start = base + len(EXACT_MIN_STRING) + len(separator)

        self.assertEqual(
            memory_map._ascii_string_spans(data, base),
            (
                (base, base + len(EXACT_MIN_STRING)),
                (long_start, long_start + len(LONG_STRING)),
            ),
        )

    def test_inherited_core_default_is_raised_for_the_new_view(self):
        view = object()
        settings = FakeSettings(4, SettingsScope.SettingsDefaultScope)

        with patch.object(memory_map, "Settings", return_value=settings):
            result = memory_map._configure_auto_string_minimum(view)

        self.assertEqual(result, 8)
        self.assertEqual(
            settings.set_calls,
            [
                (
                    memory_map.AUTO_STRING_MIN_LENGTH_SETTING,
                    8,
                    view,
                    SettingsScope.SettingsResourceScope,
                )
            ],
        )

    def test_explicit_core_string_minimum_is_preserved(self):
        view = object()
        for scope in (
            SettingsScope.SettingsUserScope,
            SettingsScope.SettingsProjectScope,
            SettingsScope.SettingsResourceScope,
        ):
            with self.subTest(scope=scope):
                settings = FakeSettings(5, scope)
                with patch.object(memory_map, "Settings", return_value=settings):
                    result = memory_map._configure_auto_string_minimum(view)

                self.assertEqual(result, 5)
                self.assertEqual(settings.set_calls, [])

    def test_elf_loader_snapshot_of_schema_default_is_raised(self):
        view = object()
        settings = FakeSettings(
            4,
            SettingsScope.SettingsResourceScope,
            inherited=(4, SettingsScope.SettingsDefaultScope),
        )

        with patch.object(memory_map, "Settings", return_value=settings):
            result = memory_map._configure_elf_auto_string_minimum(view)

        self.assertEqual(result, 8)
        self.assertEqual(
            settings.set_calls,
            [
                (
                    memory_map.AUTO_STRING_MIN_LENGTH_SETTING,
                    8,
                    view,
                    SettingsScope.SettingsResourceScope,
                )
            ],
        )

    def test_elf_explicit_string_minimums_are_preserved(self):
        view = object()
        cases = (
            # A Resource value distinct from the inherited default is an
            # explicit per-view override.
            (
                5,
                SettingsScope.SettingsResourceScope,
                (4, SettingsScope.SettingsDefaultScope),
            ),
            # An inherited User or Project value remains authoritative even
            # if ELF copied it into Resource scope.
            (
                5,
                SettingsScope.SettingsResourceScope,
                (5, SettingsScope.SettingsUserScope),
            ),
            (
                5,
                SettingsScope.SettingsResourceScope,
                (5, SettingsScope.SettingsProjectScope),
            ),
        )
        for value, scope, inherited in cases:
            with self.subTest(value=value, inherited_scope=inherited[1]):
                settings = FakeSettings(value, scope, inherited=inherited)
                with patch.object(memory_map, "Settings", return_value=settings):
                    result = memory_map._configure_elf_auto_string_minimum(view)
                self.assertEqual(result, value)
                self.assertEqual(settings.set_calls, [])


if __name__ == "__main__":
    unittest.main()
