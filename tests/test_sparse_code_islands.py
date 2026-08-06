from types import SimpleNamespace
import unittest

import msp430f5438_memory_map as memory_map
from tests.fixture_firmware import SPARSE_FUNCTION


class MockView:
    def __init__(self, start, data):
        self._start = start
        self._data = data
        self.platform = object()
        self.functions = []
        self.data_vars = {}
        self.segments = [
            SimpleNamespace(
                start=start,
                end=start + len(data),
                data_length=len(data),
                executable=True,
            )
        ]

    def read(self, addr, length):
        offset = addr - self._start
        if offset < 0 or offset >= len(self._data):
            return b""
        return self._data[offset:offset + length]

    def add_function(self, addr):
        function = SimpleNamespace(start=addr)
        self.functions.append(function)
        return function


class SparseCodeIslandTests(unittest.TestCase):
    def test_mapped_raw_executable_chunk_is_seeded(self):
        view = MockView(0x60B00, SPARSE_FUNCTION)

        created = memory_map._seed_sparse_code_island_functions(view)

        self.assertEqual(created, 1)
        self.assertEqual([function.start for function in view.functions], [0x60B00])

    def test_sparse_elf_style_segment_is_seeded(self):
        segment_start = 0x60AE0
        data = b"\xff" * 0x20 + SPARSE_FUNCTION + b"\xff" * 0x40
        view = MockView(segment_start, data)

        created = memory_map._seed_sparse_code_island_functions(view)

        self.assertEqual(created, 1)
        self.assertEqual([function.start for function in view.functions], [0x60B00])

    def test_prologue_shaped_data_without_return_is_not_seeded(self):
        view = MockView(0x60B00, SPARSE_FUNCTION[:-2])

        created = memory_map._seed_sparse_code_island_functions(view)

        self.assertEqual(created, 0)
        self.assertEqual(view.functions, [])


if __name__ == "__main__":
    unittest.main()
