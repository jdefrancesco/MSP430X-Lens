import unittest

from binaryninja import Architecture, BinaryView, Type

import msp430f5438_memory_map as memory_map
import msp430x_arch  # noqa: F401


HEADER_TEXT = """
#define DMACTL0_ 0x0500
sfrb(DMACTL0_L, DMACTL0_);
sfrb(DMACTL0_H, DMACTL0_ + 1);
sfrw(DMACTL0, DMACTL0_);

#define DMA0SA_ 0x0512
sfra(DMA0SA, DMA0SA_);

#define PAIN_ 0x0200
const_sfrb(PAIN_L, PAIN_);
const_sfrb(PAIN_H, PAIN_ + 1);
const_sfrw(PAIN, PAIN_);
"""


class HeaderSfrTests(unittest.TestCase):
    @staticmethod
    def _hlil_text(function):
        return "\n".join(
            str(instruction)
            for block in function.hlil
            for instruction in block
        )

    def test_parser_preserves_sfr_width_and_read_only_qualifier(self):
        labels, sfrs = memory_map._parse_msp430_header_definitions(
            [HEADER_TEXT]
        )
        labels_by_name = dict(labels)
        sfrs_by_name = {definition.name: definition for definition in sfrs}

        self.assertEqual(labels_by_name["DMACTL0"], 0x0500)
        self.assertEqual(labels_by_name["DMACTL0_L"], 0x0500)
        self.assertEqual(labels_by_name["DMACTL0_H"], 0x0501)
        self.assertEqual(labels_by_name["DMA0SA"], 0x0512)
        self.assertEqual(sfrs_by_name["DMACTL0_L"].width, 1)
        self.assertEqual(sfrs_by_name["DMACTL0"].width, 2)
        self.assertEqual(sfrs_by_name["DMA0SA"].width, 4)
        self.assertFalse(sfrs_by_name["DMACTL0"].read_only)
        self.assertTrue(sfrs_by_name["PAIN"].read_only)

    def test_sfr_data_vars_are_volatile_and_canonicalize_overlaps(self):
        _labels, sfrs = memory_map._parse_msp430_header_definitions(
            [HEADER_TEXT]
        )
        view = BinaryView.new(b"\0" * 0x1000)
        try:
            first_count = memory_map._define_header_sfr_data_vars(
                view,
                sfrs,
                auto_defined=True,
            )
            self.assertGreater(first_count, 0)

            dmactl0 = view.get_data_var_at(0x0500)
            self.assertIsNotNone(dmactl0)
            self.assertEqual(dmactl0.address, 0x0500)
            self.assertEqual(dmactl0.type.width, 2)
            self.assertTrue(dmactl0.type.volatile.value)
            self.assertFalse(dmactl0.type.const.value)

            # The high-byte alias remains covered by the canonical word data
            # variable instead of replacing it with an overlapping byte var.
            dmactl0_high = view.get_data_var_at(0x0501)
            self.assertIsNotNone(dmactl0_high)
            self.assertEqual(dmactl0_high.address, 0x0500)
            self.assertEqual(dmactl0_high.type.width, 2)

            dma0sa = view.get_data_var_at(0x0512)
            self.assertIsNotNone(dma0sa)
            self.assertEqual(dma0sa.type.width, 4)
            self.assertTrue(dma0sa.type.volatile.value)

            pain = view.get_data_var_at(0x0200)
            self.assertIsNotNone(pain)
            self.assertEqual(pain.type.width, 2)
            self.assertTrue(pain.type.volatile.value)
            self.assertTrue(pain.type.const.value)

            self.assertEqual(
                memory_map._define_header_sfr_data_vars(
                    view,
                    sfrs,
                    auto_defined=True,
                ),
                0,
            )
        finally:
            view.file.close()

    def test_sfr_data_vars_do_not_replace_user_types(self):
        _labels, sfrs = memory_map._parse_msp430_header_definitions(
            [HEADER_TEXT]
        )
        view = BinaryView.new(b"\0" * 0x1000)
        try:
            custom_type = Type.array(Type.int(1, False), 2)
            view.define_user_data_var(0x0500, custom_type, "custom_dma")

            memory_map._define_header_sfr_data_vars(
                view,
                sfrs,
                auto_defined=True,
            )

            preserved = view.get_data_var_at(0x0500)
            self.assertIsNotNone(preserved)
            self.assertFalse(preserved.auto_discovered)
            self.assertEqual(str(preserved.type), str(custom_type))
            self.assertEqual(preserved.name, "custom_dma")
        finally:
            view.file.close()

    def test_sfr_data_vars_upgrade_auto_inferred_types(self):
        _labels, sfrs = memory_map._parse_msp430_header_definitions(
            [HEADER_TEXT]
        )
        view = BinaryView.new(b"\0" * 0x1000)
        try:
            view.define_data_var(0x0500, Type.int(2, True), "data_500")
            inferred = view.get_data_var_at(0x0500)
            self.assertIsNotNone(inferred)
            self.assertTrue(inferred.auto_discovered)
            self.assertFalse(inferred.type.volatile.value)

            self.assertGreater(
                memory_map._define_header_sfr_data_vars(
                    view,
                    sfrs,
                    auto_defined=True,
                ),
                0,
            )

            upgraded = view.get_data_var_at(0x0500)
            self.assertIsNotNone(upgraded)
            self.assertTrue(upgraded.auto_discovered)
            self.assertEqual(upgraded.type.width, 2)
            self.assertTrue(upgraded.type.volatile.value)
        finally:
            view.file.close()

    def test_late_sfr_upgrade_rebuilds_existing_il_as_side_effecting_read(self):
        # push r12; mov &0x500,r12; pop r12; ret
        code = bytes.fromhex("0c 12 1c 42 00 05 3c 41 30 41")
        backing = bytearray(b"\0" * 0x1000)
        backing[:len(code)] = code
        view = BinaryView.new(bytes(backing))
        try:
            view.platform = Architecture["msp430x"].standalone_platform
            view.define_data_var(0x0500, Type.int(2, False), "data_500")
            function = view.add_function(0)
            self.assertIsNotNone(function)
            view.update_analysis_and_wait()
            self.assertNotIn("mmio_read", self._hlil_text(function))

            _labels, sfrs = memory_map._parse_msp430_header_definitions(
                [HEADER_TEXT]
            )
            self.assertGreater(
                memory_map._define_header_sfr_data_vars(
                    view,
                    sfrs,
                    auto_defined=True,
                ),
                0,
            )
            view.update_analysis_and_wait()

            refreshed = view.get_function_at(0)
            self.assertIsNotNone(refreshed)
            refreshed_hlil = self._hlil_text(refreshed)
            self.assertIn("mmio_read16", refreshed_hlil)
            self.assertIn("DMACTL0", refreshed_hlil)
        finally:
            view.file.close()


if __name__ == "__main__":
    unittest.main()
