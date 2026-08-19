import unittest

from binaryninja import Architecture, BinaryView, Type

import msp430f5438_memory_map as memory_map
import msp430x_arch  # noqa: F401


HEADER_TEXT = """
#define WDTCTL_ 0x015C
sfrb(WDTCTL_L, WDTCTL_);
sfrb(WDTCTL_H, WDTCTL_ + 1);
sfrw(WDTCTL, WDTCTL_);
/* WDTCTL Control Bits */
#define WDTIS0              (0x0001)  /* WDT - Timer Interval Select 0 */
#define WDTIS1              (0x0002)  /* WDT - Timer Interval Select 1 */
#define WDTIS2              (0x0004)  /* WDT - Timer Interval Select 2 */
#define WDTCNTCL            (0x0008)  /* WDT - Timer Clear */
#define WDTTMSEL            (0x0010)  /* WDT - Timer Mode Select */
#define WDTSSEL0            (0x0020)  /* WDT - Timer Clock Source Select 0 */
#define WDTSSEL1            (0x0040)  /* WDT - Timer Clock Source Select 1 */
#define WDTHOLD             (0x0080)  /* WDT - Timer hold */
/* WDTCTL Control Bits */
#define WDTIS0_L            (0x0001)  /* WDT - Timer Interval Select 0 */
#define WDTHOLD_L           (0x0080)  /* WDT - Timer hold */
#define WDTPW               (0x5A00)
#define WDTIS_0             (0x0000)  /* WDT - Timer Interval Select: /2G */
#define WDTIS_1             (0x0001)  /* WDT - Timer Interval Select: /128M */
#define WDTIS__128M         (0x0001)  /* WDT - Timer Interval Select: /128M */
#define WDTSSEL_1           (0x0020)  /* WDT - Timer Clock Source Select: ACLK */
#define WDTSSEL__ACLK       (0x0020)  /* WDT - Timer Clock Source Select: ACLK */
/* WDT-interval times [1ms] coded with Bits 0-2 */
#define WDT_MDLY_32         (WDTPW+WDTTMSEL+WDTCNTCL+WDTIS2)

#define TA0CTL_ 0x0340
sfrw(TA0CTL, TA0CTL_);
#define TA1CTL_ 0x0380
sfrw(TA1CTL, TA1CTL_);
/* TAxCTL Control Bits */
#define TASSEL1             (0x0200)  /* Timer A clock source select 1 */
#define TASSEL0             (0x0100)  /* Timer A clock source select 0 */
#define MC1                 (0x0020)  /* Timer A mode control 1 */
#define MC0                 (0x0010)  /* Timer A mode control 0 */
#define MC_1                (0x0010)  /* Timer A mode control: 1 - Up */
#define TASSEL__SMCLK       (0x0200)  /* Timer A clock source select: SMCLK */

#define ADC12MCTL0_ 0x0710
sfrb(ADC12MCTL0, ADC12MCTL0_);
#define ADC12MCTL1_ 0x0711
sfrb(ADC12MCTL1, ADC12MCTL1_);
/* ADC12MCTLx Control Bits */
#define ADC12INCH0          (0x0001)  /* ADC12 Input Channel Select Bit 0 */
#define ADC12EOS            (0x0080)  /* ADC12 End of Sequence */
#define ADC12INCH_15        (0x000F)  /* ADC12 Input Channel 15 */

#define PMMRIE_ 0x012E
sfrb(PMMRIE_L, PMMRIE_);
sfrb(PMMRIE_H, PMMRIE_ + 1);
sfrw(PMMRIE, PMMRIE_);
/* PMMIE and RESET Control Bits */
#define SVSMLDLYIE          (0x0001)  /* SVS and SVM low side Delay expired interrupt enable */
#define SVSLPE              (0x0100)  /* SVS low side POR enable */

#define UCA0CTLW0_ 0x05C0
sfrb(UCA0CTLW0_L, UCA0CTLW0_);
sfrb(UCA0CTLW0_H, UCA0CTLW0_ + 1);
sfrw(UCA0CTLW0, UCA0CTLW0_);
#define UCA0CTL1 UCA0CTLW0_L
#define UCA0CTL0 UCA0CTLW0_H
// UCAxCTL0 UART-Mode Control Bits
#define UCPEN               (0x80)    /* Async. Mode: Parity enable */
#define UCMODE_3            (0x06)    /* Sync. Mode: USCI Mode: 3 */
// UCAxCTL1 UART-Mode Control Bits
#define UCSWRST             (0x01)    /* USCI Software Reset */
#define UCSSEL_2            (0x80)    /* USCI 0 Clock Source: 2 */

#define UCA0ICTL_ 0x05DC
sfrb(UCA0ICTL_L, UCA0ICTL_);
sfrb(UCA0ICTL_H, UCA0ICTL_ + 1);
sfrw(UCA0ICTL, UCA0ICTL_);
#define UCA0IE UCA0ICTL_L
#define UCA0IFG UCA0ICTL_H
/* UCAxIE Control Bits */
#define UCTXIE              (0x0002)  /* USCI Transmit Interrupt Enable */
#define UCRXIE              (0x0001)  /* USCI Receive Interrupt Enable */
/* UCAxIFG Control Bits */
#define UCTXIFG             (0x0002)  /* USCI Transmit Interrupt Flag */
#define UCRXIFG             (0x0001)  /* USCI Receive Interrupt Flag */
#define UCA0IV_ 0x05DE
sfrw(UCA0IV, UCA0IV_);

#define DMACTL0_ 0x0500
sfrb(DMACTL0_L, DMACTL0_);
sfrb(DMACTL0_H, DMACTL0_ + 1);
sfrw(DMACTL0, DMACTL0_);

#define DMA0SA_ 0x0512
sfra(DMA0SA, DMA0SA_);
#define DMA0DA_ 0x0516
sfrl(DMA0DA, DMA0DA_);
#define DMA1SA_ 0x0522
sfr_a(DMA1SA);
#define DMA1DA_ 0x0526
sfr_l(DMA1DA);

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
        self.assertEqual(labels_by_name["DMA0DA"], 0x0516)
        self.assertEqual(labels_by_name["DMA1SA"], 0x0522)
        self.assertEqual(labels_by_name["DMA1DA"], 0x0526)
        self.assertEqual(labels_by_name["WDTCTL"], 0x015C)
        self.assertEqual(sfrs_by_name["DMACTL0_L"].width, 1)
        self.assertEqual(sfrs_by_name["DMACTL0"].width, 2)
        self.assertEqual(sfrs_by_name["DMA0SA"].width, 4)
        self.assertEqual(sfrs_by_name["DMA0DA"].width, 4)
        self.assertEqual(sfrs_by_name["DMA1SA"].width, 4)
        self.assertEqual(sfrs_by_name["DMA1DA"].width, 4)
        self.assertFalse(sfrs_by_name["DMACTL0"].read_only)
        self.assertTrue(sfrs_by_name["PAIN"].read_only)
        self.assertIn(("WDTHOLD", 0x0080), sfrs_by_name["WDTCTL"].enum_members)
        self.assertIn(("WDTPW", 0x5A00), sfrs_by_name["WDTCTL"].enum_members)
        self.assertIn(("WDT_MDLY_32", 0x5A1C), sfrs_by_name["WDTCTL"].enum_members)
        self.assertNotIn(("WDTHOLD_L", 0x0080), sfrs_by_name["WDTCTL"].enum_members)
        self.assertIn(("MC_1", 0x0010), sfrs_by_name["TA0CTL"].enum_members)
        self.assertIn(("MC_1", 0x0010), sfrs_by_name["TA1CTL"].enum_members)
        self.assertIn(("ADC12EOS", 0x0080), sfrs_by_name["ADC12MCTL0"].enum_members)
        self.assertIn(("ADC12EOS", 0x0080), sfrs_by_name["ADC12MCTL1"].enum_members)
        self.assertIn(("SVSLPE", 0x0100), sfrs_by_name["PMMRIE"].enum_members)
        self.assertIn(("UCPEN", 0x8000), sfrs_by_name["UCA0CTLW0"].enum_members)
        self.assertIn(("UCSWRST", 0x0001), sfrs_by_name["UCA0CTLW0"].enum_members)
        self.assertIn(("UCTXIE", 0x0002), sfrs_by_name["UCA0ICTL"].enum_members)
        self.assertIn(("UCTXIFG", 0x0200), sfrs_by_name["UCA0ICTL"].enum_members)

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

    def test_sfr_data_vars_use_registered_bit_enums_when_available(self):
        _labels, sfrs = memory_map._parse_msp430_header_definitions(
            [HEADER_TEXT]
        )
        view = BinaryView.new(b"\0" * 0x1000)
        try:
            self.assertGreater(
                memory_map._define_header_sfr_data_vars(
                    view,
                    sfrs,
                    auto_defined=True,
                ),
                0,
            )

            wdtctl = view.get_data_var_at(0x015C)
            self.assertIsNotNone(wdtctl)
            self.assertEqual(wdtctl.type.width, 2)
            self.assertTrue(wdtctl.type.volatile.value)
            self.assertIn("WDTCTL_bits", str(wdtctl.type))

            enum_type = view.get_type_by_name("WDTCTL_bits")
            self.assertIsNotNone(enum_type)
            enum_members = {
                member.name: member.value
                for member in enum_type.members
            }
            self.assertEqual(enum_members["WDTHOLD"], 0x0080)
            self.assertEqual(enum_members["WDTPW"], 0x5A00)
            self.assertEqual(enum_members["WDT_MDLY_32"], 0x5A1C)

            ta0ctl = view.get_data_var_at(0x0340)
            self.assertIsNotNone(ta0ctl)
            self.assertIn("TA0CTL_bits", str(ta0ctl.type))
            ta1ctl = view.get_data_var_at(0x0380)
            self.assertIsNotNone(ta1ctl)
            self.assertIn("TA1CTL_bits", str(ta1ctl.type))

            adc12mctl0 = view.get_data_var_at(0x0710)
            self.assertIsNotNone(adc12mctl0)
            self.assertIn("ADC12MCTL0_bits", str(adc12mctl0.type))

            pmmrie = view.get_data_var_at(0x012E)
            self.assertIsNotNone(pmmrie)
            self.assertIn("PMMRIE_bits", str(pmmrie.type))

            uca0ctlw0 = view.get_data_var_at(0x05C0)
            self.assertIsNotNone(uca0ctlw0)
            self.assertIn("UCA0CTLW0_bits", str(uca0ctlw0.type))
            uca0ictl = view.get_data_var_at(0x05DC)
            self.assertIsNotNone(uca0ictl)
            self.assertIn("UCA0ICTL_bits", str(uca0ictl.type))

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

    def test_sfr_data_vars_replace_stale_header_aliases_and_default_data(self):
        labels, sfrs = memory_map._parse_msp430_header_definitions(
            [HEADER_TEXT]
        )
        view = BinaryView.new(b"\0" * 0x1000)
        try:
            view.define_user_data_var(0x05DC, Type.char(), "UCA0IE")
            view.define_user_data_var(0x05DD, Type.char(), "UCA0IFG")
            view.define_user_data_var(0x05DE, Type.char(), "UCA0IV")
            view.define_user_data_var(0x05DF, Type.char(), "data_5df")

            self.assertGreater(
                memory_map._define_header_sfr_data_vars(
                    view,
                    sfrs,
                    auto_defined=True,
                    replaceable_names={name for name, _addr in labels},
                ),
                0,
            )

            uca0ictl = view.get_data_var_at(0x05DC)
            self.assertIsNotNone(uca0ictl)
            self.assertEqual(uca0ictl.address, 0x05DC)
            self.assertEqual(uca0ictl.type.width, 2)
            self.assertIn("UCA0ICTL_bits", str(uca0ictl.type))
            self.assertEqual(view.get_data_var_at(0x05DD).address, 0x05DC)

            uca0iv = view.get_data_var_at(0x05DE)
            self.assertIsNotNone(uca0iv)
            self.assertEqual(uca0iv.address, 0x05DE)
            self.assertEqual(uca0iv.type.width, 2)
            self.assertEqual(view.get_data_var_at(0x05DF).address, 0x05DE)
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
