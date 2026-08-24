from types import SimpleNamespace
import unittest

import msp430f5438_memory_map as memory_map


SOURCE_ADDRESS = 0x7000
SLOT_ADDRESS = 0x9000
TARGET_ADDRESS = 0x11000
CONTROL_KIND = "call"
TARGET_CODE = bytes.fromhex("04 12 03 43 34 41 30 41")
CPUX_FALLBACK = bytes.fromhex("00 18 70 00")


def _address_word(target: int, *, high_word: int | None = None) -> bytes:
    """Encode the MSP430X low-word/high-nibble in-memory pointer layout."""

    if high_word is None:
        high_word = (target >> 16) & 0xF
    return (target & 0xFFFF).to_bytes(2, "little") + high_word.to_bytes(
        2, "little"
    )


def _calla_absolute(slot: int) -> bytes:
    opcode = 0x1380 | ((slot >> 16) & 0xF)
    return opcode.to_bytes(2, "little") + (slot & 0xFFFF).to_bytes(2, "little")


def _bra_absolute(slot: int) -> bytes:
    opcode = 0x0020 | (((slot >> 16) & 0xF) << 8)
    return opcode.to_bytes(2, "little") + (slot & 0xFFFF).to_bytes(2, "little")


class MockView:
    """Small mapped view that keeps readable bytes and file backing distinct."""

    def __init__(self, spec=memory_map.MSP430F5438_SPEC):
        self.spec = spec
        self._memory = {}
        self._backed = set()
        self.segments = []
        self.data_vars = {}

    def map_bytes(
        self,
        addr: int,
        data: bytes,
        *,
        backed: bool = True,
        executable: bool = True,
    ) -> None:
        for offset, byte in enumerate(data):
            byte_addr = addr + offset
            self._memory[byte_addr] = byte
            if backed:
                self._backed.add(byte_addr)
        self.segments.append(
            SimpleNamespace(
                start=addr,
                end=addr + len(data),
                data_length=len(data) if backed else 0,
                executable=executable,
            )
        )

    def read(self, addr: int, length: int) -> bytes:
        segment = self.get_segment_at(addr)
        if segment is None or addr + length > segment.end:
            return b""
        return bytes(
            self._memory.get(byte_addr, 0)
            for byte_addr in range(addr, addr + length)
        )

    def is_offset_backed_by_file(self, addr: int) -> bool:
        return addr in self._backed

    def get_segment_at(self, addr: int):
        return next(
            (
                segment
                for segment in self.segments
                if segment.start <= addr < segment.end
            ),
            None,
        )

    def get_data_var_at(self, addr: int):
        return self.data_vars.get(addr)


def _mapped_recovery_view(
    *,
    slot: int = SLOT_ADDRESS,
    target: int = TARGET_ADDRESS,
    high_word: int | None = None,
    target_backed: bool = True,
    target_executable: bool = True,
    target_code: bytes = TARGET_CODE,
) -> MockView:
    view = MockView()
    # The recovery helper consumes already-proven references, but retaining a
    # real absolute-memory CALLA encoding makes the source/slot relationship
    # evident in failures.
    view.map_bytes(SOURCE_ADDRESS, _calla_absolute(slot))
    view.map_bytes(slot, _address_word(target, high_word=high_word))
    view.map_bytes(
        target,
        target_code,
        backed=target_backed,
        executable=target_executable,
    )
    return view


class IndirectAddressWordRecoveryTests(unittest.TestCase):
    def test_decodes_valid_two_word_twenty_bit_address(self):
        self.assertEqual(
            memory_map._decode_address_word(bytes.fromhex("56 34 02 00")),
            0x23456,
        )

    def test_reserved_high_word_bits_make_address_word_malformed(self):
        malformed = _address_word(TARGET_ADDRESS, high_word=0x0011)

        self.assertIsNone(memory_map._decode_address_word(malformed))
        view = _mapped_recovery_view(high_word=0x0011)
        self.assertIsNone(memory_map._read_backed_address_word(view, SLOT_ADDRESS))
        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),),
            ),
            (),
        )

    def test_valid_referenced_slot_recovers_high_bank_target_once(self):
        view = _mapped_recovery_view()
        reference = (SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND)

        self.assertEqual(
            memory_map._read_backed_address_word(view, SLOT_ADDRESS),
            TARGET_ADDRESS,
        )
        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                (reference, reference),
            ),
            ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND, TARGET_ADDRESS),),
        )

    def test_absolute_memory_bra_names_one_address_word_slot(self):
        view = _mapped_recovery_view()
        branch_bytes = _bra_absolute(SLOT_ADDRESS)
        for offset, byte in enumerate(branch_bytes):
            view._memory[SOURCE_ADDRESS + offset] = byte
        view.functions = (
            SimpleNamespace(
                arch="msp430x",
                instructions=(((), SOURCE_ADDRESS),),
            ),
        )

        decoder, _branch_edges = memory_map._msp430x_decode_api()
        instruction = decoder(branch_bytes, SOURCE_ADDRESS)
        self.assertIsNotNone(instruction)
        self.assertEqual((instruction.mnemonic, instruction.src.kind), ("mova", "mem"))
        self.assertEqual(
            memory_map._referenced_address_word_control_sites(view),
            ((SOURCE_ADDRESS, SLOT_ADDRESS, "branch"),),
        )

    def test_register_derived_bra_is_not_treated_as_a_static_slot(self):
        # MOVA @r4,pc is valid indirect control flow, but the target depends on
        # runtime register state and must not trigger a pointer-data scan.
        branch_bytes = bytes.fromhex("00 04")
        view = MockView()
        view.map_bytes(SOURCE_ADDRESS, branch_bytes)
        view.functions = (
            SimpleNamespace(
                arch="msp430x",
                instructions=(((), SOURCE_ADDRESS),),
            ),
        )

        decoder, _branch_edges = memory_map._msp430x_decode_api()
        instruction = decoder(branch_bytes, SOURCE_ADDRESS)
        self.assertIsNotNone(instruction)
        self.assertEqual((instruction.mnemonic, instruction.src.kind), ("mova", "indirect"))
        self.assertEqual(memory_map._referenced_address_word_control_sites(view), ())

    def test_unreferenced_pointer_shaped_high_bank_data_is_ignored(self):
        high_bank_slot = 0x12000
        high_bank_target = 0x13000
        view = MockView()
        view.map_bytes(high_bank_slot, _address_word(high_bank_target))
        view.map_bytes(high_bank_target, TARGET_CODE)

        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(view, ()),
            (),
        )

    def test_odd_slot_is_rejected(self):
        odd_slot = SLOT_ADDRESS + 1
        view = _mapped_recovery_view(slot=odd_slot)

        self.assertIsNone(memory_map._read_backed_address_word(view, odd_slot))
        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                ((SOURCE_ADDRESS, odd_slot, CONTROL_KIND),),
            ),
            (),
        )

    def test_slot_must_be_fully_file_backed(self):
        view = _mapped_recovery_view()
        view._backed.remove(SLOT_ADDRESS + 3)

        self.assertIsNone(
            memory_map._read_backed_address_word(view, SLOT_ADDRESS)
        )
        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),),
            ),
            (),
        )

    def test_target_must_be_fully_file_backed(self):
        view = _mapped_recovery_view()
        view._backed.remove(TARGET_ADDRESS + 1)

        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),),
            ),
            (),
        )

    def test_odd_target_is_rejected(self):
        view = _mapped_recovery_view(target=TARGET_ADDRESS + 1)

        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),),
            ),
            (),
        )

    def test_non_executable_target_is_rejected(self):
        view = _mapped_recovery_view(target_executable=False)

        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),),
            ),
            (),
        )

    def test_out_of_profile_target_is_rejected(self):
        view = _mapped_recovery_view(
            target=memory_map.MSP430F5438_SPEC.device_end,
        )

        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),),
                spec=memory_map.MSP430F5438_SPEC,
            ),
            (),
        )

    def test_erased_target_is_rejected(self):
        for target_word, label in (
            (bytes.fromhex("00 00"), "zero-fill"),
            (bytes.fromhex("ff ff"), "erased"),
        ):
            with self.subTest(label=label):
                view = _mapped_recovery_view()
                for offset, byte in enumerate(target_word):
                    view._memory[TARGET_ADDRESS + offset] = byte
                self.assertEqual(
                    memory_map._recover_referenced_address_word_targets(
                        view,
                        ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),),
                    ),
                    (),
                )

    def test_target_classified_as_data_is_rejected(self):
        view = _mapped_recovery_view()
        view.data_vars[TARGET_ADDRESS] = object()

        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),),
            ),
            (),
        )

    def test_target_instruction_must_not_overlap_following_data(self):
        # CALLA #0x11000 is four bytes. A string/table beginning on its second
        # word is stronger data evidence even though the instruction start is
        # not itself inside the data variable.
        view = _mapped_recovery_view(
            target_code=bytes.fromhex("b1 13 00 10"),
        )
        view.data_vars[TARGET_ADDRESS + 2] = SimpleNamespace(
            type=SimpleNamespace(width=2)
        )

        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),),
            ),
            (),
        )

    def test_target_instruction_must_not_cross_into_vector_data(self):
        target = memory_map.MSP430F5438_SPEC.vector_start - 2
        view = _mapped_recovery_view(
            target=target,
            target_code=bytes.fromhex("b1 13 00 10"),
        )

        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),),
            ),
            (),
        )

    def test_existing_data_span_prevents_overlapping_slot_definition(self):
        view = _mapped_recovery_view()
        view.data_vars[SLOT_ADDRESS - 2] = SimpleNamespace(
            type=SimpleNamespace(width=8)
        )
        definitions = []
        comments = []
        view.define_data_var = lambda *args: definitions.append(args)
        view.set_auto_comment_at = lambda *args: comments.append(args)

        self.assertFalse(
            memory_map._define_referenced_address_word_data(
                view,
                SLOT_ADDRESS,
                TARGET_ADDRESS,
            )
        )
        self.assertEqual(definitions, [])
        self.assertEqual(comments, [])

    def test_target_overlapping_its_address_word_slot_is_rejected(self):
        view = MockView()
        view.map_bytes(SOURCE_ADDRESS, _calla_absolute(SLOT_ADDRESS))
        slot_payload = _address_word(SLOT_ADDRESS) + bytes.fromhex(
            "03 43 03 43 03 43 03 43 03 43 03 43"
        )
        view.map_bytes(SLOT_ADDRESS, slot_payload)

        decoder, _branch_edges = memory_map._msp430x_decode_api()
        first = decoder(slot_payload, SLOT_ADDRESS)
        self.assertIsNotNone(first)
        self.assertEqual((first.mnemonic, first.fmt), ("cmp", "double"))
        self.assertEqual(
            memory_map._read_backed_address_word(view, SLOT_ADDRESS),
            SLOT_ADDRESS,
        )
        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),),
            ),
            (),
        )

    def test_cpux_fallback_target_is_rejected(self):
        target_code = CPUX_FALLBACK + bytes.fromhex(
            "03 43 03 43 03 43 03 43 03 43 03 43"
        )
        view = _mapped_recovery_view(target_code=target_code)

        decoder, _branch_edges = memory_map._msp430x_decode_api()
        first = decoder(target_code, TARGET_ADDRESS)
        self.assertIsNotNone(first)
        self.assertEqual(first.fmt, "cpux")
        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                ((SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),),
            ),
            (),
        )

    def test_conflicting_slots_for_one_source_are_ambiguous(self):
        second_slot = SLOT_ADDRESS + 4
        second_target = TARGET_ADDRESS + 0x100
        view = _mapped_recovery_view()
        view.map_bytes(second_slot, _address_word(second_target))
        view.map_bytes(second_target, TARGET_CODE)

        self.assertEqual(
            memory_map._recover_referenced_address_word_targets(
                view,
                (
                    (SOURCE_ADDRESS, SLOT_ADDRESS, CONTROL_KIND),
                    (SOURCE_ADDRESS, second_slot, CONTROL_KIND),
                ),
            ),
            (),
        )


if __name__ == "__main__":
    unittest.main()
