from pathlib import Path

from binaryninja import BinaryView, BinaryViewType

import msp430x_arch  # noqa: F401
import msp430f5438_memory_map as mm


CALLER = 0x7D20
CALL = 0x7D44
CALLEE = 0xC100
NEEDLE = "module=kernel state=%u result=%d"


def snapshot(bv, label):
    caller = bv.get_function_at(CALLER)
    callee = bv.get_function_at(CALLEE)
    adjustment = caller.get_call_type_adjustment(CALL)
    mlil = [str(ins) for ins in caller.mlil.instructions if ins.address == CALL]
    hlil = [str(ins) for ins in caller.hlil.instructions if ins.address == CALL]
    print(
        label,
        {
            "adjustment": str(adjustment),
            "adjustment_present": adjustment is not None,
            "adjustment_can_return": (
                None if adjustment is None else adjustment.can_return.value
            ),
            "callee_type": str(callee.type),
            "callee_can_return": callee.type.can_return.value,
            "mlil": mlil,
            "hlil": hlil,
            "mlil_has_string": any(NEEDLE in text for text in mlil),
            "hlil_has_string": any(NEEDLE in text for text in hlil),
        },
    )


raw = BinaryView.new(
    Path(
        "/Users/jo31816/CATS/MSP430F5438-demo-pack/"
        "aegisnode_f5438a_v2714.bin"
    ).read_bytes()
)
bv = BinaryViewType[mm.MSP430F5438BinaryView.name].create(raw)
bv.update_analysis_and_wait()
snapshot(bv, "initial")

passes = mm._stabilize_direct_string_call_parameters(bv, verbose=False)
print("initial recovery passes", passes)
snapshot(bv, "after recovery fixed point")

bv.update_analysis_and_wait()
snapshot(bv, "after extra update")

caller = bv.get_function_at(CALLER)
caller.reanalyze()
bv.update_analysis_and_wait()
snapshot(bv, "after full caller reanalysis")

mm.rerun_msp430f5438a_analysis(bv)
snapshot(bv, "after full plugin rerun")

final_passes = mm._stabilize_direct_string_call_parameters(bv, verbose=False)
print("final recovery passes", final_passes)
snapshot(bv, "final")
bv.file.close()
