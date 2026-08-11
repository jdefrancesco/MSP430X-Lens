import faulthandler
from pathlib import Path
import sys
import threading
import time

from binaryninja import BinaryView, BinaryViewType, FunctionParameter, Type

import msp430f5438_memory_map as memory_map
import msp430x_arch  # noqa: F401


IMAGE = Path("/Users/jo31816/CATS/MSP430F5438-demo-pack/aegisnode_f5438a_v2714.bin")
CALLER = 0x71E0
CALL = 0x7204
CALLEE = 0x7AE0
EXPECTED = "module=startup state=%u result="


def hlil_text(function):
    return "\n".join(str(ins) for block in function.hlil for ins in block)


faulthandler.dump_traceback_later(20, repeat=True, file=sys.stderr)
raw = BinaryView.new(IMAGE.read_bytes())
view_type = BinaryViewType[memory_map.MSP430F5438BinaryView.name]
started = time.monotonic()
view = view_type.create(raw)
print("create seconds", time.monotonic() - started, flush=True)
started = time.monotonic()
view.update_analysis_and_wait()
print(
    "initial seconds", time.monotonic() - started,
    "state", view.analysis_state,
    "functions", len(view.functions),
    flush=True,
)

caller = view.get_function_at(CALLER)
callee = view.get_function_at(CALLEE)
print("caller/callee", caller is not None, callee is not None, flush=True)
print("initial string visible", EXPECTED in hlil_text(caller), flush=True)
print("r12 at call", caller.get_reg_value_at(CALL, "r12"), flush=True)
print("initial target parameters", memory_map._register_parameter_names(callee), flush=True)

def adjust_sites():
    decoder, _ = memory_map._msp430x_decode_api()
    changed = []
    for function in list(view.functions):
        if str(function.arch) != "msp430x":
            continue
        for site in list(function.call_sites):
            address = site.address
            target = memory_map._direct_msp430_call_target(view, address, decoder)
            if target is None:
                continue
            value = function.get_reg_value_at(address, "r12", function.arch)
            if value.type not in (
                memory_map.RegisterValueType.ConstantValue,
                memory_map.RegisterValueType.ConstantPointerValue,
            ):
                continue
            string_address = int(value.value) & 0xFFFFF
            string = memory_map._read_backed_ascii_c_string(view, string_address)
            if string is None:
                continue
            target_function = memory_map._function_at_call_target(view, function, target)
            if target_function is None or str(target_function.arch) != "msp430x":
                continue
            if "r12" in memory_map._register_parameter_names(target_function):
                continue
            existing = memory_map._preservable_auto_parameters(target_function)
            if existing is None:
                continue
            if function.get_call_type_adjustment(address, function.arch) is not None:
                continue
            convention = target_function.calling_convention
            if convention is None or str(tuple(convention.int_arg_regs)[0]) != "r12":
                continue
            current = target_function.type
            is_format = memory_map._has_format_argument(string)
            adjusted = Type.function(
                target_function.return_type,
                [
                    FunctionParameter(
                        Type.pointer(target_function.arch, Type.char()),
                        "format" if is_format else "text",
                    ),
                    *existing,
                ],
                calling_convention=convention,
                variable_arguments=(
                    is_format
                    or bool(getattr(current.has_variable_arguments, "value", False))
                ),
                stack_adjust=current.stack_adjustment,
            ).mutable_copy()
            adjusted.can_return = current.can_return
            adjusted.pure = current.pure
            function.set_call_type_adjustment(address, adjusted, function.arch)
            changed.append((function.start, address, target))
    return changed


started = time.monotonic()
first = adjust_sites()
print("first adjustments", len(first), "seconds", time.monotonic() - started, flush=True)
print("adjusted callers", len({item[0] for item in first}), flush=True)
print("post adjustment progress", view.analysis_progress.count, view.analysis_progress.total, flush=True)

progress_samples = []
stop_polling = threading.Event()


def poll_progress():
    while not stop_polling.is_set():
        progress = view.analysis_progress
        progress_samples.append((progress.count, progress.total))
        time.sleep(0.005)


poller = threading.Thread(target=poll_progress)
poller.start()
started = time.monotonic()
view.update_analysis_and_wait()
update_seconds = time.monotonic() - started
stop_polling.set()
poller.join()
print("post adjustment update seconds", update_seconds, flush=True)
print("max task total", max(total for _, total in progress_samples), flush=True)

caller = view.get_function_at(CALLER)
callee = view.get_function_at(CALLEE)
print("final string visible", EXPECTED in hlil_text(caller), flush=True)
print("final target parameters", memory_map._register_parameter_names(callee), flush=True)
started = time.monotonic()
second = adjust_sites()
print("second adjustments", len(second), "seconds", time.monotonic() - started, flush=True)
print("final progress", view.analysis_progress.count, view.analysis_progress.total, flush=True)
faulthandler.cancel_dump_traceback_later()
view.file.close()
raw.file.close()
