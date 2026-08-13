from pathlib import Path

from binaryninja import BinaryView, BinaryViewType

import msp430x_arch  # noqa: F401
import msp430f5438_memory_map as mm


path = Path("/Users/jo31816/CATS/MSP430F5438-demo-pack/aegisnode_f5438a_v2714.bin")
data = path.read_bytes()
print("raw bytes", hex(len(data)))
raw = BinaryView.new(data)
view_type = BinaryViewType[mm.MSP430F5438BinaryView.name]
print("valid", view_type.is_valid_for_data(raw))
bv = view_type.create(raw)
print(
    "created",
    bv,
    "view_type",
    bv.view_type,
    "arch",
    bv.arch,
    "platform",
    bv.platform,
    "start/end",
    hex(bv.start),
    hex(bv.end),
)
print("waiting initial...")
bv.update_analysis_and_wait()
print("initial done functions", len(list(bv.functions)))

caller_addr = 0x7D20
call_addr = 0x7D44
callee_addr = 0xC100
string_addr = 0x30E04
caller = bv.get_function_at(caller_addr)
callee = bv.get_function_at(callee_addr)
print("\n=== FUNCTIONS ===")
print(
    "caller",
    caller,
    "arch",
    getattr(caller, "arch", None),
    "platform",
    getattr(caller, "platform", None),
    "start",
    hex(caller.start) if caller else None,
)
print(
    "callee",
    callee,
    "arch",
    getattr(callee, "arch", None),
    "platform",
    getattr(callee, "platform", None),
    "start",
    hex(callee.start) if callee else None,
)
print(
    "functions_at_callee",
    [
        (hex(function.start), str(function.arch), str(function.platform), function.name, str(function.type))
        for function in bv.get_functions_at(callee_addr)
    ],
)

print("\n=== CALL DISCOVERY ===")
call_sites = [] if caller is None else list(caller.call_sites)
print("caller.call_sites", [(hex(site.address), getattr(site, "function", None)) for site in call_sites])
decoder, _ = mm._msp430x_decode_api()
print("decoder", decoder)
print("direct target", mm._direct_msp430_call_target(bv, call_addr, decoder))
print("resolved target func", mm._function_at_call_target(bv, caller, callee_addr))
try:
    print("callee.callers", list(callee.callers))
except Exception as exc:
    print("callee.callers ERROR", type(exc).__name__, exc)
try:
    print(
        "callee.caller_sites",
        [(hex(site.address), getattr(site, "function", None)) for site in callee.caller_sites],
    )
except Exception as exc:
    print("callee.caller_sites ERROR", type(exc).__name__, exc)
try:
    print(
        "code_refs",
        [
            (hex(ref.address), getattr(ref, "function", None), getattr(ref, "arch", None))
            for ref in bv.get_code_refs(callee_addr)
        ],
    )
except Exception as exc:
    print("code_refs ERROR", type(exc).__name__, exc)

print("\n=== R12/STRING GATES ===")
for args in ((call_addr, "r12"), (call_addr, "r12", caller.arch)):
    try:
        reg_value = caller.get_reg_value_at(*args)
        print(
            "get_reg_value_at",
            len(args),
            "args:",
            reg_value,
            "type",
            getattr(reg_value, "type", None),
            "value",
            hex(int(getattr(reg_value, "value", 0)) & 0xFFFFF),
            "constant gate",
            getattr(reg_value, "type", None)
            in (mm.RegisterValueType.ConstantValue, mm.RegisterValueType.ConstantPointerValue),
        )
    except Exception as exc:
        print("get_reg_value_at ERROR", len(args), type(exc).__name__, exc)
text = mm._read_backed_ascii_c_string(bv, string_addr)
print("backed string exact", repr(text))
print("string object", bv.get_string_at(string_addr))
print("read bytes", bytes(bv.read(string_addr, 64)))
print("has format", mm._has_format_argument(text or ""))

print("\n=== CALLEE TYPE GATES ===")
print("has_user_type", getattr(callee, "has_user_type", None))
print("has_explicitly_defined_type", getattr(callee, "has_explicitly_defined_type", None))
print("type", callee.type)
print("type class", type(callee.type))
print("type confidence", getattr(callee.type, "confidence", None))
print("return_type", callee.return_type, "confidence", getattr(callee.return_type, "confidence", None))
print("can_return func", getattr(callee, "can_return", None), "type.can_return", getattr(callee.type, "can_return", None))
print(
    "calling convention",
    callee.calling_convention,
    "platform default",
    getattr(callee.platform, "default_calling_convention", None),
)
calling_convention = callee.calling_convention or getattr(callee.platform, "default_calling_convention", None)
print("int_arg_regs", tuple(getattr(calling_convention, "int_arg_regs", ())))
print("parameter_vars raw", callee.parameter_vars)
try:
    print("parameter_vars.vars", tuple(callee.parameter_vars.vars))
except Exception as exc:
    print("parameter_vars.vars ERROR", type(exc).__name__, exc)
print("type.parameters count", len(callee.type.parameters))
for index, parameter in enumerate(callee.type.parameters):
    location = getattr(parameter, "location", None)
    print(
        " param",
        index,
        "repr",
        parameter,
        "name",
        parameter.name,
        "type",
        parameter.type,
        "location",
        location,
        "source_type",
        getattr(location, "source_type", None),
        "storage",
        getattr(location, "storage", None),
        "reg",
        callee.arch.get_reg_name(location.storage) if location is not None else None,
    )
print("register_parameter_names", mm._register_parameter_names(callee))
print("preservable_auto_parameters", mm._preservable_auto_parameters(callee))
print("r12 already represented", "r12" in mm._register_parameter_names(callee))

print("\n=== CALL ADJUSTMENT BEFORE ===")
for args in ((call_addr,), (call_addr, caller.arch)):
    try:
        adjustment = caller.get_call_type_adjustment(*args)
        print(
            "adjustment",
            len(args),
            "args:",
            adjustment,
            "confidence",
            getattr(adjustment, "confidence", None),
            "params",
            getattr(adjustment, "parameters", None),
        )
    except Exception as exc:
        print("adjustment ERROR", len(args), type(exc).__name__, exc)

print("\n=== IL BEFORE ===")
for il_name in ("llil", "mlil", "hlil"):
    try:
        il = getattr(caller, il_name)
        hits = []
        for block in il:
            for instruction in block:
                if instruction.address in range(call_addr - 6, call_addr + 8):
                    hits.append((hex(instruction.address), str(instruction)))
        print(il_name, hits)
    except Exception as exc:
        print(il_name, "ERROR", type(exc).__name__, exc)

print("\n=== RECOVERY ===")
print("recover count", mm._recover_direct_string_call_parameters(bv, verbose=True))
print("adjustment immediate", caller.get_call_type_adjustment(call_addr))
bv.update_analysis_and_wait()
caller = bv.get_function_at(caller_addr)
callee = bv.get_function_at(callee_addr)
print("adjustment after update", caller.get_call_type_adjustment(call_addr))
print("second recover", mm._recover_direct_string_call_parameters(bv, verbose=True))
print("preservable after", mm._preservable_auto_parameters(callee))

print("\n=== MANUAL ZERO-PARAM LOCAL ADJUSTMENT ===")
current_type = callee.type
pointer_type = mm.Type.pointer(callee.arch, mm.Type.char())
adjusted_type = mm.Type.function(
    callee.return_type,
    [mm.FunctionParameter(pointer_type, "format")],
    calling_convention=calling_convention,
    variable_arguments=True,
    stack_adjust=getattr(current_type, "stack_adjustment", None),
).mutable_copy()
adjusted_type.can_return = current_type.can_return
adjusted_type.pure = current_type.pure
print("manual adjusted_type", adjusted_type, "can_return", adjusted_type.can_return)
mm._set_recovered_call_type_adjustment(caller, call_addr, adjusted_type)
print("manual immediate getter", caller.get_call_type_adjustment(call_addr))
bv.update_analysis_and_wait()
caller = bv.get_function_at(caller_addr)
print("manual after update getter", caller.get_call_type_adjustment(call_addr))
for il_name in ("mlil", "hlil"):
    il = getattr(caller, il_name)
    hits = []
    for block in il:
        for instruction in block:
            if instruction.address in range(call_addr - 6, call_addr + 8):
                hits.append((hex(instruction.address), str(instruction)))
    print(il_name, "after", hits)

bv.file.close()
print("closed")
