import unittest

from binaryninja import BinaryView, BinaryViewType

import msp430f5438_memory_map as m


class Probe(unittest.TestCase):
    def test_run(self):
        path = "/Users/jo31816/CATS/MSP430F5438-demo-pack/aegisnode_f5438a_v2714.bin"
        with open(path, "rb") as source:
            raw = BinaryView.new(source.read())
        view_type = BinaryViewType[m.MSP430F5438BinaryView.name]
        view = view_type.create(raw)
        view.update_analysis_and_wait()
        print("view", view.start, view.end, len(view.functions))
        callee = view.get_function_at(0xC100)
        caller = view.get_function_at(0x7D20)
        print(
            "callee", callee,
            "type", callee.type,
            "params", callee.type.parameters,
            "typeconf", callee.type.confidence,
            "has_user", callee.has_user_type,
            "param_vars", callee.parameter_vars,
            "pvconf", callee.parameter_vars.confidence,
            "cc", callee.calling_convention,
            "ccconf", getattr(callee.calling_convention, "confidence", None),
            "ret", callee.return_type,
            "retconf", getattr(callee.return_type, "confidence", None),
            "canret", callee.can_return,
            "pure", callee.pure,
            "varargs", callee.has_variable_arguments,
            "stack", callee.stack_adjustment,
            "symbol", callee.symbol,
            "symbol_type", callee.symbol.type,
            "symbol_auto", getattr(callee.symbol, "auto", None),
        )
        print(
            "caller", caller,
            "r12", caller.get_reg_value_at(0x7D44, "r12"),
            "adj", caller.get_call_type_adjustment(0x7D44),
        )
        print(
            "register params", m._register_parameter_names(callee),
            "preserve", m._preservable_auto_parameters(callee),
        )
        print("callers", [(x.function.start, x.address) for x in callee.callers])
        view.file.close()
