from __future__ import annotations
from mole.common.help import FunctionHelper
from mole.common.log import log
import binaryninja as bn


def get_il_code(func: bn.Function, il_type: str) -> str:
    """
    This method dispatches the IL type `il_type` and returns the corresponding code of the function
    `func`.
    """
    il_func = None
    match il_type.upper():
        case "PSEUDO_C":
            return FunctionHelper.get_pseudo_c_code(func)
        case "HLIL":
            il_func = func.hlil
        case "MLIL":
            il_func = func.mlil
        case "LLIL":
            il_func = func.llil
    return FunctionHelper.get_il_code(il_func)


def get_code_for_functions_containing(
    bv: bn.BinaryView,
    addr: str,
    il_type: str,
    tag: str = None,
) -> str:
    """
    This method returns code of functions containing address `addr`, in the specified BNIL
    representation `il_type`.
    """
    log.info(
        tag,
        f"Tool call 'get_code_for_functions_containing(addr={addr:s}, il_type={il_type:s})'",
    )
    res_code = ""
    try:
        _addr = int(addr, 0)
        il_type = il_type.upper()
        func_code = []
        for func in bv.get_functions_containing(_addr):
            header = f"{il_type:s} code of function `0x{func.start:x}: {str(func):s}`, which contains address `0x{_addr:x}`:"
            code = get_il_code(func, il_type)
            func_code.append(header + "\n```\n" + code + "\n```\n")
            log.debug(
                tag,
                f"Return {il_type:s} code of function '0x{func.start:x}: {str(func):s}'",
            )
        res_code = "\n".join(func_code)
    except Exception as e:
        msg = f"Failed to get {il_type:s} code of functions containing address '{addr:s}': {str(e):s}"
        log.warn(tag, msg)
        res_code = msg
    return res_code


def get_code_for_functions_by_name(
    bv: bn.BinaryView,
    name: str,
    il_type: str,
    tag: str = None,
) -> str:
    """
    This method returns code of functions with name `name`, in the specified BNIL representation
    `il_type`.
    """
    log.info(
        tag,
        f"Tool call 'get_code_for_functions_by_name(name={name:s}, il_type={il_type:s})'",
    )
    res_code = ""
    try:
        il_type = il_type.upper()
        func_code = []
        for func in bv.get_functions_by_name(name):
            header = f"{il_type:s} code of function `0x{func.start:x}: {str(func):s}`:"
            code = get_il_code(func, il_type)
            func_code.append(header + "\n```\n" + code + "\n```\n")
            log.debug(
                tag,
                f"Return {il_type:s} code of function '0x{func.start:x}: {str(func):s}'",
            )
        res_code = "\n".join(func_code)
    except Exception as e:
        msg = f"Failed to get {il_type:s} code of functions with name '{name:s}': {str(e):s}"
        log.warn(tag, msg)
        res_code = msg
    return res_code


def get_callers_by_address(
    bv: bn.BinaryView,
    addr: str,
    tag: str = None,
) -> str:
    """
    This method returns the callers of functions containing address `addr`.
    """
    log.info(tag, f"Tool call 'get_callers_by_address(addr={addr:s})'")
    res_callers = ""
    try:
        _addr = int(addr, 0)
        callers = []
        for func in bv.get_functions_containing(_addr):
            header = f"Callers of function `0x{func.start:x}: {str(func):s}`, which contains address `0x{_addr:x}`:"
            func_callers = "\n".join(
                f"- `0x{caller.start:x}`: `{caller.symbol.short_name:s}`"
                for caller in func.callers
            )
            callers.append(header + "\n" + func_callers + "\n")
        res_callers = "\n".join(callers)
    except Exception as e:
        msg = f"Failed to get callers of functions containing address '{addr:s}': {str(e):s}"
        log.warn(tag, msg)
        res_callers = msg
    return res_callers


def get_callers_by_name(
    bv: bn.BinaryView,
    name: str,
    tag: str = None,
) -> str:
    """
    This method returns the callers of functions with name `name`.
    """
    log.info(tag, f"Tool call 'get_callers_by_name(name={name:s})'")
    res_callers = ""
    try:
        callers = []
        for func in bv.get_functions_by_name(name):
            header = f"Callers of function `0x{func.start:x}: {str(func):s}`:"
            func_callers = "\n".join(
                f"- `0x{caller.start:x}`: `{caller.symbol.short_name:s}`"
                for caller in func.callers
            )
            callers.append(header + "\n" + func_callers + "\n")
        res_callers = "\n".join(callers)
    except Exception as e:
        msg = f"Failed to get callers of functions with name '{name:s}': {str(e):s}"
        log.warn(tag, msg)
        res_callers = msg
    return res_callers
