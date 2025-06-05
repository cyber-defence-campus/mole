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
    This method returns code of functions containing `addr`, in the specified BNIL representation
    `il_type`.
    """
    code = ""
    log.info(
        tag,
        f"Tool call 'get_code_for_functions_containing(addr={addr:s}, il_type={il_type:s})'",
    )
    try:
        addr = int(addr, 0)
        il_type = il_type.upper()
        func_code = []
        for func in bv.get_functions_containing(addr):
            header = f"{il_type:s} code of function '{str(func):s}' containing address '0x{addr:x}':"
            code = get_il_code(func, il_type)
            func_code.append(header + "\n```" + code + "```\n")
            log.debug(tag, f"Return {il_type:s} code of function '{str(func):s}'")
        code = "\n".join(func_code)
    except Exception as e:
        log.error(
            tag,
            f"Failed to get {il_type:s} code of functions containing address '0x{addr:x}': {str(e):s}",
        )
    return code
