from typing import Optional
from binaryninja import Function


def get_pseudo_c(func):
    """
    Get the pseudo C representation of a function with addresses.
    """
    if func.pseudo_c_if_available is None:
        return None

    # Add function address to prototype
    proto = f"{hex(func.start)}: {' '.join(map(str, func.type.get_tokens_before_name()))} {func.name}{''.join(map(str, func.type.get_tokens_after_name()))}"

    # Get lines with their addresses
    lines_with_addresses = []
    for line in func.pseudo_c_if_available.get_linear_lines(func.hlil.root):
        addr = None
        if hasattr(line, "address"):
            addr = hex(line.address)

        if addr:
            lines_with_addresses.append(f"{addr}: {str(line)}")
        else:
            lines_with_addresses.append(str(line))

    return "\n".join([proto] + lines_with_addresses)


def get_hlil_code(func: Function) -> Optional[str]:
    """
    Get the HLIL code representation of a function with addresses.
    """
    hlil = func.hlil
    if hlil is None:
        return None

    # Add function address to prototype
    proto = f"{hex(func.start)}: {' '.join(map(str, func.type.get_tokens_before_name()))} {func.name}{''.join(map(str, func.type.get_tokens_after_name()))}"

    lines_with_addresses = []
    indent = "    "
    for line in hlil.root.lines:
        addr = hex(line.address) if hasattr(line, "address") else None
        line_str = str(line)
        if addr:
            lines_with_addresses.append(f"{addr}:{indent} {line_str}")
        else:
            lines_with_addresses.append(f"{indent}{line_str}")
    return "\n".join([proto] + lines_with_addresses)


def get_mlil_code(func: Function) -> Optional[str]:
    """
    Get the MLIL code representation of a function with addresses.
    """
    mlil = func.mlil
    if mlil is None:
        return None
    header = f"{func.start:x} | {str(func)}"
    # Get lines with their addresses and symbolized instructions
    lines = [
        f"{insn.address:x}: {''.join(str(t) for t in insn.tokens)}"
        for insn in mlil.instructions
    ]
    return header + "\n" + "\n".join(lines)
