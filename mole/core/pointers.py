import binaryninja as bn
from typing import List
from functools import lru_cache

@lru_cache(maxsize=None)
def _get_alias_map_for_function(func):
    return _build_pointer_alias_map_for_function(func)

def get_instructions_for_pointer_alias(func: bn.Function, pointer: bn.MediumLevelILAddressOf) -> List[bn.MediumLevelILInstruction]:
    alias_map = _get_alias_map_for_function(func)
    return alias_map.get(str(pointer), [])

def _build_pointer_alias_map_for_function(func: bn.MediumLevelILFunction):
    pointer_alias_map = {}

    # Iterate over MLIL SSA instructions for this function
    for block in func.ssa_form:
        for instr in block:
            # Detect pointer-related assignments (e.g., var_x = &var_y)
            if isinstance(instr, bn.MediumLevelILSetVarSsa):
                src = instr.operands[1]
                # Check if the src operand is an actual pointer by verifying it's an AddressOf operation
                if isinstance(src, bn.MediumLevelILAddressOf):
                    pointer_alias_map.setdefault(str(src), []).append(instr)

    return pointer_alias_map
