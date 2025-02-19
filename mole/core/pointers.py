from functools     import lru_cache
from typing        import Dict, List
import binaryninja as bn


def _build_pointer_alias_map_for_function(
        func: bn.MediumLevelILFunction
    ) -> Dict[bn.Variable, List[bn.MediumLevelILSetVarSsa]]:
    pointer_alias_map = {}
    # Iterate over MLIL SSA instructions for this function
    for block in func.ssa_form:
        for inst in block:
            # Match pointer-related assignments (e.g., var_x = &var_y)
            match inst:
                case (bn.MediumLevelILSetVarSsa(src=bn.MediumLevelILAddressOf())):
                    pointer_alias_map.setdefault(inst.src.src, []).append(inst)
    return pointer_alias_map

@lru_cache(maxsize=None)
def _get_alias_map_for_function(
    func: bn.MediumLevelILFunction
    ) -> Dict[bn.Variable, List[bn.MediumLevelILSetVarSsa]]:
    return _build_pointer_alias_map_for_function(func)

def get_instructions_for_pointer_alias(
        inst: bn.MediumLevelILAddressOf,
        func: bn.MediumLevelILFunction
    ) -> List[bn.MediumLevelILSetVarSsa]:
    alias_map = _get_alias_map_for_function(func)
    return alias_map.get(inst.src, [])