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
            # Match assignments of variable addresses (e.g. `var_x = &var_y`)
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

@lru_cache(maxsize=None)
def _get_var_addr_assignments(
        bb: bn.BasicBlock
    ) -> Dict[bn.Variable, List[bn.MediumLevelILSetVarSsa]]:
    var_addr_assignments = {}
    for inst in bb:
        # Match assignments of variable addresses (e.g. `var_x = &var_y`)
        match inst:
            case (bn.MediumLevelILSetVarSsa(src=bn.MediumLevelILAddressOf())):
                var_addr_assignments.setdefault(inst.src.src, []).append(inst)
    return var_addr_assignments

def get_bb_var_addr_assignments(
        inst: bn.MediumLevelILAddressOf
    ) -> List[bn.MediumLevelILSetVarSsa]:
    """
    This method returns a list of assignment instructions (`bn.MediumLevelILSetVarSSA`) that have as
    their source the same variable address (`bn.MediumLevelILAddressOf`). Only instructions within
    the same basic block as `inst` are considered.
    """
    bb = inst.function.get_basic_block_at(inst.instr_index)
    if bb is None:
        return []
    return _get_var_addr_assignments(bb).get(inst.src, [])