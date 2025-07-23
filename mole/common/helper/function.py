from __future__ import annotations
from functools import lru_cache
from typing import Dict, List, Optional, Tuple
import binaryninja as bn


class FunctionHelper:
    """
    This class provides helper functions with respect to functions.
    """

    @staticmethod
    def get_func_info(
        func: bn.MediumLevelILFunction, with_class_name: bool = True
    ) -> str:
        """
        This method returns a string with information about the function `func`.
        """
        info = f"0x{func.source_function.start:x} {func.source_function.name:s}"
        if with_class_name:
            info = f"{info:s} ({func.__class__.__name__:s})"
        return info

    @staticmethod
    def get_mlil_parm_insts(
        func: bn.MediumLevelILFunction,
    ) -> List[Optional[bn.MediumLevelILVarSsa]]:
        """
        This method returns a list of `MediumLevelILVarSsa` instructions that correspond to the
        parameters of function `func`. The order of the returned instructions corresponds to the one
        of the parameters in the function signature.
        """
        parm_vars = list(func.source_function.parameter_vars)
        parm_insts = len(parm_vars) * [None]

        func = func.ssa_form
        if func is None:
            return parm_insts

        # Find instructions corresponding to the function parameters
        def find_mlil_parm_inst(
            inst: bn.MediumLevelILInstruction,
        ) -> Tuple[int, Optional[bn.MediumLevelILVarSsa]]:
            if isinstance(inst, bn.MediumLevelILVarSsa):
                if inst.var.var in parm_vars:
                    return (parm_vars.index(inst.var.var), inst)
            return (-1, None)

        # Iterate instructions in the function
        for inst in func.instructions:
            for parm_idx, parm_inst in inst.traverse(find_mlil_parm_inst):
                if (
                    parm_idx >= 0
                    and parm_idx < len(parm_insts)
                    and parm_insts[parm_idx] is None
                    and parm_inst is not None
                ):
                    parm_insts[parm_idx] = parm_inst
            if None not in parm_insts:
                break
        return parm_insts

    @staticmethod
    @lru_cache(maxsize=None)
    def get_var_addr_assignments(
        func: bn.MediumLevelILFunction,
    ) -> Dict[bn.Variable, List[bn.MediumLevelILSetVarSsa]]:
        """
        This method returns a dictionary mapping variables (`var_y`) to assignment instructions
        (`var_x = &var_y`) within `func`, where the variable's address (`&var_y`) is assigned to
        another variable (`var_x`).
        """

        # Find variable address assignments (e.g. `var_x = &var_y`) in `inst`
        def find_var_addr_assignments(
            inst: bn.MediumLevelILInstruction,
        ) -> Tuple[Optional[bn.Variable], Optional[bn.MediumLevelILSetVarSsa]]:
            match inst:
                # TODO: Should we consider the `offset` in MLIL_ADDRESS_OF_FIELD as well?
                case bn.MediumLevelILSetVarSsa(
                    src=bn.MediumLevelILAddressOf(src=src)
                    | bn.MediumLevelILAddressOfField(src=src)
                ):
                    return (src, inst)
            return (None, None)

        # Find variable address assignments (e.g. `var_x = &var_y`) in `func`
        var_addr_assignments = {}
        if func is not None and func.ssa_form is not None:
            for var, inst in func.ssa_form.traverse(find_var_addr_assignments):
                if var is None or inst is None:
                    continue
                insts: List[bn.MediumLevelILSetVarSsa] = (
                    var_addr_assignments.setdefault(var, [])
                )
                insts.append(inst)
        return var_addr_assignments

    @staticmethod
    @lru_cache(maxsize=None)
    def get_ssa_memory_definitions(
        func: bn.MediumLevelILFunction,
        ssa_memory_version: int,
        ssa_memory_versions: frozenset[int] = frozenset(),
    ) -> List[bn.MediumLevelILInstruction]:
        """
        This method returns a list of all instructions within `func` that define the memory with
        version `ssa_memory_version`. A memory defining instruction is an instruction that creates a
        new memory version.
        """
        # Determine current memory defining instruction
        if func is None or ssa_memory_version in ssa_memory_versions:
            return []
        ssa_memory_versions = ssa_memory_versions.union({ssa_memory_version})
        mem_def_inst = func.get_ssa_memory_definition(ssa_memory_version)
        if mem_def_inst is None:
            return []
        mem_def_insts: List[bn.MediumLevelILInstruction] = [mem_def_inst]
        # Determine source memory versions
        src_memory_versions: List[int] = []
        match mem_def_inst:
            case bn.MediumLevelILMemPhi(src_memory=src_memory):
                src_memory_versions.extend(src_memory)
            case _:
                src_memory_versions.append(mem_def_inst.ssa_memory_version)
        # Recursively determine memory defining instructions
        for src_memory_version in src_memory_versions:
            mem_def_insts.extend(
                FunctionHelper.get_ssa_memory_definitions(
                    func, src_memory_version, ssa_memory_versions
                )
            )
        return mem_def_insts

    @staticmethod
    def get_mlil_synthetic_call_inst(
        bv: bn.BinaryView,
        func: bn.MediumLevelILFunction,
    ) -> Optional[bn.MediumLevelILCallSsa]:
        """
        This method builds a synthetic call instruction for the function `func` in SSA form.
        """
        func_addr = func.source_function.start
        call_dest = func.const_pointer(bv.address_size, func_addr)
        parm_insts = FunctionHelper.get_mlil_parm_insts(func)
        call_parms = [
            parm_inst.expr_index for parm_inst in parm_insts if parm_inst is not None
        ]
        expr_idx = func.call(
            output=[],
            dest=call_dest,
            params=call_parms,
            loc=bn.ILSourceLocation(func_addr, 0),
        )
        call_inst = func.get_expr(expr_idx)
        return call_inst

    @staticmethod
    def get_il_code(
        func: bn.HighLevelILFunction | bn.MediumLevelILFunction | bn.LowLevelILFunction,
    ) -> str:
        """
        This method returns an IL code representation of the function `func`.
        """
        if not func:
            return ""
        code_lines = [
            f"0x{inst.address:x}: {str(inst):s}" for inst in func.instructions
        ]
        return "\n".join(code_lines)

    @staticmethod
    def get_pseudo_c_code(func: bn.Function) -> str:
        """
        This method returns the pseudo C code of the function `func`.
        """
        if not func or func.pseudo_c_if_available is None:
            return ""
        code_lines = []
        for code_line in func.pseudo_c_if_available.get_linear_lines(func.hlil.root):
            code_lines.append(f"0x{code_line.address:x}: {str(code_line):s}")
        return "\n".join(code_lines)
