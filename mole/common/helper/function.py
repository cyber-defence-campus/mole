from __future__ import annotations
from collections import deque
from functools import lru_cache
from mole.common.helper.instruction import InstructionHelper
from typing import Dict, List, Optional, Set, Tuple
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
        info = f"0x{func.source_function.start:x} {func.source_function.symbol.short_name:s}"
        if with_class_name:
            info = f"{info:s} ({func.__class__.__name__:s})"
        return info

    @staticmethod
    def get_mlil_return_insts(
        func: bn.MediumLevelILFunction,
    ) -> List[bn.MediumLevelILInstruction]:
        """
        This method returns a list of return instructions of function `func`.
        """
        ret_insts: List[bn.MediumLevelILInstruction] = []
        for inst in func.instructions:
            match inst:
                case bn.MediumLevelILRet() | bn.MediumLevelILTailcallSsa():
                    ret_insts.append(inst)
        return ret_insts

    @staticmethod
    def get_mlil_direct_call_insts(
        func: bn.MediumLevelILFunction,
    ) -> Set[
        bn.MediumLevelILCallSsa
        | bn.MediumLevelILCallUntypedSsa
        | bn.MediumLevelILTailcallSsa
        | bn.MediumLevelILTailcallUntypedSsa
    ]:
        """
        This method returns a set of MLIL call instructions that directly call the function `func`.
        """
        call_insts: Set[
            bn.MediumLevelILCallSsa
            | bn.MediumLevelILCallUntypedSsa
            | bn.MediumLevelILTailcallSsa
            | bn.MediumLevelILTailcallUntypedSsa
        ] = set()
        # Iterate all caller sites of (instructions calling) `func`
        for caller_site in func.source_function.caller_sites:
            caller_func = caller_site.function
            # Ensure caller function is valid
            if caller_func is None:
                continue
            # Ensure caller function has a valid MLIL SSA representation
            if (
                caller_func.mlil is None or caller_func.mlil.ssa_form is None
            ) and caller_func.analysis_skipped:
                caller_func.analysis_skipped = False
                if caller_func.mlil is None or caller_func.mlil.ssa_form is None:
                    continue
            # Iterate all call sites of (instructions calling) the caller function
            for call_site in caller_func.call_sites:
                if call_site != caller_site:
                    continue
                for inst in call_site.mlils:
                    call_insts.update(InstructionHelper.get_mlil_call_insts(inst))
        return call_insts

    @staticmethod
    def get_mlil_indirect_call_insts(
        bv: bn.BinaryView,
        func: bn.MediumLevelILFunction,
    ) -> Set[
        bn.MediumLevelILCallSsa
        | bn.MediumLevelILCallUntypedSsa
        | bn.MediumLevelILTailcallSsa
        | bn.MediumLevelILTailcallUntypedSsa
    ]:
        """
        This method returns a set of MLIL call instructions that indirectly call the function
        `func`.
        """
        call_insts: Set[
            bn.MediumLevelILCallSsa
            | bn.MediumLevelILCallUntypedSsa
            | bn.MediumLevelILTailcallSsa
            | bn.MediumLevelILTailcallUntypedSsa
        ] = set()
        # Iterate all data references of `func`
        data_refs = bv.get_data_refs(func.source_function.start)
        for data_ref in data_refs:
            # Ensure a valid function pointer is stored at the data reference
            func_ptr = bv.read_pointer(data_ref)
            func = bv.get_function_at(func_ptr)
            if func is None:
                continue
            # Ensure a valid data variable is stored at the data reference
            data_var = bv.get_data_var_at(data_ref)
            if data_var is None:
                continue
            # Get data variable's type name and offset
            try:
                name = data_var.type.name
                offset = data_ref - data_var.address
            except Exception:
                continue
            # Iterate all code references to the data variable's referenced field
            for code_ref in bv.get_code_refs_for_type_field(name, offset):
                # Iterate all functions containing the code reference
                for ref_func in bv.get_functions_containing(code_ref.address):
                    # Ensure rereferenced function is valid
                    if ref_func is None:
                        continue
                    # Ensure referenced function has a valid MLIL SSA representation
                    if (
                        ref_func.mlil is None or ref_func.mlil.ssa_form is None
                    ) and ref_func.analysis_skipped:
                        ref_func.analysis_skipped = False
                        if ref_func.mlil is None or ref_func.mlil.ssa_form is None:
                            continue
                    # Iterate all call sites of (instructions calling) the referenced function
                    ref_func = ref_func.mlil.ssa_form
                    for call_site in ref_func.source_function.call_sites:
                        for inst in call_site.mlils:
                            for call_inst in InstructionHelper.get_mlil_call_insts(
                                inst
                            ):
                                # Indirect call
                                if isinstance(call_inst.dest, bn.MediumLevelILVarSsa):
                                    # Get definition of call destination variable
                                    call_dest_def = (
                                        call_inst.dest.function.get_ssa_var_definition(
                                            call_inst.dest.var
                                        )
                                    )
                                    # Store call instruction if its definition address matches the
                                    # code reference
                                    if (
                                        call_dest_def
                                        and call_dest_def.address == code_ref.address
                                    ):
                                        call_insts.add(call_inst)
                                # Store call instruction if its address matches the code reference
                                if call_inst.address == code_ref.address:
                                    call_insts.add(call_inst)
        return call_insts

    @staticmethod
    def get_mlil_param_insts(
        func: bn.MediumLevelILFunction,
    ) -> List[Optional[bn.MediumLevelILVarSsa]]:
        """
        This method returns a list of `MediumLevelILVarSsa` instructions that correspond to the
        parameters of function `func`. The order of the returned instructions corresponds to the one
        of the parameters in the function signature.
        """
        param_vars = list(func.source_function.parameter_vars)
        param_insts = len(param_vars) * [None]

        func = func.ssa_form
        if func is None:
            return param_insts

        # Find instructions corresponding to the function parameters
        def find_mlil_param_inst(
            inst: bn.MediumLevelILInstruction,
        ) -> Tuple[int, Optional[bn.MediumLevelILVarSsa]]:
            if isinstance(inst, bn.MediumLevelILVarSsa):
                if inst.var.var in param_vars:
                    return (param_vars.index(inst.var.var), inst)
            return (-1, None)

        # Iterate instructions in the function
        for inst in func.instructions:
            for param_idx, param_inst in inst.traverse(find_mlil_param_inst):
                if (
                    param_idx >= 0
                    and param_idx < len(param_insts)
                    and param_insts[param_idx] is None
                    and param_inst is not None
                ):
                    param_insts[param_idx] = param_inst
            if None not in param_insts:
                break
        return param_insts

    @staticmethod
    @lru_cache(maxsize=32)
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
    @lru_cache(maxsize=32)
    def get_ssa_memory_definitions(
        func: bn.MediumLevelILFunction,
        memory_version: int,
        max_memory_slice_depth: int = -1,
    ) -> List[bn.MediumLevelILInstruction]:
        """
        This method returns a list of all instructions within `func` that define the memory with
        version `memory_version` (using breadth-first search). A memory defining instruction is an
        instruction that creates a new memory version.
        """
        if func is None:
            return []
        mem_def_insts: List[bn.MediumLevelILInstruction] = []
        visited_memory_versions = set()
        queue = deque([memory_version])
        while queue:
            # Break if maximum number of memory versions visited
            if (
                max_memory_slice_depth >= 0
                and len(visited_memory_versions) >= max_memory_slice_depth
            ):
                break
            # Get current memory version
            current_memory_version = queue.popleft()
            if current_memory_version not in visited_memory_versions:
                # Visit current memory version
                visited_memory_versions.add(current_memory_version)
                mem_def_inst = func.get_ssa_memory_definition(current_memory_version)
                if mem_def_inst is None:
                    continue
                mem_def_insts.append(mem_def_inst)
                # Add new memory versions to queue
                match mem_def_inst:
                    case bn.MediumLevelILMemPhi(src_memory=src_memory):
                        queue.extend(src_memory)
                    case _:
                        queue.append(mem_def_inst.ssa_memory_version)
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
        param_insts = FunctionHelper.get_mlil_param_insts(func)
        call_params = [
            param_inst.expr_index if param_inst is not None else -1
            for param_inst in param_insts
        ]
        expr_idx = func.call(
            output=[],
            dest=call_dest,
            params=call_params,
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
