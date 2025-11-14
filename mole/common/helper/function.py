from __future__ import annotations
from collections import deque
from functools import lru_cache
from mole.common.helper.instruction import InstructionHelper
from typing import Dict, List, Optional, Set, Tuple
import binaryninja as bn


class FunctionHelper:
    """
    This class provides helper functions with respect to functions.

    TODO:
    - Review all functions in this class: which ones can be cached?
    - `my_func.cache_clear()`
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
    def get_alias_map(
        func: bn.MediumLevelILFunction,
    ) -> Dict[bn.Variable, Set[bn.SSAVariable]]:
        """
        This method finds all aliased variable assignments (`var_y = var_x`, where `var_x` is
        an aliased variable) in function `func`. It then returns a dictionary mapping the HLIL
        variable corresponding to `var_x` to a set of MLIL SSA variables corresponding to `var_y`.
        """

        # Find aliased assignments (e.g. `var_y = var_x`, where `var_x` is aliased) in instruction
        # `inst` and return its MLIL destination SSA variable and HLIL source variable
        def find_aliased_assignments(
            inst: bn.MediumLevelILInstruction,
        ) -> Tuple[Optional[bn.SSAVariable], Optional[bn.Variable]]:
            # Determine MLIL destination variable
            match inst:
                # `var_y = OP(var_x)`, where `var_x` is aliased
                case bn.MediumLevelILSetVarSsa(
                    dest=mlil_dest_ssa_var,
                    src=(
                        bn.MediumLevelILVarAliased(src=bn.SSAVariable())
                        | bn.MediumLevelILUnaryBase(
                            src=bn.MediumLevelILVarAliased(src=bn.SSAVariable())
                        )
                    ),
                ):
                    # Determine HLIL source variable
                    match inst.src.hlil:
                        case (
                            bn.HighLevelILVar(var=hlil_src_var)
                            | bn.HighLevelILUnaryBase(
                                src=bn.HighLevelILVar(var=hlil_src_var)
                            )
                        ):
                            return (mlil_dest_ssa_var, hlil_src_var)
            return (None, None)

        # Find aliased assignments (e.g. `var_y = var_x`, where `var_x` is aliased) in function
        # `func`
        alias_map: Dict[bn.Variable, Set[bn.SSAVariable]] = {}
        if func is not None and func.ssa_form is not None:
            for mlil_dest_ssa_var, hlil_src_var in func.ssa_form.traverse(
                find_aliased_assignments
            ):
                mlil_dest_ssa_var = mlil_dest_ssa_var  # type: Optional[bn.SSAVariable]
                hlil_src_var = hlil_src_var  # type: Optional[bn.Variable]
                if mlil_dest_ssa_var is not None and hlil_src_var is not None:
                    alias_map.setdefault(hlil_src_var, set()).add(mlil_dest_ssa_var)
        return alias_map

    @staticmethod
    @lru_cache(maxsize=32)
    def get_ptr_map(
        func: bn.MediumLevelILFunction,
    ) -> Dict[bn.Variable, Set[bn.Variable]]:
        """
        This method finds all pointer assignments (e.g. `var_y = &var_x`) in function `func`. It
        then returns a dictionary mapping the MLIL variable corresponding to `var_y` to a set of
        HLIL variables corresponding to `var_x`.
        """

        # Find pointer assignment (e.g. `var_y = &var_x`) in instruction `inst`
        # and return its MLIL destination SSA variable and HLIL source variable
        def find_ptr_assignments(
            inst: bn.MediumLevelILInstruction,
        ) -> Tuple[Optional[bn.SSAVariable], Optional[bn.Variable]]:
            # Determine MLIL destination variable
            match inst:
                # `var_y = &var_x` or `var_y = &var_x:offset`
                case bn.MediumLevelILSetVarSsa(
                    dest=mlil_dest_ssa_var,
                    src=(
                        bn.MediumLevelILAddressOf()
                        | bn.MediumLevelILAddressOfField()
                        | bn.MediumLevelILVarSsa()
                    ),
                ):
                    # Determine HLIL source variable
                    match inst.src.hlil:
                        case bn.HighLevelILAddressOf(
                            src=(
                                bn.HighLevelILVar(var=hlil_src_var)
                                | bn.HighLevelILArrayIndex(
                                    src=bn.HighLevelILVar(var=hlil_src_var)
                                )
                            )
                        ):
                            return (mlil_dest_ssa_var, hlil_src_var)
            return (None, None)

        # Recursively find all SSA variables having the same value as `ssa_var` assigned
        def find_var_assignments(ssa_var: bn.SSAVariable) -> Set[bn.SSAVariable]:
            ssa_vars: Set[bn.SSAVariable] = set()
            for use_site in ssa_var.use_sites:
                if not isinstance(use_site, bn.MediumLevelILSetVarSsa):
                    continue
                dest_ssa_var = use_site.dest
                match use_site.src:
                    # `var_y = var_x:0`
                    case (
                        bn.MediumLevelILVarSsa(var=src_ssa_var)
                        | bn.MediumLevelILVarSsaField(src=src_ssa_var)
                        | bn.MediumLevelILVarAliased(src=src_ssa_var)
                    ):
                        offset = getattr(use_site.src, "offset", 0)
                        if src_ssa_var == ssa_var and offset == 0:
                            ssa_vars |= {dest_ssa_var} | find_var_assignments(
                                dest_ssa_var
                            )
                    # `var_y = var_x + ...` or `var_y = ... + var_x`
                    case bn.MediumLevelILAdd(left=left_inst, right=right_inst):
                        if (
                            isinstance(left_inst, bn.MediumLevelILVarSsa)
                            and left_inst.var == ssa_var
                        ):
                            ssa_vars |= {dest_ssa_var} | find_var_assignments(
                                dest_ssa_var
                            )
                        elif (
                            isinstance(right_inst, bn.MediumLevelILVarSsa)
                            and right_inst.var == ssa_var
                        ):
                            ssa_vars |= {dest_ssa_var} | find_var_assignments(
                                dest_ssa_var
                            )
            return ssa_vars

        # Create mapping from MLIL destination variable to HLIL source variable
        ptr_map: Dict[bn.Variable, Set[bn.Variable]] = {}
        if func is not None and func.ssa_form is not None:
            # Get map of variable aliases for function `func`
            alias_map = FunctionHelper.get_alias_map(func)
            # Find pointer assignment (e.g. `var_y = &var_x`) in function `func`
            for mlil_dest_ssa_var, hlil_src_var in func.ssa_form.traverse(
                find_ptr_assignments
            ):
                mlil_dest_ssa_var = mlil_dest_ssa_var  # type: Optional[bn.SSAVariable]
                hlil_src_var = hlil_src_var  # type: Optional[bn.Variable]
                if mlil_dest_ssa_var is not None and hlil_src_var is not None:
                    ssa_vars = set([mlil_dest_ssa_var])
                    # Find other SSA variables having the same pointer assigned
                    ssa_vars |= find_var_assignments(mlil_dest_ssa_var)
                    # Find other aliased SSA variables having the same pointer
                    for alias_ssa_var in alias_map.get(hlil_src_var, set()):
                        ssa_vars |= set([alias_ssa_var]) | find_var_assignments(
                            alias_ssa_var
                        )
                    # Store mappings from MLIL destination variable to HLIL source variable
                    for ssa_var in ssa_vars:
                        ptr_map.setdefault(ssa_var.var, set()).add(hlil_src_var)
        return ptr_map

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
