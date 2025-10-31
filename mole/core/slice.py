from __future__ import annotations
from collections import deque
from mole.common.helper.function import FunctionHelper
from mole.common.helper.instruction import InstructionHelper
from mole.common.helper.variable import VariableHelper
from mole.common.log import log
from mole.core.call import MediumLevelILCallTracker
from mole.core.graph import MediumLevelILFunctionGraph, MediumLevelILInstructionGraph
from typing import Callable, Dict
import binaryninja as bn


tag = "Mole.Slice"


class MediumLevelILBackwardSlicer:
    """
    This class implements backward slicing for MLIL instructions.
    """

    def __init__(
        self,
        bv: bn.BinaryView,
        custom_tag: str = "",
        max_call_level: int = -1,
        max_memory_slice_depth: int = -1,
        cancelled: Callable[[], bool] = None,
    ) -> None:
        self._bv = bv
        self._tag = custom_tag if custom_tag else tag
        self._max_call_level = max_call_level
        self._max_memory_slice_depth = max_memory_slice_depth
        self._cancelled = cancelled if cancelled else lambda: False
        self._call_tracker: MediumLevelILCallTracker = None
        return

    def _slice_ssa_var_definition(
        self, ssa_var: bn.SSAVariable, inst: bn.MediumLevelILInstruction
    ) -> None:
        """
        This method tries to find the instruction containing the SSA variable definition of
        `ssa_var`. It first tries to find the defining instruction within the current function
        `inst.function`. If found, slicing proceeds there. If no defining instruction is found
        within `inst.function`, the method checks whether `ssa_var` is used as a parameter of
        function `inst.function`. If so, the method next distinguishes whether or not slicing
        entered `inst.function`. If slicing entered `inst.function`, nothing needs to be done, since
        we will step out later automatically. If slicing did not enter `inst.function`, the method
        determines all possible callers and follows the corresponding parameter.
        """
        # If an instruction containing the SSA variable definition exists in the current
        # function, proceed slicing there (otherwise try find it in callers)
        inst_def = inst.function.get_ssa_var_definition(ssa_var)
        if inst_def:
            self._slice_backwards(inst_def)
            return
        # Determine all instructions calling the current function
        direct_call_insts = FunctionHelper.get_mlil_direct_call_insts(inst.function)
        indirect_call_insts = FunctionHelper.get_mlil_indirect_call_insts(
            self._bv, inst.function
        )
        # Iterate the current function's parameters
        for param_idx, param_var in enumerate(
            inst.function.source_function.parameter_vars,
            start=1,
        ):
            # Ignore parameters not corresponding to the intended variable
            if param_var != ssa_var.var:
                continue
            ssa_var_info = VariableHelper.get_ssavar_info(ssa_var)
            # Follow the parameter to all possible callers if we did not go down the call graph
            if not self._call_tracker.is_going_downwards():
                for call_inst in direct_call_insts | indirect_call_insts:
                    from_inst = call_inst
                    to_inst = call_inst.params[param_idx - 1]
                    recursion = self._call_tracker.push_func(
                        from_inst, to_inst, reverse=True
                    )
                    from_inst_info = InstructionHelper.get_inst_info(from_inst, False)
                    if not recursion:
                        log.debug(
                            self._tag,
                            f"Follow parameter {param_idx:d} '{ssa_var_info:s}' to possible caller '{from_inst_info:s}'",
                        )
                        self._slice_backwards(to_inst)
                    else:
                        log.debug(
                            self._tag,
                            f"Do not follow parameter {param_idx:d} '{ssa_var_info:s}' to possible caller '{from_inst_info:s}' since recursion detected",
                        )
                    self._call_tracker.pop_func()
            # Follow the parameter in specific caller later
            else:
                log.debug(
                    self._tag,
                    f"Follow parameter {param_idx:d} '{ssa_var_info:s}' when going back to specific caller",
                )
                self._call_tracker.push_param(param_idx)
        return

    def _slice_backwards(
        self,
        inst: bn.MediumLevelILInstruction,
    ) -> None:
        """
        This method backward slices instruction `inst` based on its type.
        """
        # Check if slicing should be cancelled
        if self._cancelled():
            return
        # Check if maximum call level is reached
        call_level = self._call_tracker.get_call_level()
        if self._max_call_level >= 0 and abs(call_level) > self._max_call_level:
            log.debug(self._tag, f"Maximum call level {self._max_call_level:d} reached")
            return
        # Slice instruction
        inst_info = InstructionHelper.get_inst_info(inst)
        # For all non-call instructions stop slicing if we did before in the current call frame
        if not isinstance(
            inst,
            bn.MediumLevelILCallSsa
            | bn.MediumLevelILCallUntypedSsa
            | bn.MediumLevelILTailcallSsa
            | bn.MediumLevelILTailcallUntypedSsa,
        ):
            if self._call_tracker.is_in_current_call_frame(inst):
                log.debug(
                    self._tag,
                    f"Do not follow instruction '{inst_info:s}' since followed before in the current call frame",
                )
                return
        log.debug(self._tag, f"[{call_level:+d}] {inst_info:s}")
        self._call_tracker.push_inst(inst)
        match inst:
            # NOTE: Case order matters
            case bn.MediumLevelILConstPtr(constant=constant):
                # Ignore pointers that are in non-writable segments
                segment = self._bv.get_segment_at(constant)
                if segment and segment.writable:
                    # Iterate all memory defining instructions
                    mem_def_insts = FunctionHelper.get_ssa_memory_definitions(
                        inst.function,
                        inst.ssa_memory_version,
                        self._max_memory_slice_depth,
                    )
                    for mem_def_inst in mem_def_insts:
                        mem_def_inst_info = InstructionHelper.get_inst_info(
                            mem_def_inst, False
                        )
                        # Check if memory defining instruction was followed before
                        if self._call_tracker.is_in_current_mem_def_insts(mem_def_inst):
                            log.debug(
                                self._tag,
                                f"Do not follow instruction '{mem_def_inst_info:s}' since followed before in the current call frame",
                            )
                            continue
                        match mem_def_inst:
                            # Slice calls having the same pointer as parameter
                            case (
                                bn.MediumLevelILCallSsa(params=params)
                                | bn.MediumLevelILCallUntypedSsa(params=params)
                                | bn.MediumLevelILTailcallSsa(params=params)
                                | bn.MediumLevelILTailcallUntypedSsa(params=params)
                            ):
                                followed = False
                                for param in params:
                                    match param:
                                        case bn.MediumLevelILConstPtr(
                                            constant=constant
                                        ) if constant == inst.constant:
                                            log.debug(
                                                self._tag,
                                                f"Follow call instruction '{mem_def_inst_info:s}' since it uses '0x{inst.constant:x}'",
                                            )
                                            self._call_tracker.push_mem_def_inst(
                                                mem_def_inst
                                            )
                                            self._slice_backwards(mem_def_inst)
                                            followed = True
                                    if followed:
                                        break
                                if not followed:
                                    log.debug(
                                        self._tag,
                                        f"Do not follow instruction '{mem_def_inst_info:s}' since it does not use '0x{inst.constant:x}'",
                                    )
                else:
                    log.debug(
                        self._tag,
                        f"Do not follow pointer '0x{constant:x}' since it is in a non-writable segment",
                    )
            case bn.MediumLevelILLoadSsa(src=load_src_inst, size=load_src_size):
                followed = False
                # Iterate all memory defining instructions
                mem_def_insts = FunctionHelper.get_ssa_memory_definitions(
                    inst.function,
                    inst.ssa_memory_version,
                    self._max_memory_slice_depth,
                )
                for mem_def_inst in mem_def_insts:
                    mem_def_inst_info = InstructionHelper.get_inst_info(
                        mem_def_inst, False
                    )
                    # Check if memory defining instruction was followed before
                    if self._call_tracker.is_in_current_mem_def_insts(mem_def_inst):
                        log.debug(
                            self._tag,
                            f"Do not follow instruction '{mem_def_inst_info:s}' since followed before in the current call frame",
                        )
                        continue
                    match mem_def_inst:
                        case bn.MediumLevelILStoreSsa(size=store_dest_size):
                            # Match HLIL instructions
                            if inst.hlil is None or mem_def_inst.hlil is None:
                                continue
                            hlil_load_inst = inst.hlil.ssa_form
                            hlil_store_inst = mem_def_inst.hlil.ssa_form
                            match (hlil_load_inst, hlil_store_inst):
                                # Constant pointer dereferencing
                                case (
                                    bn.HighLevelILDerefSsa(
                                        src=bn.HighLevelILConstPtr(
                                            constant=load_src_addr
                                        )
                                    ),
                                    bn.HighLevelILAssignMemSsa(
                                        dest=bn.HighLevelILDerefSsa(
                                            src=bn.HighLevelILConstPtr(
                                                constant=store_dest_addr
                                            )
                                        )
                                    ),
                                ):
                                    # Ensure store overlaps the load
                                    if (
                                        load_src_addr < store_dest_addr
                                        or load_src_addr + load_src_size
                                        > store_dest_addr + store_dest_size
                                    ):
                                        continue
                                    log.debug(
                                        self._tag,
                                        f"Follow store instruction '{mem_def_inst_info:s}' since it overwrites the memory loaded by '{inst_info:s}'",
                                    )
                                    self._call_tracker.push_mem_def_inst(mem_def_inst)
                                    self._slice_backwards(mem_def_inst)
                                    followed = True
                                    break
                                # Variable dereferencing
                                case (
                                    bn.HighLevelILDerefSsa(
                                        src=bn.HighLevelILVarSsa(var=load_var)
                                    ),
                                    bn.HighLevelILAssignMemSsa(
                                        dest=bn.HighLevelILDerefSsa(
                                            src=bn.HighLevelILVarSsa(var=store_var)
                                        )
                                    ),
                                ):
                                    # Ensure load from and store to the same variable
                                    if load_var != store_var:
                                        continue
                                    log.debug(
                                        self._tag,
                                        f"Follow store instruction '{mem_def_inst_info:s}' since it writes the same variable ('{str(hlil_load_inst):s}') as load instruction '{inst_info:s}'",
                                    )
                                    self._call_tracker.push_mem_def_inst(mem_def_inst)
                                    self._slice_backwards(mem_def_inst)
                                    followed = True
                                    break
                                # Variable with offset dereferencing
                                case (
                                    bn.HighLevelILDerefSsa(
                                        src=bn.HighLevelILAdd(
                                            left=bn.HighLevelILVarSsa(var=load_var),
                                            right=bn.HighLevelILConst(
                                                constant=load_offset
                                            ),
                                        )
                                    ),
                                    bn.HighLevelILAssignMemSsa(
                                        dest=bn.HighLevelILDerefSsa(
                                            src=bn.HighLevelILAdd(
                                                left=bn.HighLevelILVarSsa(
                                                    var=store_var
                                                ),
                                                right=bn.HighLevelILConst(
                                                    constant=store_offset
                                                ),
                                            )
                                        )
                                    ),
                                ):
                                    # Ensure load from and store to the same variable and offset
                                    if (
                                        load_var != store_var
                                        or load_offset != store_offset
                                    ):
                                        continue
                                    log.debug(
                                        self._tag,
                                        f"Follow store instruction '{mem_def_inst_info:s}' since it writes the same variable ('{str(hlil_load_inst):s}') as load instruction '{inst_info:s}'",
                                    )
                                    self._call_tracker.push_mem_def_inst(mem_def_inst)
                                    self._slice_backwards(mem_def_inst)
                                    followed = True
                                    break
                                # Array indexing
                                case (
                                    bn.HighLevelILArrayIndexSsa(
                                        src=bn.HighLevelILVarSsa(
                                            var=load_var,
                                        ),
                                        index=bn.HighLevelILConst(constant=load_index),
                                    ),
                                    bn.HighLevelILAssignMemSsa(
                                        dest=bn.HighLevelILArrayIndexSsa(
                                            src=bn.HighLevelILVarSsa(var=store_var),
                                            index=bn.HighLevelILConst(
                                                constant=store_index
                                            ),
                                        )
                                    ),
                                ):
                                    # Ensure load from and store to the same array element
                                    if (
                                        load_var != store_var
                                        or load_index != store_index
                                    ):
                                        continue
                                    log.debug(
                                        self._tag,
                                        f"Follow store instruction '{mem_def_inst_info:s}' since it writes the same array element ('{str(hlil_load_inst):s}') as load instruction '{inst_info:s}'",
                                    )
                                    self._call_tracker.push_mem_def_inst(mem_def_inst)
                                    self._slice_backwards(mem_def_inst)
                                    followed = True
                                    break
                # Follow load source instruction if no specific store instruction was followed
                if not followed:
                    load_src_inst_info = InstructionHelper.get_inst_info(
                        load_src_inst, False
                    )
                    log.debug(
                        self._tag,
                        f"Follow load source instruction '{load_src_inst_info:s}' since no specific store instruction was found",
                    )
                    self._slice_backwards(load_src_inst)
            case bn.MediumLevelILLoadStructSsa(
                src=load_src_inst, offset=load_src_offset
            ):
                followed = False
                # Iterate all memory defining instructions
                mem_def_insts = FunctionHelper.get_ssa_memory_definitions(
                    inst.function,
                    inst.ssa_memory_version,
                    self._max_memory_slice_depth,
                )
                for mem_def_inst in mem_def_insts:
                    mem_def_inst_info = InstructionHelper.get_inst_info(
                        mem_def_inst, False
                    )
                    # Check if memory defining instruction was followed before
                    if self._call_tracker.is_in_current_mem_def_insts(mem_def_inst):
                        log.debug(
                            self._tag,
                            f"Do not follow instruction '{mem_def_inst_info:s}' since followed before in the current call frame",
                        )
                        continue
                    match mem_def_inst:
                        case bn.MediumLevelILStoreSsa(size=store_dest_size):
                            # Match HLIL instructions
                            if inst.hlil is None or mem_def_inst.hlil is None:
                                continue
                            hlil_load_inst = inst.hlil.ssa_form
                            hlil_store_inst = mem_def_inst.hlil.ssa_form
                            match (hlil_load_inst, hlil_store_inst):
                                # Struct field dereferencing
                                case (
                                    bn.HighLevelILDerefFieldSsa(
                                        src=bn.HighLevelILVarSsa(var=load_var),
                                        offset=load_offset,
                                    ),
                                    bn.HighLevelILAssignMemSsa(
                                        dest=bn.HighLevelILDerefSsa(
                                            src=bn.HighLevelILVarSsa(var=store_var)
                                        )
                                    ),
                                ):
                                    # Ensure load from and store to the same struct field
                                    if load_var != store_var or load_offset != 0:
                                        continue
                                    log.debug(
                                        self._tag,
                                        f"Follow store struct instruction '{mem_def_inst_info:s}' since it writes the same struct member '{str(hlil_load_inst):s}' as load struct instruction '{inst_info:s}'",
                                    )
                                    self._call_tracker.push_mem_def_inst(mem_def_inst)
                                    self._slice_backwards(mem_def_inst)
                                    followed = True
                                    break
                        case bn.MediumLevelILStoreStructSsa(offset=store_dest_offset):
                            # Ensure load from and store to the same struct field
                            if load_src_offset != store_dest_offset:
                                continue
                            # Match HLIL instructions
                            if inst.hlil is None or mem_def_inst.hlil is None:
                                continue
                            hlil_load_inst = inst.hlil.ssa_form
                            hlil_store_inst = mem_def_inst.hlil.ssa_form
                            match (hlil_load_inst, hlil_store_inst):
                                # Struct field dereferencing
                                case (
                                    bn.HighLevelILDerefFieldSsa(
                                        src=bn.HighLevelILVarSsa(
                                            var=load_var,
                                        ),
                                        offset=load_offset,
                                    ),
                                    bn.HighLevelILAssignMemSsa(
                                        dest=bn.HighLevelILDerefFieldSsa(
                                            src=bn.HighLevelILVarSsa(
                                                var=store_var,
                                            ),
                                            offset=store_offset,
                                        )
                                    ),
                                ):
                                    # Ensure load from and store to the same struct field
                                    if (
                                        load_var != store_var
                                        or load_offset != store_offset
                                    ):
                                        continue
                                    log.debug(
                                        self._tag,
                                        f"Follow store struct instruction '{mem_def_inst_info:s}' since it writes the same struct member '{str(hlil_load_inst):s}' as load struct instruction '{inst_info:s}'",
                                    )
                                    self._call_tracker.push_mem_def_inst(mem_def_inst)
                                    self._slice_backwards(mem_def_inst)
                                    followed = True
                                    break
                # Follow load source instruction if no specific store instruction was followed
                if not followed:
                    load_src_inst_info = InstructionHelper.get_inst_info(
                        load_src_inst, False
                    )
                    log.debug(
                        self._tag,
                        f"Follow load struct source instruction '{load_src_inst_info:s}' since no specific struct store instruction was found",
                    )
                    self._slice_backwards(load_src_inst)
            case (
                bn.MediumLevelILVarAliased()
                | bn.MediumLevelILVarAliasedField()
                | bn.MediumLevelILAddressOf()
                | bn.MediumLevelILAddressOfField()
            ):
                # Get all assignment instructions of the form `var_x = &var_y` in the current
                # function
                var_addr_assignments = FunctionHelper.get_var_addr_assignments(
                    inst.function
                )
                # Get variable being referenced by `inst` (`var_y`)
                # TODO: Should we consider the `offset` in MLIL_VAR_ALIASED_FIELD and
                # MLIL_ADDRESS_OF_FIELD as well?
                match inst:
                    case (
                        bn.MediumLevelILVarAliased(src=src)
                        | bn.MediumLevelILVarAliasedField(src=src)
                    ):
                        var = src.var
                    case (
                        bn.MediumLevelILAddressOf(src=src)
                        | bn.MediumLevelILAddressOfField(src=src)
                    ):
                        var = src
                var_info = VariableHelper.get_var_info(var)
                # Get all assignment instructions (`var_x = &var_y`) using the address of the
                # referenced variable (`var_y`) as a source
                var_addr_ass_insts = var_addr_assignments.get(var, [])
                # Get all use sites (e.g. `var_z = call(var_x)`) of assignment instructions'
                # destinations (`var_x`)
                dest_var_use_sites: Dict[
                    bn.MediumLevelILInstruction, bn.MediumLevelILSetVarSsa
                ] = {}
                for var_addr_ass_inst in var_addr_ass_insts:
                    for dest_var_use_site in var_addr_ass_inst.dest.use_sites:
                        dest_var_use_sites[dest_var_use_site] = var_addr_ass_inst
                # Iterate all instructions in the current function defining the current memory
                # version
                mem_def_insts = FunctionHelper.get_ssa_memory_definitions(
                    inst.function,
                    inst.ssa_memory_version,
                    self._max_memory_slice_depth,
                )
                for mem_def_inst in mem_def_insts:
                    mem_def_inst_info = InstructionHelper.get_inst_info(
                        mem_def_inst, False
                    )
                    # Check if memory defining instruction is in the use sites
                    if mem_def_inst not in dest_var_use_sites:
                        log.debug(
                            self._tag,
                            f"Do not follow instruction '{mem_def_inst_info:s}' since it not uses '&{var_info:s}'",
                        )
                        continue
                    # Check if memory defining instruction was followed before
                    if self._call_tracker.is_in_current_mem_def_insts(mem_def_inst):
                        log.debug(
                            self._tag,
                            f"Do not follow instruction '{mem_def_inst_info:s}' since followed before in the current call frame",
                        )
                        continue

                    match mem_def_inst:
                        # Slice calls having the referenced variable address (`&var_y`) as parameter
                        case (
                            bn.MediumLevelILCallSsa(params=params)
                            | bn.MediumLevelILCallUntypedSsa(params=params)
                            | bn.MediumLevelILTailcallSsa(params=params)
                            | bn.MediumLevelILTailcallUntypedSsa(params=params)
                        ):
                            var_addr_ass_inst = dest_var_use_sites[mem_def_inst]
                            var_addr_ass_inst_info = InstructionHelper.get_inst_info(
                                var_addr_ass_inst, False
                            )
                            log.debug(
                                self._tag,
                                f"Follow call instruction '{mem_def_inst_info:s}' since it uses '{var_addr_ass_inst_info:s}'",
                            )
                            self._call_tracker.push_mem_def_inst(mem_def_inst)
                            self._slice_backwards(mem_def_inst)
            case (
                bn.MediumLevelILVarSsa()
                | bn.MediumLevelILVarSsaField()
                | bn.MediumLevelILVarField()
                | bn.MediumLevelILUnimplMem()
                | bn.MediumLevelILForceVerSsa()
            ):
                self._slice_ssa_var_definition(inst.src, inst)
            case bn.MediumLevelILRet():
                for ret_inst in inst.src:
                    self._slice_backwards(ret_inst)
            case bn.MediumLevelILVarSplitSsa():
                self._slice_ssa_var_definition(inst.high, inst)
                self._slice_ssa_var_definition(inst.low, inst)
            case bn.MediumLevelILVarPhi():
                for var in inst.src:
                    self._slice_ssa_var_definition(var, inst)
            case (
                bn.MediumLevelILCallSsa(dest=dest_inst)
                | bn.MediumLevelILCallUntypedSsa(dest=dest_inst)
                | bn.MediumLevelILTailcallSsa(dest=dest_inst)
                | bn.MediumLevelILTailcallUntypedSsa(dest=dest_inst)
            ):
                inst_info = InstructionHelper.get_inst_info(inst, False)
                dest_inst_info = InstructionHelper.get_inst_info(dest_inst, False)
                match dest_inst:
                    # Direct function calls
                    case (
                        bn.MediumLevelILConstPtr(constant=func_addr)
                        | bn.MediumLevelILImport(constant=func_addr)
                    ):
                        # Get destination function
                        dest_func = self._bv.get_function_at(func_addr)
                        # Proceed slicing the parameters if we cannot go into the callee (callee is
                        # not a valid function - e.g. external function)
                        if (
                            not dest_func
                            or not dest_func.mlil
                            or not dest_func.mlil.ssa_form
                        ):
                            for param in inst.params:
                                self._slice_backwards(param)
                        # Proceed slicing the callee's return instructions if we can go into the
                        # callee (callee is a valid function)
                        else:
                            dest_func = dest_func.mlil.ssa_form
                            dest_symb = dest_func.source_function.symbol
                            followed_mem_def_inst = (
                                self._call_tracker.is_in_current_mem_def_insts(
                                    inst, offset=-1
                                )
                            )
                            for dest_func_inst in dest_func.instructions:
                                match dest_func_inst:
                                    case (
                                        bn.MediumLevelILRet()
                                        | bn.MediumLevelILTailcallSsa()
                                    ):
                                        # Function
                                        if dest_symb.type in [
                                            bn.SymbolType.FunctionSymbol,
                                            bn.SymbolType.LibraryFunctionSymbol,
                                        ]:
                                            from_inst = inst
                                            to_inst = dest_func_inst
                                            recursion = self._call_tracker.push_func(
                                                from_inst, to_inst
                                            )
                                            to_inst_info = (
                                                InstructionHelper.get_inst_info(
                                                    to_inst, False
                                                )
                                            )
                                            if not recursion:
                                                # Slice callee's return instructions
                                                log.debug(
                                                    self._tag,
                                                    f"Follow return instruction '{to_inst_info:s}' of function '{dest_inst_info:s}'",
                                                )
                                                self._slice_backwards(to_inst)
                                                # Slice callee's output parameters if we followed
                                                # the call due to a pointer parameter
                                                if followed_mem_def_inst:
                                                    # Iterate all memory defining instructions
                                                    mem_def_insts = FunctionHelper.get_ssa_memory_definitions(
                                                        dest_func,
                                                        to_inst.ssa_memory_version,
                                                        self._max_memory_slice_depth,
                                                    )
                                                    for mem_def_inst in mem_def_insts:
                                                        mem_def_inst_info = InstructionHelper.get_inst_info(
                                                            mem_def_inst, False
                                                        )
                                                        # Check if memory defining instruction was followed before
                                                        if self._call_tracker.is_in_current_mem_def_insts(
                                                            mem_def_inst
                                                        ):
                                                            log.debug(
                                                                self._tag,
                                                                f"Do not follow instruction '{mem_def_inst_info:s}' since followed before in the current call frame",
                                                            )
                                                            continue
                                                        match mem_def_inst:
                                                            case bn.MediumLevelILStoreSsa(
                                                                size=store_dest_size
                                                            ):
                                                                # Match HLIL instruction
                                                                if (
                                                                    mem_def_inst.hlil
                                                                    is None
                                                                ):
                                                                    continue
                                                                hlil_mem_def_inst = mem_def_inst.hlil.ssa_form
                                                                match hlil_mem_def_inst:
                                                                    # Memory assignment to dereferenced variable
                                                                    case bn.HighLevelILAssignMemSsa(
                                                                        dest=bn.HighLevelILDerefSsa(
                                                                            src=bn.HighLevelILVarSsa(
                                                                                var=dest_var
                                                                            )
                                                                        )
                                                                    ):
                                                                        # Ensure we store to a parameter variable
                                                                        if not dest_var.var.is_parameter_variable:
                                                                            continue
                                                                        dest_var_info = VariableHelper.get_ssavar_info(
                                                                            dest_var
                                                                        )
                                                                        log.debug(
                                                                            self._tag,
                                                                            f"Follow instruction '{mem_def_inst_info:s}' since it writes the output parameter variable '{dest_var_info:s}'",
                                                                        )
                                                                        self._slice_backwards(
                                                                            mem_def_inst
                                                                        )
                                            else:
                                                log.debug(
                                                    self._tag,
                                                    f"Do not follow return instruction '{to_inst_info:s}' of function '{dest_inst_info:s}' since recursion detected",
                                                )
                                            # Get call level of the callee
                                            call_level = (
                                                self._call_tracker.get_call_level()
                                            )
                                            # Get parameters reached in the callee
                                            param_idxs = self._call_tracker.pop_func()
                                            # If maximum call level was reached in the callee, slice
                                            # all parameters
                                            if (
                                                self._max_call_level >= 0
                                                and abs(call_level)
                                                > self._max_call_level
                                            ):
                                                for param in inst.params:
                                                    self._slice_backwards(param)
                                            # If maximum call level was not reached in the callee,
                                            # slice only the specifically reached parameters
                                            else:
                                                for param_idx in param_idxs:
                                                    self._slice_backwards(
                                                        inst.params[param_idx - 1]
                                                    )
                                        # Imported function
                                        elif (
                                            dest_symb.type
                                            == bn.SymbolType.ImportedFunctionSymbol
                                        ):
                                            for param in inst.params:
                                                self._slice_backwards(param)
                    # Indirect function calls
                    case bn.MediumLevelILVarSsa():
                        for param in inst.params:
                            self._slice_backwards(param)
                    # Unhandled function calls
                    case _:
                        log.warn(
                            self._tag,
                            f"[{call_level:+d}] {dest_inst_info:s}: Missing call handler",
                        )
            case (
                bn.MediumLevelILSyscallSsa()
                | bn.MediumLevelILSyscallUntypedSsa()
                | bn.MediumLevelILIntrinsicSsa()
                | bn.MediumLevelILSeparateParamList()
            ):
                for param in inst.params:
                    self._slice_backwards(param)
            case (
                bn.MediumLevelILConstBase()
                | bn.MediumLevelILNop()
                | bn.MediumLevelILBp()
                | bn.MediumLevelILTrap()
                | bn.MediumLevelILFreeVarSlotSsa()
                | bn.MediumLevelILUndef()
                | bn.MediumLevelILUnimpl()
            ):
                pass
            case (
                bn.MediumLevelILSetVarSsa()
                | bn.MediumLevelILSetVarAliased()
                | bn.MediumLevelILSetVarAliasedField()
                | bn.MediumLevelILSetVarSsaField()
                | bn.MediumLevelILSetVarSplitSsa()
                | bn.MediumLevelILUnaryBase()
                | bn.MediumLevelILBoolToInt()
                | bn.MediumLevelILStoreSsa()
                | bn.MediumLevelILStoreStructSsa()
            ):
                self._slice_backwards(inst.src)
            case bn.MediumLevelILBinaryBase() | bn.MediumLevelILCarryBase():
                self._slice_backwards(inst.left)
                self._slice_backwards(inst.right)
            case bn.MediumLevelILJump() | bn.MediumLevelILJumpTo():
                self._slice_backwards(inst.dest)
            case _:
                log.warn(
                    self._tag,
                    f"[{call_level:+d}] {inst_info:s}: Missing instruction handler",
                )
        self._call_tracker.pop_inst()
        return

    def slice_backwards(self, inst: bn.MediumLevelILInstruction) -> None:
        """
        This method backward slices the instruction `inst`.
        """
        self._call_tracker = MediumLevelILCallTracker()
        self._call_tracker.push_func(None, inst, reverse=True)
        deque(
            inst.ssa_form.traverse(lambda inst: self._slice_backwards(inst)),
            maxlen=0,
        )
        self._call_tracker.pop_func()
        return

    def get_call_graph(self) -> MediumLevelILFunctionGraph:
        """
        This method returns the call graph built during slicing.
        """
        if not self._call_tracker:
            return MediumLevelILFunctionGraph()
        return self._call_tracker.get_call_graph()

    def get_inst_graph(self) -> MediumLevelILInstructionGraph:
        """
        This method returns the instruction graph built during slicing.
        """
        if not self._call_tracker:
            return MediumLevelILInstructionGraph()
        return self._call_tracker.get_inst_graph()
