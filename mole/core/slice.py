from __future__ import annotations
from collections import deque
from mole.common.helper.function import FunctionHelper
from mole.common.helper.instruction import InstructionHelper
from mole.common.helper.variable import VariableHelper
from mole.common.log import log
from mole.core.call import MediumLevelILCallTracker
from mole.core.graph import MediumLevelILFunctionGraph, MediumLevelILInstructionGraph
from typing import Callable, Set, Tuple
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

    def _is_ptr_equivalent(
        self,
        ssa_var: bn.MediumLevelILVarSsa,
        offset: int,
        param_inst: bn.MediumLevelILInstruction,
    ) -> Tuple[bool, str]:
        """
        TODO
        """
        match param_inst:
            # `var == &param_var`
            case bn.MediumLevelILAddressOf(src=param_var):
                if ssa_var.var == param_var:
                    return True, ""
            # `var.offset == &param_var.offset`
            case bn.MediumLevelILAddressOfField(src=param_var, offset=param_offset):
                if ssa_var.var == param_var and offset == param_offset:
                    return True, ""
            # `ptr_var == param_ptr_var` or `ptr_var == &(*param_ptr_var)[index]`
            case bn.MediumLevelILVarSsa(var=param_ssa_var):
                # Get pointer map for the current function
                ptr_map = FunctionHelper.get_ptr_map(param_inst.function)
                # Get pointer instructions for `ssa_var` and `param_ssa_var`
                ptr_inst = ptr_map.get(ssa_var, None)
                param_ptr_inst = ptr_map.get(param_ssa_var, None)
                # Ensure valid pointer instructions
                if ptr_inst is None or param_ptr_inst is None:
                    return False, ""
                # Compare pointer instructions
                match (ptr_inst, param_ptr_inst):
                    # `ptr_var == param_ptr_var`
                    case (
                        # `ptr_var`
                        bn.HighLevelILVar(var=ptr_var),
                        # `param_ptr_var`
                        bn.HighLevelILVar(var=param_ptr_var),
                    ):
                        if ptr_var == param_ptr_var:
                            return True, str(ptr_inst)
                    # `ptr_var == (*param_ptr_var)[index]`
                    case (
                        # `ptr_var`
                        bn.HighLevelILVar(),
                        # `(*param_ptr_var)[index]`
                        bn.HighLevelILArrayIndex(
                            src=bn.HighLevelILDerefSsa(
                                src=bn.HighLevelILVarSsa(var=param_ptr_ssa_var)
                            )
                        ),
                    ):
                        if ptr_inst == ptr_map.get(param_ptr_ssa_var, None):
                            return True, str(ptr_inst)
                    # `ptr_var[ptr_index] == param_ptr_var[param_ptr_index]`
                    case (
                        # `ptr_var[ptr_index]`
                        bn.HighLevelILArrayIndex(
                            src=bn.HighLevelILVarSsa(var=ptr_var),
                            index=bn.HighLevelILConst(constant=ptr_index),
                        ),
                        # `param_ptr_var[param_ptr_index]`
                        bn.HighLevelILArrayIndex(
                            src=bn.HighLevelILVarSsa(var=param_ptr_var),
                            index=bn.HighLevelILConst(constant=param_ptr_index),
                        ),
                    ):
                        if ptr_var == param_ptr_var and ptr_index == param_ptr_index:
                            return True, str(ptr_inst)
        return False, ""

    def _slice_todo(
        self,
        ssa_var: bn.SSAVariable,
        offset: int,
        mem_def_inst: bn.MediumLevelILInstruction,
    ) -> None:
        """
        This method matches a memory defining instruction `mem_def_inst` against the following
        cases:
        - If `mem_def_inst` is an assignment to an alias of `ssa_var`, slice its source
        - If `mem_def_inst` is an assignment to an aliased field of `ssa_var`, slice its source
        - If `mem_def_inst` is a call using a pointer to `ssa_var` as parameter, slice the call
        """
        ssa_var_info = VariableHelper.get_ssavar_info(ssa_var)
        # Ensure memory defining instruction has not yet been followed in the current call frame
        mem_def_inst_info = InstructionHelper.get_inst_info(mem_def_inst, False)
        if self._call_tracker.is_in_current_mem_def_insts(mem_def_inst):
            log.debug(
                self._tag,
                f"Do not follow instruction '{mem_def_inst_info:s}' since followed before in the current call frame",
            )
            return
        # Match memory defining instruction
        match mem_def_inst:
            # Slice the source of assignments having an alias of `var` as destination
            case bn.MediumLevelILSetVarAliased(
                prev=prev_ssa_var,
                dest=dest_ssa_var,
                src=src_inst,
            ):
                if (
                    prev_ssa_var.var == dest_ssa_var.var == ssa_var.var
                    and prev_ssa_var.version + 1
                    == dest_ssa_var.version
                    <= ssa_var.version
                ):
                    log.debug(
                        self._tag,
                        f"Follow source of instruction '{mem_def_inst_info:s}' since it writes to an alias of '{ssa_var_info:s}'",
                    )
                    self._call_tracker.push_mem_def_inst(mem_def_inst)
                    self._slice_backwards(src_inst)
            # Slice the source of assignments having an aliased field of `var` as destination
            case bn.MediumLevelILSetVarAliasedField(
                prev=prev_ssa_var,
                dest=dest_ssa_var,
                offset=dest_offset,
                src=src_inst,
            ):
                if (
                    prev_ssa_var.var == dest_ssa_var.var == ssa_var.var
                    and prev_ssa_var.version + 1
                    == dest_ssa_var.version
                    <= ssa_var.version
                    and dest_offset == offset
                ):
                    log.debug(
                        self._tag,
                        f"Follow source of instruction '{mem_def_inst_info:s}' since it writes to an alias of '{ssa_var_info:s}.{dest_offset:d}'",
                    )
                    self._call_tracker.push_mem_def_inst(mem_def_inst)
                    self._slice_backwards(src_inst)
            # Slice calls having a pointer to `var` as parameter
            case (
                bn.MediumLevelILCallSsa(params=params)
                | bn.MediumLevelILCallUntypedSsa(params=params)
                | bn.MediumLevelILTailcallSsa(params=params)
                | bn.MediumLevelILTailcallUntypedSsa(params=params)
            ):
                # Find set of call parameters the slicer should follow
                ptr_inst_str = ""
                call_params: Set[int] = set()
                for param_idx, param_inst in enumerate(params, start=1):
                    is_ptr_equal, ptr_inst_str = self._is_ptr_equivalent(
                        ssa_var, offset, param_inst
                    )
                    if is_ptr_equal:
                        call_params.add(param_idx)

                # Slice the call instruction if we need to follow any parameter
                if call_params:
                    params_str = (
                        "parameter " if len(call_params) == 1 else "parameters "
                    )
                    params_str += ", ".join(map(str, call_params))
                    ptr_str = (
                        f"'{ssa_var_info:s} = &{ptr_inst_str:s}'"
                        if ptr_inst_str
                        else f"'&{ssa_var_info:s}'"
                    )
                    log.debug(
                        self._tag,
                        f"Follow call instruction '{mem_def_inst_info:s}' since it uses {ptr_str:s} in {params_str:s}",
                    )
                    self._call_tracker.push_mem_def_inst(mem_def_inst)
                    self._slice_backwards(mem_def_inst, call_params)
        return

    def _slice_var_mem_definitions(
        self, ssa_var: bn.SSAVariable, inst: bn.MediumLevelILInstruction
    ) -> None:
        """
        This method iterates all instructions in the function `inst.function` that define the
        current memory version `inst.ssa_memory_version`. A memory defining instruction
        `mem_def_inst` is then matched against the following cases:
        - If `mem_def_inst` is an assignment to an alias of `ssa_var`, slice its source
        - If `mem_def_inst` is an assignment to an aliased field of `ssa_var`, slice its source
        - If `mem_def_inst` is a call using a pointer to `ssa_var` as parameter, slice the call
        """
        # ssa_var_info = VariableHelper.get_ssavar_info(ssa_var)
        # Get offset if applicable
        offset = getattr(inst, "offset", 0)
        # Get instructions defining the memory version of `inst`
        mem_def_insts = FunctionHelper.get_ssa_memory_definitions(
            inst.function, inst.ssa_memory_version, self._max_memory_slice_depth
        )
        # Iterate memory defining instructions
        for mem_def_inst in mem_def_insts:
            self._slice_todo(ssa_var, offset, mem_def_inst)
            # # Ensure memory defining instruction has not yet been followed in the current call frame
            # mem_def_inst_info = InstructionHelper.get_inst_info(mem_def_inst, False)
            # if self._call_tracker.is_in_current_mem_def_insts(mem_def_inst):
            #     log.debug(
            #         self._tag,
            #         f"Do not follow instruction '{mem_def_inst_info:s}' since followed before in the current call frame",
            #     )
            #     continue
            # # Match memory defining instruction
            # match mem_def_inst:
            #     # Slice the source of assignments having an alias of `var` as destination
            #     case bn.MediumLevelILSetVarAliased(
            #         prev=prev_ssa_var,
            #         dest=dest_ssa_var,
            #         src=src_inst,
            #     ):
            #         if (
            #             prev_ssa_var.var == dest_ssa_var.var == ssa_var.var
            #             and prev_ssa_var.version + 1
            #             == dest_ssa_var.version
            #             <= ssa_var.version
            #         ):
            #             log.debug(
            #                 self._tag,
            #                 f"Follow source of instruction '{mem_def_inst_info:s}' since it writes to an alias of '{ssa_var_info:s}'",
            #             )
            #             self._call_tracker.push_mem_def_inst(mem_def_inst)
            #             self._slice_backwards(src_inst)
            #     # Slice the source of assignments having an aliased field of `var` as destination
            #     case bn.MediumLevelILSetVarAliasedField(
            #         prev=prev_ssa_var,
            #         dest=dest_ssa_var,
            #         offset=dest_offset,
            #         src=src_inst,
            #     ):
            #         if (
            #             prev_ssa_var.var == dest_ssa_var.var == ssa_var.var
            #             and prev_ssa_var.version + 1
            #             == dest_ssa_var.version
            #             <= ssa_var.version
            #             and dest_offset == offset
            #         ):
            #             log.debug(
            #                 self._tag,
            #                 f"Follow source of instruction '{mem_def_inst_info:s}' since it writes to an alias of '{ssa_var_info:s}.{dest_offset:d}'",
            #             )
            #             self._call_tracker.push_mem_def_inst(mem_def_inst)
            #             self._slice_backwards(src_inst)
            #     # Slice calls having a pointer to `var` as parameter
            #     case (
            #         bn.MediumLevelILCallSsa(params=params)
            #         | bn.MediumLevelILCallUntypedSsa(params=params)
            #         | bn.MediumLevelILTailcallSsa(params=params)
            #         | bn.MediumLevelILTailcallUntypedSsa(params=params)
            #     ):
            #         # Find set of call parameters the slicer should follow
            #         ptr_inst_str = ""
            #         call_params: Set[int] = set()
            #         for param_idx, param_inst in enumerate(params, start=1):
            #             is_ptr_equal, ptr_inst_str = self._is_ptr_equivalent(
            #                 ssa_var, offset, param_inst
            #             )
            #             if is_ptr_equal:
            #                 call_params.add(param_idx)
            #             # # Match parameter instruction
            #             # match param_inst:
            #             #     # `var == &param_var`
            #             #     case bn.MediumLevelILAddressOf(src=param_var):
            #             #         if ssa_var.var == param_var:
            #             #             call_params.add(param_idx)
            #             #     # `var.offset == &param_var.offset`
            #             #     case bn.MediumLevelILAddressOfField(
            #             #         src=param_var, offset=param_offset
            #             #     ):
            #             #         if ssa_var.var == param_var and offset == param_offset:
            #             #             call_params.add(param_idx)
            #             #     # `ptr_var == param_ptr_var` or `ptr_var == &(*param_ptr_var)[index]`
            #             #     case bn.MediumLevelILVarSsa(var=param_ssa_var):
            #             #         # Get pointer map for the current function
            #             #         ptr_map = FunctionHelper.get_ptr_map(inst.function)
            #             #         # Get pointer instructions for `ssa_var` and `param_ssa_var`
            #             #         ptr_inst = ptr_map.get(ssa_var, None)
            #             #         param_ptr_inst = ptr_map.get(param_ssa_var, None)
            #             #         # Ensure valid pointer instructions
            #             #         if ptr_inst is None or param_ptr_inst is None:
            #             #             continue
            #             #         # Compare pointer instructions
            #             #         match (ptr_inst, param_ptr_inst):
            #             #             # `ptr_var == param_ptr_var`
            #             #             case (
            #             #                 # `ptr_var`
            #             #                 bn.HighLevelILVar(var=ptr_var),
            #             #                 # `param_ptr_var`
            #             #                 bn.HighLevelILVar(var=param_ptr_var),
            #             #             ):
            #             #                 if ptr_var == param_ptr_var:
            #             #                     call_params.add(param_idx)
            #             #                     ptr_inst_str = str(ptr_inst)
            #             #             # `ptr_var == (*param_ptr_var)[index]`
            #             #             case (
            #             #                 # `ptr_var`
            #             #                 bn.HighLevelILVar(),
            #             #                 # `(*param_ptr_var)[index]`
            #             #                 bn.HighLevelILArrayIndex(
            #             #                     src=bn.HighLevelILDerefSsa(
            #             #                         src=bn.HighLevelILVarSsa(
            #             #                             var=param_ptr_ssa_var
            #             #                         )
            #             #                     )
            #             #                 ),
            #             #             ):
            #             #                 if ptr_inst == ptr_map.get(
            #             #                     param_ptr_ssa_var, None
            #             #                 ):
            #             #                     call_params.add(param_idx)
            #             #                     ptr_inst_str = str(ptr_inst)
            #             #             # `ptr_var[ptr_index] == param_ptr_var[param_ptr_index]`
            #             #             case (
            #             #                 # `ptr_var[ptr_index]`
            #             #                 bn.HighLevelILArrayIndex(
            #             #                     src=bn.HighLevelILVarSsa(var=ptr_var),
            #             #                     index=bn.HighLevelILConst(
            #             #                         constant=ptr_index
            #             #                     ),
            #             #                 ),
            #             #                 # `param_ptr_var[param_ptr_index]`
            #             #                 bn.HighLevelILArrayIndex(
            #             #                     src=bn.HighLevelILVarSsa(var=param_ptr_var),
            #             #                     index=bn.HighLevelILConst(
            #             #                         constant=param_ptr_index
            #             #                     ),
            #             #                 ),
            #             #             ):
            #             #                 if (
            #             #                     ptr_var == param_ptr_var
            #             #                     and ptr_index == param_ptr_index
            #             #                 ):
            #             #                     call_params.add(param_idx)
            #             #                     ptr_inst_str = str(ptr_inst)

            #         # Slice the call instruction if we need to follow any parameter
            #         if call_params:
            #             params_str = (
            #                 "parameter " if len(call_params) == 1 else "parameters "
            #             )
            #             params_str += ", ".join(map(str, call_params))
            #             ptr_str = (
            #                 f"'{ssa_var_info:s} = &{ptr_inst_str:s}'"
            #                 if ptr_inst_str
            #                 else f"'&{ssa_var_info:s}'"
            #             )
            #             log.debug(
            #                 self._tag,
            #                 f"Follow call instruction '{mem_def_inst_info:s}' since it uses {ptr_str:s} in {params_str:s}",
            #             )
            #             self._call_tracker.push_mem_def_inst(mem_def_inst)
            #             self._slice_backwards(mem_def_inst, call_params)
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
        var_info = VariableHelper.get_var_info(ssa_var.var)
        # Slice all memory defining instructions using the variable
        self._slice_var_mem_definitions(ssa_var, inst)
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
            # Follow the parameter to all possible callers if we go up the call graph
            if not self._call_tracker.is_going_downwards():
                for call_inst in direct_call_insts | indirect_call_insts:
                    from_inst = call_inst
                    to_inst = call_inst.params[param_idx - 1]
                    recursion = self._call_tracker.push_func(
                        to_inst=to_inst,
                        reverse=True,
                        param_idx=param_idx,
                    )
                    from_inst_info = InstructionHelper.get_inst_info(from_inst, False)
                    if not recursion:
                        log.debug(
                            self._tag,
                            f"Follow parameter {param_idx:d} '{var_info:s}' to possible caller '{from_inst_info:s}'",
                        )
                        self._slice_backwards(to_inst)
                    else:
                        log.debug(
                            self._tag,
                            f"Do not follow parameter {param_idx:d} '{var_info:s}' to possible caller '{from_inst_info:s}' since recursion detected",
                        )
                    self._call_tracker.pop_func()
            # Follow the parameter in specific caller later
            else:
                log.debug(
                    self._tag,
                    f"Follow parameter {param_idx:d} '{var_info:s}' when going back to specific caller",
                )
                self._call_tracker.add_func_param(param_idx)
        return

    def _slice_backwards(
        self, inst: bn.MediumLevelILInstruction, call_params: Set[int] = set()
    ) -> None:
        """
        This method backward slices instruction `inst` based on its type. `call_params` is a set of
        parameters (indices) used to distinguish whether the slicer reached the last call
        instruction due to hitting some parameters (in which case slicing proceeds at the definition
        sites of these parameters) or due to hitting the call's return value (in which case slicing
        proceeds at all possible return instructions).
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
        self._call_tracker.push_inst(inst, call_params)
        match inst:
            # NOTE: Case order matters
            case bn.MediumLevelILConstPtr(constant=constant):
                # Ignore pointers that are in non-writable segments
                segment = self._bv.get_segment_at(constant)
                if segment and segment.writable:
                    # Get instructions defining the memory version of `inst`
                    mem_def_insts = FunctionHelper.get_ssa_memory_definitions(
                        inst.function,
                        inst.ssa_memory_version,
                        self._max_memory_slice_depth,
                    )
                    # Iterate memory defining instructions
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
                                for param_idx, param in enumerate(params, start=1):
                                    match param:
                                        case bn.MediumLevelILConstPtr(
                                            constant=constant
                                        ) if constant == inst.constant:
                                            log.debug(
                                                self._tag,
                                                f"Follow call instruction '{mem_def_inst_info:s}' since it uses '0x{inst.constant:x}' as parameter",
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
                                        f"Do not follow instruction '{mem_def_inst_info:s}' since it does not use the pointer '0x{inst.constant:x}'",
                                    )
                else:
                    log.debug(
                        self._tag,
                        f"Do not follow pointer '0x{constant:x}' since it is in a non-writable segment",
                    )
            case bn.MediumLevelILLoadSsa(src=load_src_inst, size=load_src_size):
                followed = False
                # Get instructions defining the memory version of `inst`
                mem_def_insts = FunctionHelper.get_ssa_memory_definitions(
                    inst.function,
                    inst.ssa_memory_version,
                    self._max_memory_slice_depth,
                )
                # Iterate memory defining instructions
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
                # Get instructions defining the memory version of `inst`
                mem_def_insts = FunctionHelper.get_ssa_memory_definitions(
                    inst.function,
                    inst.ssa_memory_version,
                    self._max_memory_slice_depth,
                )
                # Iterate memory defining instructions
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
                bn.MediumLevelILVarAliased(src=ssa_var)
                | bn.MediumLevelILVarAliasedField(src=ssa_var)
            ):
                self._slice_ssa_var_definition(ssa_var, inst)
            case (
                bn.MediumLevelILAddressOf(src=var)
                | bn.MediumLevelILAddressOfField(src=var)
            ):
                pass
            case (
                bn.MediumLevelILVarSsa(src=ssa_var)
                | bn.MediumLevelILVarSsaField(src=ssa_var)
                | bn.MediumLevelILVarField(src=ssa_var)
                | bn.MediumLevelILUnimplMem(src=ssa_var)
                | bn.MediumLevelILForceVerSsa(src=ssa_var)
            ):
                self._slice_ssa_var_definition(ssa_var, inst)
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
                        # Get destination function and its symbol
                        dest_func = self._bv.get_function_at(func_addr)
                        dest_symb = dest_func.symbol if dest_func else None
                        # Slicer cannot go into the callee (proceed with function parameters)
                        if (
                            not dest_func
                            or not dest_func.mlil
                            or not dest_func.mlil.ssa_form
                            or not dest_symb
                            or dest_symb.type
                            not in [
                                bn.SymbolType.FunctionSymbol,
                                bn.SymbolType.LibraryFunctionSymbol,
                            ]
                        ):
                            for param in inst.params:
                                self._slice_backwards(param)
                        # Slicer can go into the callee
                        else:
                            # Get callee's SSA form
                            dest_func = dest_func.mlil.ssa_form
                            # Iterate the callee's return instructions
                            for ret_inst in FunctionHelper.get_mlil_return_insts(
                                dest_func
                            ):
                                ret_inst_info = InstructionHelper.get_inst_info(
                                    ret_inst, False
                                )
                                # Proceed slicing the relevant output parameters, if we followed the
                                # call due to reaching them
                                if call_params:
                                    # Get instructions defining the memory version of `inst`
                                    mem_def_insts = (
                                        FunctionHelper.get_ssa_memory_definitions(
                                            dest_func,
                                            ret_inst.ssa_memory_version,
                                            self._max_memory_slice_depth,
                                        )
                                    )
                                    # Iterate memory defining instructions
                                    for mem_def_inst in mem_def_insts:
                                        mem_def_inst_info = (
                                            InstructionHelper.get_inst_info(
                                                mem_def_inst, False
                                            )
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
                                        # TODO: Test call instruction
                                        if isinstance(
                                            mem_def_inst,
                                            bn.MediumLevelILCallSsa
                                            | bn.MediumLevelILCallUntypedSsa
                                            | bn.MediumLevelILTailcallSsa
                                            | bn.MediumLevelILTailcallUntypedSsa,
                                        ):
                                            # Get the parameter instructions
                                            mlil_param_insts = (
                                                FunctionHelper.get_mlil_param_insts(
                                                    dest_func
                                                )
                                            )
                                            # Iterate caller's call parameters of interest
                                            for param_idx in call_params:
                                                if param_idx <= 0 or param_idx > len(
                                                    mlil_param_insts
                                                ):
                                                    continue
                                                # Get callee's parameter of interest
                                                mlil_param_inst = mlil_param_insts[
                                                    param_idx - 1
                                                ]
                                                if mlil_param_inst is None:
                                                    continue
                                                param_offset = getattr(
                                                    mlil_param_inst, "offset", 0
                                                )
                                                param_ssa_var = mlil_param_inst.var
                                                # param_ssa_var_info = (
                                                #     VariableHelper.get_ssavar_info(
                                                #         param_ssa_var
                                                #     )
                                                # )
                                                # TODO: Test 1
                                                # self._slice_todo(
                                                #     param_ssa_var,
                                                #     param_offset,
                                                #     mem_def_inst,
                                                # )

                                                # Push callee and proceed slicing its output
                                                # parameter writing instruction (if no recursion)
                                                recursion = (
                                                    self._call_tracker.push_func(
                                                        to_inst=mem_def_inst,
                                                        reverse=False,
                                                        param_idx=param_idx,
                                                    )
                                                )
                                                if recursion:
                                                    log.debug(
                                                        self._tag,
                                                        f"Do not follow instruction '{mem_def_inst_info:s}' of function '{dest_inst_info:s}' since recursion detected",
                                                    )
                                                else:
                                                    # log.debug(
                                                    #     self._tag,
                                                    #     f"TODO: Follow instruction '{mem_def_inst_info:s}' of function '{dest_inst_info:s}' since it writes the output parameter variable '{param_ssa_var_info:s}'",
                                                    # )
                                                    # self._call_tracker.push_mem_def_inst(
                                                    #     mem_def_inst
                                                    # )
                                                    # self._slice_backwards(
                                                    #     mem_def_inst,
                                                    #     set([mem_def_param_idx]),
                                                    # )
                                                    self._slice_todo(
                                                        param_ssa_var,
                                                        param_offset,
                                                        mem_def_inst,
                                                    )
                                                # Get call level of the callee
                                                call_level = (
                                                    self._call_tracker.get_call_level()
                                                )
                                                # Get parameters reached in the callee
                                                param_idxs = (
                                                    self._call_tracker.pop_func()
                                                )
                                                # If maximum call level was reached in the callee, slice all
                                                # parameters
                                                if (
                                                    self._max_call_level >= 0
                                                    and abs(call_level)
                                                    > self._max_call_level
                                                ):
                                                    for param in inst.params:
                                                        self._slice_backwards(param)
                                                # If maximum call level was not reached in the callee, slice only
                                                # the specifically reached parameters
                                                else:
                                                    for param_idx in param_idxs:
                                                        self._slice_backwards(
                                                            inst.params[param_idx - 1]
                                                        )

                                                # # TODO: Test 2
                                                # hlil_param_inst = mlil_param_inst.hlil
                                                # if hlil_param_inst is None:
                                                #     continue
                                                # # Iterate callee's memory defining instruction's parameters
                                                # mem_def_params: Set[int] = set()
                                                # for (
                                                #     mem_def_param_idx,
                                                #     mlil_mem_def_param_inst,
                                                # ) in enumerate(
                                                #     mem_def_inst.params, start=1
                                                # ):
                                                #     hlil_mem_def_param_inst = (
                                                #         mlil_mem_def_param_inst.hlil
                                                #     )
                                                #     if hlil_mem_def_param_inst is None:
                                                #         continue
                                                #     if (
                                                #         hlil_param_inst
                                                #         == hlil_mem_def_param_inst
                                                #     ):
                                                #         mem_def_params.add(
                                                #             mem_def_param_idx
                                                #         )
                                                # # TODO: Test 3
                                                # ptr_inst_str = ""
                                                # mem_def_params: Set[int] = set()
                                                # for mem_def_param_idx, mlil_mem_def_param_inst in enumerate(mem_def_inst.params, start=1):
                                                #     is_ptr_equal, ptr_inst_str = self._is_ptr_equivalent(
                                                #         param_ssa_var, param_offset, mlil_mem_def_param_inst
                                                #     )
                                                #     if is_ptr_equal:
                                                #         mem_def_params.add(mem_def_param_idx)
                                                # # TODO: Test 2 and 3
                                                # for mem_def_param_idx in mem_def_params:
                                                #     # Push callee and proceed slicing its output
                                                #     # parameter writing instruction (if no recursion)
                                                #     recursion = (
                                                #         self._call_tracker.push_func(
                                                #             to_inst=mem_def_inst,
                                                #             reverse=False,
                                                #             param_idx=mem_def_param_idx,
                                                #         )
                                                #     )
                                                #     if recursion:
                                                #         log.debug(
                                                #             self._tag,
                                                #             f"Do not follow instruction '{mem_def_inst_info:s}' of function '{dest_inst_info:s}' since recursion detected",
                                                #         )
                                                #     else:
                                                #         log.debug(
                                                #             self._tag,
                                                #             f"TODO: Follow instruction '{mem_def_inst_info:s}' of function '{dest_inst_info:s}' since it writes the output parameter variable '{param_ssa_var_info:s}'",
                                                #         )
                                                #         self._call_tracker.push_mem_def_inst(
                                                #             mem_def_inst
                                                #         )
                                                #         self._slice_backwards(
                                                #             mem_def_inst,
                                                #             set([mem_def_param_idx]),
                                                #         )
                                                #     # Get call level of the callee
                                                #     call_level = self._call_tracker.get_call_level()
                                                #     # Get parameters reached in the callee
                                                #     param_idxs = (
                                                #         self._call_tracker.pop_func()
                                                #     )
                                                #     # If maximum call level was reached in the callee, slice all
                                                #     # parameters
                                                #     if (
                                                #         self._max_call_level >= 0
                                                #         and abs(call_level)
                                                #         > self._max_call_level
                                                #     ):
                                                #         for param in inst.params:
                                                #             self._slice_backwards(param)
                                                #     # If maximum call level was not reached in the callee, slice only
                                                #     # the specifically reached parameters
                                                #     else:
                                                #         for param_idx in param_idxs:
                                                #             self._slice_backwards(
                                                #                 inst.params[
                                                #                     param_idx - 1
                                                #                 ]
                                                #             )
                                        # Ensure store instruction
                                        if not isinstance(
                                            mem_def_inst,
                                            bn.MediumLevelILStoreSsa
                                            | bn.MediumLevelILStoreStructSsa,
                                        ):
                                            continue
                                        # Match HLIL instruction
                                        if mem_def_inst.hlil is None:
                                            continue
                                        hlil_mem_def_inst = mem_def_inst.hlil.ssa_form
                                        match hlil_mem_def_inst:
                                            # Memory assignment to dereferenced variable
                                            case bn.HighLevelILAssignMemSsa(
                                                dest=(
                                                    bn.HighLevelILDerefSsa(
                                                        src=bn.HighLevelILVarSsa(
                                                            var=dest_var
                                                        )
                                                    )
                                                    | bn.HighLevelILDerefFieldSsa(
                                                        src=bn.HighLevelILVarSsa(
                                                            var=dest_var
                                                        )
                                                    )
                                                )
                                            ):
                                                # Ensure we store a parameter variable of interest
                                                param_vars = list(
                                                    dest_func.source_function.parameter_vars
                                                )
                                                if dest_var.var not in param_vars:
                                                    continue
                                                param_idx = (
                                                    param_vars.index(dest_var.var) + 1
                                                )
                                                if param_idx not in call_params:
                                                    continue
                                                # Push callee and proceed slicing its output
                                                # parameter writing instruction (if no recursion)
                                                recursion = (
                                                    self._call_tracker.push_func(
                                                        to_inst=mem_def_inst,
                                                        reverse=False,
                                                        param_idx=param_idx,
                                                    )
                                                )
                                                if recursion:
                                                    log.debug(
                                                        self._tag,
                                                        f"Do not follow instruction '{mem_def_inst_info:s}' of function '{dest_inst_info:s}' since recursion detected",
                                                    )
                                                else:
                                                    dest_var_info = (
                                                        VariableHelper.get_ssavar_info(
                                                            dest_var
                                                        )
                                                    )
                                                    log.debug(
                                                        self._tag,
                                                        f"Follow instruction '{mem_def_inst_info:s}' of function '{dest_inst_info:s}' since it writes the output parameter variable '{dest_var_info:s}'",
                                                    )
                                                    self._call_tracker.push_mem_def_inst(
                                                        mem_def_inst
                                                    )
                                                    self._slice_backwards(mem_def_inst)
                                                # Get call level of the callee
                                                call_level = (
                                                    self._call_tracker.get_call_level()
                                                )
                                                # Get parameters reached in the callee
                                                param_idxs = (
                                                    self._call_tracker.pop_func()
                                                )
                                                # If maximum call level was reached in the callee, slice all
                                                # parameters
                                                if (
                                                    self._max_call_level >= 0
                                                    and abs(call_level)
                                                    > self._max_call_level
                                                ):
                                                    for param in inst.params:
                                                        self._slice_backwards(param)
                                                # If maximum call level was not reached in the callee, slice only
                                                # the specifically reached parameters
                                                else:
                                                    for param_idx in param_idxs:
                                                        self._slice_backwards(
                                                            inst.params[param_idx - 1]
                                                        )
                                # Proceed slicing all possible return instructions, if we followed
                                # the call due to reaching its return value
                                else:
                                    # Push callee and proceed slicing its return instruction (if no recursion)
                                    recursion = self._call_tracker.push_func(
                                        to_inst=ret_inst,
                                        reverse=False,
                                        param_idx=0,
                                    )
                                    if recursion:
                                        log.debug(
                                            self._tag,
                                            f"Do not follow return instruction '{ret_inst_info:s}' of function '{dest_inst_info:s}' since recursion detected",
                                        )
                                    else:
                                        log.debug(
                                            self._tag,
                                            f"Follow return instruction '{ret_inst_info:s}' of function '{dest_inst_info:s}'",
                                        )
                                        self._slice_backwards(ret_inst)
                                    # Get call level of the callee
                                    call_level = self._call_tracker.get_call_level()
                                    # Get parameters reached in the callee
                                    param_idxs = self._call_tracker.pop_func()
                                    # If maximum call level was reached in the callee, slice all
                                    # parameters
                                    if (
                                        self._max_call_level >= 0
                                        and abs(call_level) > self._max_call_level
                                    ):
                                        for param in inst.params:
                                            self._slice_backwards(param)
                                    # If maximum call level was not reached in the callee, slice only
                                    # the specifically reached parameters
                                    else:
                                        for param_idx in param_idxs:
                                            self._slice_backwards(
                                                inst.params[param_idx - 1]
                                            )
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
        self._call_tracker.push_func(to_inst=inst, reverse=True, param_idx=0)
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
