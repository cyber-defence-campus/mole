from __future__ import annotations
from collections import deque
from mole.common.helper.function import FunctionHelper
from mole.common.helper.instruction import InstructionHelper
from mole.common.helper.variable import VariableHelper
from mole.common.log import Logger
from mole.core.call import MediumLevelILCallTracker
from mole.core.graph import MediumLevelILFunctionGraph, MediumLevelILInstructionGraph
from typing import cast, Callable, Dict, Iterable, List, Set, Tuple
import binaryninja as bn
import os


tag = "Slice"


class MediumLevelILBackwardSlicer:
    """
    This class implements backward slicing for MLIL instructions.
    """

    def __init__(
        self,
        bv: bn.BinaryView,
        log: Logger,
        custom_tag: str = "",
        max_call_level: int = -1,
        max_memory_slice_depth: int = -1,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> None:
        self.bv = bv
        self.log = log
        self._filename = os.path.basename(bv.file.filename)
        self._tag = custom_tag if custom_tag else tag
        self._max_call_level = max_call_level
        self._max_memory_slice_depth = max_memory_slice_depth
        self._cancelled = cancelled
        self._call_tracker: MediumLevelILCallTracker = MediumLevelILCallTracker()
        return

    def __pop_func_and_slice_reached_params(
        self,
        inst: bn.MediumLevelILCallSsa
        | bn.MediumLevelILCallUntypedSsa
        | bn.MediumLevelILTailcallSsa
        | bn.MediumLevelILTailcallUntypedSsa
        | None = None,
    ) -> None:
        """
        This method pops the current call frame from the top of the call stack and continues slicing
        the reached parameters if `inst` is not `None`.
        """
        # Get call level of the current call frame
        call_level = self._call_tracker.get_call_level()
        # Pop current call frame from the top of the call stack and retrieve its reached parameters
        param_idxs = self._call_tracker.pop_func()
        # Slice parameters
        if inst is not None:
            # Slice all parameters if maximum call level was reached
            if self._max_call_level >= 0 and abs(call_level) > self._max_call_level:
                for param in inst.params:
                    self._slice_backwards(param)
            # Slice reached parameters if maximum call level was not reached
            else:
                for param_idx in param_idxs:
                    self._slice_backwards(inst.params[param_idx - 1])
        return

    @staticmethod
    def _get_read_range(
        ssa_var: bn.SSAVariable, inst: bn.MediumLevelILInstruction
    ) -> Tuple[int, int]:
        """
        This method returns the byte range `(offset, size)` of `ssa_var` read by instruction `inst`.
        The offset is 0 if `inst` has no offset. The size falls back to the width of `ssa_var` if
        `inst` has no size, and to a single byte if `ssa_var` has no type either (i.e. only the
        byte at the offset is considered read).
        """
        offset = getattr(inst, "offset", 0)
        if inst.size > 0:
            size = inst.size
        elif ssa_var.var.type is not None and ssa_var.var.type.width > 0:
            size = ssa_var.var.type.width
        else:
            size = 1
        return offset, size

    def _is_mem_def_inst_followed(
        self, mem_def_inst: bn.MediumLevelILInstruction
    ) -> bool:
        """
        This method returns whether the memory defining instruction `mem_def_inst` was followed
        before in the current call frame.
        """
        if not self._call_tracker.is_in_current_mem_def_insts(mem_def_inst):
            return False
        mem_def_inst_info = InstructionHelper.get_inst_info(mem_def_inst, False)
        self.log.debug(
            self._tag,
            f"Do not follow instruction '{mem_def_inst_info:s}' since followed before in the current call frame",
        )
        return True

    def _slice_ssa_var_mem_definition(
        self,
        ssa_var: bn.SSAVariable,
        inst: bn.MediumLevelILInstruction,
        mem_def_inst: bn.MediumLevelILInstruction,
    ) -> bool:
        """
        This method matches the memory defining instruction `mem_def_inst` against the following
        cases, where `inst` is the instruction being sliced that reads `ssa_var` (e.g. a
        `MediumLevelILVarAliasedField` reading `ssa_var` at some offset):
        - If `mem_def_inst` is an assignment to the aliased variable underlying `ssa_var`, slice it
        - If `mem_def_inst` is an assignment to a field of the aliased variable underlying
          `ssa_var` that overlaps the bytes read by `inst`, slice it
        - If `mem_def_inst` is a call having a parameter that possibly writes `ssa_var`, slice the
          call. This is the case if `ssa_var` is aliased and the parameter points to it (e.g.
          `&ssa_var`), or if `ssa_var` is a pointer and the parameter holds the same pointer value
          (i.e. the callee can write the memory `ssa_var` points to)
        The method returns whether slicing proceeded at `mem_def_inst` or not.
        """
        followed = False
        # Ignore memory defining instructions not handled below (e.g. stores)
        if not isinstance(
            mem_def_inst,
            bn.MediumLevelILSetVarAliased
            | bn.MediumLevelILSetVarAliasedField
            | bn.MediumLevelILCallSsa
            | bn.MediumLevelILCallUntypedSsa
            | bn.MediumLevelILTailcallSsa
            | bn.MediumLevelILTailcallUntypedSsa,
        ):
            return followed
        ssa_var_info = VariableHelper.get_ssavar_info(ssa_var)
        mem_def_inst_info = InstructionHelper.get_inst_info(mem_def_inst, False)
        # Ensure memory defining instruction has not yet been followed in the current call frame
        if self._is_mem_def_inst_followed(mem_def_inst):
            return followed
        # Match memory defining instruction
        match mem_def_inst:
            # Assignment to aliased variable underlying `ssa_var` -> slice assignment instruction
            case bn.MediumLevelILSetVarAliased(
                prev=prev_ssa_var,
                dest=dest_ssa_var,
            ):
                if (
                    prev_ssa_var.var == dest_ssa_var.var == ssa_var.var
                    and prev_ssa_var.version + 1
                    == dest_ssa_var.version
                    <= ssa_var.version
                ):
                    self.log.debug(
                        self._tag,
                        f"Follow instruction '{mem_def_inst_info:s}' since it writes aliased variable '{ssa_var_info:s}'",
                    )
                    self._call_tracker.push_mem_def_inst(mem_def_inst)
                    self._slice_backwards(mem_def_inst)
                    followed = True
            # Assignment to field of aliased variable underlying `ssa_var` -> slice assignment
            # instruction
            case bn.MediumLevelILSetVarAliasedField(
                prev=prev_ssa_var,
                dest=dest_ssa_var,
                offset=dest_offset,
                size=dest_size,
            ):
                # Byte range of `ssa_var` read by `inst`
                read_offset, read_size = self._get_read_range(ssa_var, inst)
                if (
                    prev_ssa_var.var == dest_ssa_var.var == ssa_var.var
                    and prev_ssa_var.version + 1
                    == dest_ssa_var.version
                    <= ssa_var.version
                    # Ensure byte ranges `[offset, offset + size)` intersect
                    and dest_offset < read_offset + read_size
                    and read_offset < dest_offset + dest_size
                ):
                    self.log.debug(
                        self._tag,
                        f"Follow instruction '{mem_def_inst_info:s}' since it writes bytes [{dest_offset:d}, {dest_offset + dest_size:d}) of aliased variable '{ssa_var_info:s}' overlapping [{read_offset:d}, {read_offset + read_size:d})",
                    )
                    self._call_tracker.push_mem_def_inst(mem_def_inst)
                    self._slice_backwards(mem_def_inst)
                    followed = True
            # Call with a parameter possibly writing `ssa_var` -> slice call instruction
            case (
                bn.MediumLevelILCallSsa(params=params)
                | bn.MediumLevelILCallUntypedSsa(params=params)
                | bn.MediumLevelILTailcallSsa(params=params)
                | bn.MediumLevelILTailcallUntypedSsa(params=params)
            ):
                # Find set of call parameters the slicer should follow
                call_params: Set[int] = set()
                call_inst: bn.HighLevelILInstruction | None = None
                call_offset: int = 0
                for param_idx, param_inst in enumerate(params, start=1):
                    match param_inst:
                        # Parameter is a variable: follow parameter if it points to `ssa_var` or
                        # holds the same pointer value as `ssa_var`
                        case bn.MediumLevelILVarSsa(var=param_ssa_var):
                            # Get pointers in the current function
                            out_params = self._call_tracker.get_out_params()
                            ptr_map = FunctionHelper.get_ptr_map(
                                param_inst.function, out_params
                            )
                            # Get pointer instruction for `param_ssa_var`
                            ptr_inst_param_ssa_var, ptr_offset_param_ssa_var = (
                                ptr_map.get(param_ssa_var, (None, 0))
                            )
                            if ptr_inst_param_ssa_var is None:
                                continue
                            # `ssa_var` is aliased: follow parameter if it points to `ssa_var`
                            # (e.g. `ssa_var` is `size#2` and the call is `f(rdi#1)` with
                            # `rdi#1 = &size`)
                            if ssa_var.var in param_inst.function.aliased_vars:
                                ptr_addr = InstructionHelper.get_ptr_value_addr(
                                    ptr_inst_param_ssa_var
                                )
                                follow = (
                                    ptr_addr is not None
                                    and isinstance(ptr_addr[0], bn.HighLevelILVar)
                                    and ptr_addr[0].var == ssa_var.var
                                    and ptr_addr[1] + ptr_offset_param_ssa_var
                                    in (0, getattr(inst, "offset", 0))
                                )
                            # `ssa_var` is a pointer: follow parameter if it holds the same
                            # pointer value (e.g. `ssa_var` is `p#2` and the call is `f(rdi#1)`
                            # with `rdi#1 = p#2`)
                            else:
                                ptr_inst_ssa_var, ptr_offset_ssa_var = ptr_map.get(
                                    ssa_var, (None, 0)
                                )
                                follow = (
                                    ptr_inst_ssa_var is not None
                                    and ptr_offset_ssa_var == ptr_offset_param_ssa_var
                                    and InstructionHelper.is_value_equivalent(
                                        ptr_inst_ssa_var, ptr_inst_param_ssa_var
                                    )
                                )
                            if follow:
                                call_params.add(param_idx)
                                call_inst = ptr_inst_param_ssa_var
                                call_offset = ptr_offset_param_ssa_var
                        # Parameter is the address of `ssa_var`: follow parameter
                        case bn.MediumLevelILAddressOf(src=param_var):
                            if ssa_var.var == param_var:
                                call_params.add(param_idx)
                        # Parameter is the address of a field of `ssa_var`: follow parameter if the
                        # field offset matches the offset read by `inst`
                        case bn.MediumLevelILAddressOfField(
                            src=param_var, offset=param_offset
                        ):
                            if (
                                ssa_var.var == param_var
                                and getattr(inst, "offset", 0) == param_offset
                            ):
                                call_params.add(param_idx)
                # Slice the call instruction if we need to follow any parameter
                if call_params:
                    hlil_inst_str = (
                        f" (HLIL: {str(call_inst):s}{call_offset:+d})"
                        if call_inst is not None
                        else ""
                    )
                    params_str = (
                        "parameter " if len(call_params) == 1 else "parameters "
                    )
                    params_str += ", ".join(map(str, sorted(call_params)))
                    self.log.debug(
                        self._tag,
                        f"Follow call instruction '{mem_def_inst_info:s}' since it uses '{ssa_var_info:s}'{hlil_inst_str:s} in {params_str:s}",
                    )
                    self._call_tracker.push_mem_def_inst(mem_def_inst)
                    self._slice_backwards(mem_def_inst, call_params)
                    followed = True
        return followed

    def _walk_ssa_mem_definitions(
        self,
        func: bn.MediumLevelILFunction,
        mem_versions: Iterable[int],
        read_bytes: Set[int],
        visit: Callable[[bn.MediumLevelILInstruction], Set[int]],
    ) -> bool:
        """
        This method walks the SSA memory chain of function `func` backwards, starting at the memory
        versions `mem_versions`. Each (non-phi) memory defining instruction is passed once to
        `visit`, which slices it if relevant and returns the bytes in `read_bytes` it defines. At a
        mem phi-node, each source memory version is walked as a separate path, which ends once its
        bytes in `read_bytes` are fully defined. The method returns whether any path reached the
        entry of `func` (or the maximum memory slice depth) with bytes in `read_bytes` undefined.
        """
        undef_at_entry = False
        # Undefined bytes each memory version was visited with
        visited: Dict[int, Set[int]] = {}
        # Bytes defined by each visited memory defining instruction
        def_bytes: Dict[bn.MediumLevelILInstruction, Set[int]] = {}
        # Memory versions to visit with the bytes still undefined on their path (initially all)
        queue: deque[Tuple[int, Set[int]]] = deque(
            (mem_version, read_bytes) for mem_version in mem_versions
        )
        while queue:
            mem_version, undef_bytes = queue.popleft()
            # Ignore memory version if visited before with the same undefined bytes
            if undef_bytes <= visited.get(mem_version, set()):
                continue
            # Break if maximum number of memory versions visited
            if (
                self._max_memory_slice_depth >= 0
                and len(visited) >= self._max_memory_slice_depth
            ):
                undef_at_entry = True
                break
            visited[mem_version] = visited.get(mem_version, set()) | undef_bytes
            mem_def_inst = func.get_ssa_memory_definition(mem_version)
            match mem_def_inst:
                # Memory version is not defined within `func`
                case None:
                    undef_at_entry = True
                # Memory version can be defined by multiple paths (mem phi-node)
                case bn.MediumLevelILMemPhi(src_memory=src_memory_versions):
                    queue.extend(
                        (src_memory_version, undef_bytes)
                        for src_memory_version in src_memory_versions
                    )
                # Visit memory defining instruction and continue with the still undefined bytes
                case _:
                    # Visit (and thus slice) each instruction only once, even if on multiple paths
                    if mem_def_inst not in def_bytes:
                        def_bytes[mem_def_inst] = visit(mem_def_inst)
                    # Continue with the previous memory version unless all bytes are defined
                    undef_bytes = undef_bytes - def_bytes[mem_def_inst]
                    if undef_bytes:
                        queue.append((mem_def_inst.ssa_memory_version, undef_bytes))
        return undef_at_entry

    def _slice_ssa_var_mem_definitions(
        self, ssa_var: bn.SSAVariable, inst: bn.MediumLevelILInstruction
    ) -> bool:
        """
        This method walks the SSA memory chain of the function `inst.function` backwards from
        `inst.ssa_memory_version` and slices the instructions possibly defining `ssa_var`. Each
        path through mem phi-nodes ends once the bytes read by `inst` are fully defined on it.
        Calls only possibly write `ssa_var` (through pointer parameters) and field assignments may
        only partially write the bytes read by `inst`, so slicing continues past them.
        """
        # Bytes of `ssa_var` read by `inst` that must be defined before slicing stops
        read_offset, read_size = self._get_read_range(ssa_var, inst)
        read_bytes = set(range(read_offset, read_offset + read_size))
        # Whether any memory defining instruction was sliced
        followed = False

        # Slice `mem_def_inst` and return the bytes in `read_bytes` it defines (calls define none)
        def visit(mem_def_inst: bn.MediumLevelILInstruction) -> Set[int]:
            nonlocal followed
            if not self._slice_ssa_var_mem_definition(ssa_var, inst, mem_def_inst):
                return set()
            followed = True
            match mem_def_inst:
                case bn.MediumLevelILSetVarAliased():
                    return read_bytes
                case bn.MediumLevelILSetVarAliasedField(offset=offset, size=size):
                    return read_bytes & set(range(offset, offset + size))
            return set()

        self._walk_ssa_mem_definitions(
            inst.function, [inst.ssa_memory_version], read_bytes, visit
        )
        return followed

    def _slice_store_chain(
        self,
        load_inst: bn.MediumLevelILLoadSsa,
        store_chain: Tuple[bn.MediumLevelILInstruction, ...],
    ) -> None:
        """
        This method slices the store instruction at the end of `store_chain`, which may define the
        memory loaded by `load_inst`. All other instructions in `store_chain` are calls, each into
        the function of the next instruction. The first instruction is in the function of the
        current call frame. For each call, a call frame is pushed for the called function. When
        returning from it, the arguments of the call are sliced for each parameter that was reached.
        """
        mem_def_inst, *rest = store_chain
        mem_def_inst_info = InstructionHelper.get_inst_info(mem_def_inst, False)
        # Follow the store instruction
        if not rest:
            load_inst_info = InstructionHelper.get_inst_info(load_inst, False)
            self.log.debug(
                self._tag,
                f"Follow store instruction '{mem_def_inst_info:s}' since it may overlap the memory loaded by '{load_inst_info:s}'",
            )
            self._call_tracker.push_mem_def_inst(mem_def_inst)
            self._slice_backwards(mem_def_inst)
            return
        # Follow the call into the function of the next instruction
        call_inst = cast(
            bn.MediumLevelILCallSsa
            | bn.MediumLevelILCallUntypedSsa
            | bn.MediumLevelILTailcallSsa
            | bn.MediumLevelILTailcallUntypedSsa,
            mem_def_inst,
        )
        self._call_tracker.push_inst(call_inst)
        recursion = self._call_tracker.push_func(to_inst=rest[0])
        if recursion:
            self.log.debug(
                self._tag,
                f"Do not follow call instruction '{mem_def_inst_info:s}' since recursion detected",
            )
        else:
            self._slice_store_chain(load_inst, tuple(rest))
        # Pop called function and follow the reached parameters
        self.__pop_func_and_slice_reached_params(call_inst)
        self._call_tracker.pop_inst()
        return

    def _slice_load_ptr_call(
        self,
        load_inst: bn.MediumLevelILLoadSsa | bn.MediumLevelILLoadStructSsa,
        call_inst: bn.MediumLevelILCallSsa
        | bn.MediumLevelILCallUntypedSsa
        | bn.MediumLevelILTailcallSsa
        | bn.MediumLevelILTailcallUntypedSsa,
    ) -> None:
        """
        This method slices the call instruction `call_inst` (may-def) if it gets a pointer into
        the memory object loaded by `load_inst` as a parameter, since the callee may write the
        loaded memory through it. Slicing then proceeds in the callee at the instructions writing
        these output parameters.
        """
        call_params = InstructionHelper.get_load_ptr_params(load_inst, call_inst)
        if not call_params:
            return
        call_inst_info = InstructionHelper.get_inst_info(call_inst, False)
        load_inst_info = InstructionHelper.get_inst_info(load_inst, False)
        params_str = "parameter " if len(call_params) == 1 else "parameters "
        params_str += ", ".join(map(str, sorted(call_params)))
        self.log.debug(
            self._tag,
            f"Follow call instruction '{call_inst_info:s}' since it may write the memory loaded by '{load_inst_info:s}' through {params_str:s}",
        )
        self._call_tracker.push_mem_def_inst(call_inst)
        self._slice_backwards(call_inst, call_params)
        return

    def _slice_load_mem_definitions(self, inst: bn.MediumLevelILLoadSsa) -> None:
        """
        This method follows to the store instructions possibly defining the memory loaded by `inst`:
        - Stores in `inst.function` overlapping the loaded memory are must-defs, i.e. they end the
          path through the SSA memory chain they are on
        - If `inst` loads from a constant global address (i.e. a global or static variable) in a
          writable segment, stores to it in other functions are may-defs. Stores in (transitive)
          callees are sliced at the call when walking the SSA memory chain of `inst.function`.
          Stores in all other functions are only sliced if some path reaches the entry of
          `inst.function` without a must-def. Within a function, stores are found by walking its SSA
          memory chain backwards from its return instructions, so that stores on all paths through
          the function are sliced.
        If some path reaches the entry of `inst.function` (or the maximum memory slice depth)
        without a must-def, the load source instruction is sliced too.
        """
        inst_info = InstructionHelper.get_inst_info(inst, False)
        curr_func = inst.function.source_function
        # Bytes loaded by `inst`, which a store must cover to end a path (must-def)
        read_bytes = set(range(inst.size))
        # Get other functions storing to the loaded address (only if it is a constant global
        # address)
        writer_funcs: Set[bn.Function] = set()
        match inst.src:
            case bn.MediumLevelILConstPtr(constant=load_addr):
                # Ensure rw- segment (only writable data can be stored)
                segment = self.bv.get_segment_at(load_addr)
                if (
                    segment
                    and segment.readable
                    and segment.writable
                    and not segment.executable
                ):
                    for code_ref in self.bv.get_code_refs(load_addr):
                        if code_ref.function is None or code_ref.function == curr_func:
                            continue
                        if any(
                            isinstance(mlil.ssa_form, bn.MediumLevelILStoreSsa)
                            for mlil in code_ref.mlils
                        ):
                            writer_funcs.add(code_ref.function)
        # Whether a function (transitively) calls a function in `writer_funcs`
        may_write: Dict[bn.Function, bool] = {}
        # Functions whose SSA memory chain was walked for stores
        walked_funcs: Set[bn.Function] = set()

        # Get the callee of `call_inst` if it is or (transitively) calls a function in
        # `writer_funcs`, i.e. if it may write the loaded memory (only possible for loads from a
        # constant global address)
        def get_writer_callee(
            call_inst: bn.MediumLevelILCallSsa
            | bn.MediumLevelILCallUntypedSsa
            | bn.MediumLevelILTailcallSsa
            | bn.MediumLevelILTailcallUntypedSsa,
        ) -> bn.Function | None:
            match call_inst.dest:
                case (
                    bn.MediumLevelILConstPtr(constant=func_addr)
                    | bn.MediumLevelILImport(constant=func_addr)
                ):
                    func = self.bv.get_function_at(func_addr)
                    if func is None:
                        return None
                    if func not in may_write:
                        may_write[func] = any(
                            func == writer_func
                            or FunctionHelper.calls(func, writer_func)
                            for writer_func in writer_funcs
                        )
                    if may_write[func]:
                        return func
            return None

        # Get the store chains of all stores to the loaded memory in `func` and its callees, without
        # descending into the functions in `visiting` (the current call path). A store chain is a
        # tuple of calls leading to a store (see `_slice_store_chain`).
        def get_store_chains(
            func: bn.Function, visiting: Set[bn.Function]
        ) -> List[Tuple[bn.MediumLevelILInstruction, ...]]:
            walked_funcs.add(func)
            store_chains: List[Tuple[bn.MediumLevelILInstruction, ...]] = []
            mlil_func = func.mlil.ssa_form if func.mlil is not None else None
            if mlil_func is None:
                return store_chains

            def visit(mem_def_inst: bn.MediumLevelILInstruction) -> Set[int]:
                match mem_def_inst:
                    case bn.MediumLevelILStoreSsa():
                        if InstructionHelper.is_load_store_overlapping(
                            inst, mem_def_inst
                        ):
                            store_chains.append((mem_def_inst,))
                            return read_bytes
                    case (
                        bn.MediumLevelILCallSsa()
                        | bn.MediumLevelILCallUntypedSsa()
                        | bn.MediumLevelILTailcallSsa()
                        | bn.MediumLevelILTailcallUntypedSsa()
                    ):
                        callee = get_writer_callee(mem_def_inst)
                        if callee is not None and callee not in visiting:
                            store_chains.extend(
                                (mem_def_inst, *store_chain)
                                for store_chain in get_store_chains(
                                    callee, visiting | {callee}
                                )
                            )
                return set()

            ret_mem_versions = [
                ret_inst.ssa_memory_version
                for ret_inst in FunctionHelper.get_mlil_return_insts(mlil_func)
            ]
            self._walk_ssa_mem_definitions(
                mlil_func, ret_mem_versions, read_bytes, visit
            )
            return store_chains

        # Slice stores in the current function (must-defs) and in its (transitive) callees (may-defs)
        def visit(mem_def_inst: bn.MediumLevelILInstruction) -> Set[int]:
            mem_def_inst_info = InstructionHelper.get_inst_info(mem_def_inst, False)
            # Check if memory defining instruction was followed before
            if self._is_mem_def_inst_followed(mem_def_inst):
                return set()
            match mem_def_inst:
                case bn.MediumLevelILStoreSsa():
                    if InstructionHelper.is_load_store_overlapping(inst, mem_def_inst):
                        self.log.debug(
                            self._tag,
                            f"Follow store instruction '{mem_def_inst_info:s}' since it overlaps the memory loaded by '{inst_info:s}'",
                        )
                        self._call_tracker.push_mem_def_inst(mem_def_inst)
                        self._slice_backwards(mem_def_inst)
                        return read_bytes
                case (
                    bn.MediumLevelILCallSsa()
                    | bn.MediumLevelILCallUntypedSsa()
                    | bn.MediumLevelILTailcallSsa()
                    | bn.MediumLevelILTailcallUntypedSsa()
                ):
                    callee = get_writer_callee(mem_def_inst)
                    if callee is not None:
                        for store_chain in get_store_chains(
                            callee, {curr_func, callee}
                        ):
                            self._slice_store_chain(inst, (mem_def_inst, *store_chain))
                    # Slice call if the callee may write the loaded memory through a pointer
                    # parameter
                    self._slice_load_ptr_call(inst, mem_def_inst)
            return set()

        # Walk the SSA memory chain of the current function backwards from the load and record
        # whether some path reaches its entry without a must-def
        undef_at_entry = self._walk_ssa_mem_definitions(
            inst.function, [inst.ssa_memory_version], read_bytes, visit
        )

        # Slice stores (may-defs) in functions not called on the SSA memory chain, if some path
        # reaches the entry of the current function without a must-def
        if undef_at_entry:
            for writer_func in sorted(writer_funcs, key=lambda func: func.start):
                if writer_func in walked_funcs:
                    continue
                downwards = FunctionHelper.calls(curr_func, writer_func)
                for store_chain in get_store_chains(
                    writer_func, {curr_func, writer_func}
                ):
                    # Push writer function (no call in the current function, so reached
                    # parameters are not followed)
                    recursion = self._call_tracker.push_func(
                        to_inst=store_chain[0], downwards=downwards
                    )
                    if recursion:
                        self.log.debug(
                            self._tag,
                            f"Do not follow writer function '{writer_func.symbol.short_name:s}' since recursion detected",
                        )
                    else:
                        self._slice_store_chain(inst, store_chain)
                    self.__pop_func_and_slice_reached_params()
            # Follow load source instruction
            load_src_inst_info = InstructionHelper.get_inst_info(inst.src, False)
            self.log.debug(
                self._tag,
                f"Follow load source instruction '{load_src_inst_info:s}' since some path reaches the function entry without a must-def",
            )
            self._slice_backwards(inst.src)
        return

    def _slice_ssa_var_definition(
        self, ssa_var: bn.SSAVariable, inst: bn.MediumLevelILInstruction
    ) -> None:
        """
        This method first tries to find the instruction defining SSA variable `ssa_var` within the
        current function (`inst.function`) and if found, slices it. It then looks for the closest
        memory defining instruction within the current function (`inst.function`) that uses
        `ssa_var` and if found, slices it. If neither a variable nor memory defining instruction is
        found, the method tries to follow `ssa_var` to possible callers.
        """
        followed = False
        var_info = VariableHelper.get_var_info(ssa_var.var)
        # Slice SSA variable defining instruction if there is one (aliased writes are left to the
        # memory definitions below, since they may not define the bytes read by `inst`)
        inst_def = inst.function.get_ssa_var_definition(ssa_var)
        if inst_def and not isinstance(
            inst_def, bn.MediumLevelILSetVarAliased | bn.MediumLevelILSetVarAliasedField
        ):
            self._slice_backwards(inst_def)
            followed = True
        # Slice memory defining instruction if it uses the SSA variable
        if self._slice_ssa_var_mem_definitions(ssa_var, inst):
            followed = True
        # Return if we followed a variable or memory defining instruction (otherwise look in
        # callers)
        if followed:
            return
        # Determine all instructions calling the current function
        direct_call_insts = FunctionHelper.get_mlil_direct_call_insts(inst.function)
        indirect_call_insts = FunctionHelper.get_mlil_indirect_call_insts(inst.function)
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
                # Follow to the first instruction using the parameter
                param_insts = FunctionHelper.get_mlil_param_insts(inst.function)
                param_inst = param_insts[param_idx - 1]
                if param_inst is not None and param_inst != inst:
                    self._slice_backwards(param_inst)
                # Follow the parameter to all possible callers
                else:
                    for call_inst in direct_call_insts | indirect_call_insts:
                        from_inst = call_inst
                        to_inst = call_inst.params[param_idx - 1]
                        recursion = self._call_tracker.push_func(
                            to_inst=to_inst,
                            downwards=False,
                            param_idx=param_idx,
                        )
                        from_inst_info = InstructionHelper.get_inst_info(
                            from_inst, False
                        )
                        if not recursion:
                            self.log.debug(
                                self._tag,
                                f"Follow parameter {param_idx:d} '{var_info:s}' to possible caller '{from_inst_info:s}'",
                            )
                            self._slice_backwards(to_inst)
                        else:
                            self.log.debug(
                                self._tag,
                                f"Do not follow parameter {param_idx:d} '{var_info:s}' to possible caller '{from_inst_info:s}' since recursion detected",
                            )
                        self._call_tracker.pop_func()
            # Follow the parameter in specific caller later
            else:
                self.log.debug(
                    self._tag,
                    f"Follow parameter {param_idx:d} '{var_info:s}' when going back to specific caller",
                )
                self._call_tracker.add_hit_param(param_idx)
        return

    def _slice_const_ptr_mem_definitions(self, inst: bn.MediumLevelILConstPtr) -> None:
        """
        This method slices the calls defining the memory version of `inst` that have the pointer
        `inst.constant` as parameter, given the pointer is in a writable segment.
        """
        constant = inst.constant

        # Slice `mem_def_inst` if it is a call having the same pointer as parameter (calls define no
        # bytes, so every path is walked to the function entry)
        def visit(mem_def_inst: bn.MediumLevelILInstruction) -> Set[int]:
            mem_def_inst_info = InstructionHelper.get_inst_info(mem_def_inst, False)
            # Check if memory defining instruction was followed before
            if self._is_mem_def_inst_followed(mem_def_inst):
                return set()
            match mem_def_inst:
                # Slice calls having the same pointer as parameter
                case (
                    bn.MediumLevelILCallSsa(params=params)
                    | bn.MediumLevelILCallUntypedSsa(params=params)
                    | bn.MediumLevelILTailcallSsa(params=params)
                    | bn.MediumLevelILTailcallUntypedSsa(params=params)
                ):
                    param_idxs: Set[int] = set()
                    for param_idx, param_inst in enumerate(params, start=1):
                        match param_inst:
                            case bn.MediumLevelILConstPtr(constant=constant) if (
                                constant == inst.constant
                            ):
                                param_idxs.add(param_idx)
                    if param_idxs:
                        params_str = (
                            "parameter " if len(param_idxs) == 1 else "parameters "
                        )
                        params_str += ", ".join(map(str, sorted(param_idxs)))
                        self.log.debug(
                            self._tag,
                            f"Follow call instruction '{mem_def_inst_info:s}' since it uses '0x{inst.constant:x}' in {params_str:s}",
                        )
                        self._call_tracker.push_mem_def_inst(mem_def_inst)
                        self._slice_backwards(mem_def_inst, param_idxs)
            return set()

        # Ignore pointers that are in non-writable segments
        segment = self.bv.get_segment_at(constant)
        if segment and segment.writable:
            self._walk_ssa_mem_definitions(
                inst.function, [inst.ssa_memory_version], {0}, visit
            )
        else:
            self.log.debug(
                self._tag,
                f"Do not follow pointer '0x{constant:x}' since it is in a non-writable segment",
            )
        return

    def _slice_load_struct_mem_definitions(
        self, inst: bn.MediumLevelILLoadStructSsa
    ) -> None:
        """
        This method walks the SSA memory chain of the function `inst.function` backwards from
        `inst.ssa_memory_version` and slices the store instructions writing the same struct member
        as loaded by `inst`. Each such store ends the path through the SSA memory chain it is on. If
        some path reaches the function entry without such a store, the load source instruction is
        sliced.
        """
        inst_info = InstructionHelper.get_inst_info(inst, False)
        load_src_inst = inst.src
        read_bytes = set(range(inst.size))

        # Slice `mem_def_inst` and return `read_bytes` if it stores the same struct member
        def visit(mem_def_inst: bn.MediumLevelILInstruction) -> Set[int]:
            mem_def_inst_info = InstructionHelper.get_inst_info(mem_def_inst, False)
            # Check if memory defining instruction was followed before
            if self._is_mem_def_inst_followed(mem_def_inst):
                return set()
            match mem_def_inst:
                case bn.MediumLevelILStoreSsa() | bn.MediumLevelILStoreStructSsa():
                    if InstructionHelper.is_load_store_overlapping(inst, mem_def_inst):
                        self.log.debug(
                            self._tag,
                            f"Follow store instruction '{mem_def_inst_info:s}' since it overlaps the struct member loaded by '{inst_info:s}'",
                        )
                        self._call_tracker.push_mem_def_inst(mem_def_inst)
                        self._slice_backwards(mem_def_inst)
                        return read_bytes
                # Slice call if the callee may write the loaded struct member through a pointer
                # parameter
                case (
                    bn.MediumLevelILCallSsa()
                    | bn.MediumLevelILCallUntypedSsa()
                    | bn.MediumLevelILTailcallSsa()
                    | bn.MediumLevelILTailcallUntypedSsa()
                ):
                    self._slice_load_ptr_call(inst, mem_def_inst)
            return set()

        # Follow load source instruction if some path reaches the function entry without a store
        # writing the same struct member
        if self._walk_ssa_mem_definitions(
            inst.function, [inst.ssa_memory_version], read_bytes, visit
        ):
            load_src_inst_info = InstructionHelper.get_inst_info(load_src_inst, False)
            self.log.debug(
                self._tag,
                f"Follow load struct source instruction '{load_src_inst_info:s}' since some path reaches the function entry without a must-def",
            )
            self._slice_backwards(load_src_inst)
        return

    def _slice_callee_out_param_definitions(
        self,
        inst: bn.MediumLevelILCallSsa
        | bn.MediumLevelILCallUntypedSsa
        | bn.MediumLevelILTailcallSsa
        | bn.MediumLevelILTailcallUntypedSsa,
        dest_func: bn.MediumLevelILFunction,
        call_params: Set[int],
    ) -> None:
        """
        This method walks the SSA memory chain of the callee `dest_func` of call `inst` backwards
        from the memory versions of all its return instructions and slices the instructions writing
        the output parameters in `call_params` (calls define no bytes, so every path is walked to
        the function entry).
        """
        dest_func_name = dest_func.source_function.symbol.short_name

        def visit(mem_def_inst: bn.MediumLevelILInstruction) -> Set[int]:
            mem_def_inst_info = InstructionHelper.get_inst_info(mem_def_inst, False)
            # Match memory defining instruction
            match mem_def_inst:
                # Memory defining store instruction
                case bn.MediumLevelILStoreSsa() | bn.MediumLevelILStoreStructSsa():
                    # Match HLIL instruction
                    if mem_def_inst.hlil is None:
                        return set()
                    hlil_mem_def_inst = mem_def_inst.hlil.ssa_form
                    match hlil_mem_def_inst:
                        # Memory assignment to dereferenced variable
                        case bn.HighLevelILAssignMemSsa(
                            dest=(
                                bn.HighLevelILDerefSsa(
                                    src=bn.HighLevelILVarSsa(var=dest_var)
                                )
                                | bn.HighLevelILDerefFieldSsa(
                                    src=bn.HighLevelILVarSsa(var=dest_var)
                                )
                            )
                        ):
                            # Ensure we store a parameter variable of interest
                            param_vars = list(dest_func.source_function.parameter_vars)
                            if dest_var.var not in param_vars:
                                return set()
                            param_idx = param_vars.index(dest_var.var) + 1
                            if param_idx not in call_params:
                                return set()
                            # Push function containing the memory
                            # defining instruction
                            recursion = self._call_tracker.push_func(
                                to_inst=mem_def_inst,
                                downwards=True,
                                param_idx=param_idx,
                            )
                            # Follow the output parameter defining
                            # instruction
                            if not recursion:
                                dest_var_info = VariableHelper.get_ssavar_info(dest_var)
                                self.log.debug(
                                    self._tag,
                                    f"Follow instruction '{mem_def_inst_info:s}' of function '{dest_func_name:s}' since it writes the output parameter variable '{dest_var_info:s}'",
                                )
                                self._call_tracker.push_mem_def_inst(mem_def_inst)
                                self._slice_backwards(mem_def_inst)
                            # Recursion detected
                            else:
                                self.log.debug(
                                    self._tag,
                                    f"Do not follow instruction '{mem_def_inst_info:s}' of function '{dest_func_name:s}' since recursion detected",
                                )
                            # Pop function containing the memory
                            # defining instruction and follow the
                            # reached parameters
                            self.__pop_func_and_slice_reached_params(inst)
                # Memory defining call instruction
                case (
                    bn.MediumLevelILCallSsa()
                    | bn.MediumLevelILCallUntypedSsa()
                    | bn.MediumLevelILTailcallSsa()
                    | bn.MediumLevelILTailcallUntypedSsa()
                ):
                    # Get the callee's parameter instructions
                    mlil_param_insts = FunctionHelper.get_mlil_param_insts(dest_func)
                    # Iterate the relevant output parameters
                    for param_idx in call_params:
                        # Get callee's parameter of interest
                        if param_idx <= 0 or param_idx > len(mlil_param_insts):
                            continue
                        mlil_param_inst = mlil_param_insts[param_idx - 1]
                        if mlil_param_inst is None:
                            continue
                        param_ssa_var = mlil_param_inst.var
                        # Push function containing the memory defining
                        # instruction
                        recursion = self._call_tracker.push_func(
                            to_inst=mem_def_inst,
                            downwards=True,
                            param_idx=param_idx,
                        )
                        # Follow the output parameter defining
                        # instruction
                        if not recursion:
                            self._slice_ssa_var_mem_definition(
                                param_ssa_var,
                                mlil_param_inst,
                                mem_def_inst,
                            )
                        # Recursion detected
                        else:
                            self.log.debug(
                                self._tag,
                                f"Do not follow instruction '{mem_def_inst_info:s}' of function '{dest_func_name:s}' since recursion detected",
                            )
                        # Pop function containing the memory defining
                        # instruction and follow the reached parameters
                        self.__pop_func_and_slice_reached_params(inst)
            return set()

        ret_mem_versions = [
            ret_inst.ssa_memory_version
            for ret_inst in FunctionHelper.get_mlil_return_insts(dest_func)
        ]
        self._walk_ssa_mem_definitions(dest_func, ret_mem_versions, {0}, visit)
        return

    def _slice_call(
        self,
        inst: bn.MediumLevelILCallSsa
        | bn.MediumLevelILCallUntypedSsa
        | bn.MediumLevelILTailcallSsa
        | bn.MediumLevelILTailcallUntypedSsa,
        call_params: Set[int] = set(),
    ) -> None:
        """
        This method slices the call instruction `inst`. For direct calls into a function the slicer
        can go into, slicing proceeds in the callee, either at the instructions writing the output
        parameters in `call_params` (if the call was reached due to hitting these parameters) or at
        all possible return instructions (otherwise). For all other calls, the parameters are
        sliced.
        """
        call_level = self._call_tracker.get_call_level()
        dest_inst = inst.dest
        dest_inst_info = InstructionHelper.get_inst_info(dest_inst, False)
        match dest_inst:
            # Direct function calls
            case (
                bn.MediumLevelILConstPtr(constant=func_addr)
                | bn.MediumLevelILImport(constant=func_addr)
            ):
                # Get destination function and its symbol
                dest_func = self.bv.get_function_at(func_addr)
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
                    # Proceed slicing the relevant output parameters, if we followed the call due
                    # to reaching them
                    if call_params:
                        self._slice_callee_out_param_definitions(
                            inst, dest_func, call_params
                        )
                        return
                    # Proceed slicing all possible return instructions, if we followed the call
                    # due to reaching its return value
                    for ret_inst in FunctionHelper.get_mlil_return_insts(dest_func):
                        ret_inst_info = InstructionHelper.get_inst_info(ret_inst, False)
                        # Push callee and proceed slicing its return instruction (if no recursion)
                        recursion = self._call_tracker.push_func(
                            to_inst=ret_inst,
                            downwards=True,
                            param_idx=0,
                        )
                        if recursion:
                            self.log.debug(
                                self._tag,
                                f"Do not follow return instruction '{ret_inst_info:s}' of function '{dest_symb.short_name:s}' since recursion detected",
                            )
                        else:
                            self.log.debug(
                                self._tag,
                                f"Follow return instruction '{ret_inst_info:s}' of function '{dest_symb.short_name:s}'",
                            )
                            self._slice_backwards(ret_inst)
                        # Pop function containing the return instruction and follow the reached
                        # parameters
                        self.__pop_func_and_slice_reached_params(inst)
            # Indirect function calls
            case bn.MediumLevelILVarSsa() | bn.MediumLevelILLoadSsa():
                for param in inst.params:
                    self._slice_backwards(param)
            # Unhandled function calls
            case _:
                self.log.warn(
                    self._tag,
                    f"[{call_level:+d}] {dest_inst_info:s}: Missing call handler",
                )
        return

    def _slice_backwards(
        self,
        inst: bn.MediumLevelILInstruction,
        call_params: Set[int] = set(),
        *args,
        **kwargs,
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
            self.log.debug(
                self._tag, f"Maximum call level {self._max_call_level:d} reached"
            )
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
                self.log.debug(
                    self._tag,
                    f"Do not follow instruction '{inst_info:s}' since followed before in the current call frame",
                )
                return
        self.log.debug(self._tag, f"[{call_level:+d}] {inst_info:s}")
        self._call_tracker.push_inst(inst, call_params)
        match inst:
            # NOTE: Case order matters
            case bn.MediumLevelILConstPtr():
                self._slice_const_ptr_mem_definitions(inst)
            case bn.MediumLevelILLoadSsa():
                self._slice_load_mem_definitions(inst)
            case bn.MediumLevelILLoadStructSsa():
                self._slice_load_struct_mem_definitions(inst)
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
                bn.MediumLevelILCallSsa()
                | bn.MediumLevelILCallUntypedSsa()
                | bn.MediumLevelILTailcallSsa()
                | bn.MediumLevelILTailcallUntypedSsa()
            ):
                self._slice_call(inst, call_params)
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
                | bn.MediumLevelILUnimplMem()
            ):
                self._slice_backwards(inst.src)
            case bn.MediumLevelILBinaryBase() | bn.MediumLevelILCarryBase():
                self._slice_backwards(inst.left)
                self._slice_backwards(inst.right)
            case bn.MediumLevelILJump() | bn.MediumLevelILJumpTo():
                self._slice_backwards(inst.dest)
            case _:
                self.log.warn(
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
        self._call_tracker.push_func(to_inst=inst, downwards=False, param_idx=0)
        deque(
            inst.ssa_form.traverse(self._slice_backwards),
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
