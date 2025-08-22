from __future__ import annotations
from collections import deque
from mole.common.helper.function import FunctionHelper
from mole.common.helper.instruction import InstructionHelper
from mole.common.helper.variable import VariableHelper
from mole.common.log import log
from mole.core.call import MediumLevelILCallTracker
from typing import Any, Callable, Dict, List, Set
import binaryninja as bn
import networkx as nx


tag = "Mole.Slice"


class MediumLevelILInstructionGraph(nx.DiGraph):
    """
    This class represents a directed graph that stores the `MediumLevelILInstruction` of a slice.
    """

    def add_node(
        self,
        inst: bn.MediumLevelILInstruction,
        call_level: int = None,
        caller_site: bn.MediumLevelILFunction = None,
        **attr: Any,
    ) -> None:
        """
        This method adds a node for the given instruction `inst` with the following node attributes:
        The attribute `call_level` is expected to be `inst`'s level within the call stack. The
        attribute `caller_site` is expected to be the function that called `inst.function`.
        """
        super().add_node(inst, call_level=call_level, caller_site=caller_site, **attr)
        return

    def add_edge(
        self,
        from_inst: bn.MediumLevelILInstruction,
        to_inst: bn.MediumLevelILInstruction,
        **attr: Any,
    ) -> None:
        """
        This method adds an edge from `from_inst` to `to_inst`.
        """
        if from_inst not in self.nodes:
            info = InstructionHelper.get_inst_info(from_inst)
            log.warn(
                tag,
                f"Edge not added to instruction graph due to an inexisting from node ({info:s})",
            )
            return
        if to_inst not in self.nodes:
            info = InstructionHelper.get_inst_info(to_inst)
            log.warn(
                tag,
                f"Edge not added to instruction graph due to an inexisting to node ({info:s})",
            )
            return
        super().add_edge(from_inst, to_inst, **attr)
        return


class MediumLevelILFunctionGraph(nx.DiGraph):
    """
    This class represents a directed graph that stores the `MediumLevelILFunction` call graph of a
    slice.
    """

    def add_node(
        self, call_site: bn.MediumLevelILFunction, call_level: int = None, **attr: Any
    ) -> None:
        """
        This method adds a node for the given `call_site`, with the following node attribute: The
        attribute `call_level` is expected to be the `call_site`'s level within the call stack.
        """
        super().add_node(call_site, call_level=call_level, **attr)
        return

    def add_edge(
        self,
        from_call_site: bn.MediumLevelILFunction,
        to_call_site: bn.MediumLevelILFunction,
        **attr: Any,
    ) -> None:
        """
        This method adds an edge from `from_call_site` to `to_call_site`.
        """
        if from_call_site not in self.nodes:
            info = FunctionHelper.get_func_info(from_call_site)
            log.warn(
                tag,
                f"Edge not added to function graph due to an inexisting from node ({info:s})",
            )
            return
        if to_call_site not in self.nodes:
            info = FunctionHelper.get_func_info(to_call_site)
            log.warn(
                tag,
                f"Edge not added to function graph due to an inexisting to node ({info:s})",
            )
            return
        super().add_edge(from_call_site, to_call_site, **attr)
        return

    def copy(self) -> MediumLevelILFunctionGraph:
        """
        This method returns a copy of the graph.
        """
        graph = MediumLevelILFunctionGraph()
        graph.update(self)
        return graph

    def to_dict(self, debug: bool = False) -> Dict:
        """
        This method serializes the graph to a dictionary.
        """
        # Serialize nodes
        nodes: List[Dict[str, Any]] = []
        for node, atts in self.nodes(data=True):
            node_dict = {
                "adr": hex(node.source_function.start),
                "att": atts,
            }
            if debug:
                node_dict["func"] = FunctionHelper.get_func_info(node, True)
            nodes.append(node_dict)
        # Serialize edges
        edges: List[Dict[str, Any]] = []
        for src_node, tgt_node, atts in self.edges(data=True):
            edges.append(
                {
                    "src": hex(src_node.source_function.start),
                    "snk": hex(tgt_node.source_function.start),
                    "att": atts,
                }
            )
        return {"nodes": nodes, "edges": edges}

    @classmethod
    def from_dict(
        cls: MediumLevelILFunctionGraph, bv: bn.BinaryView, d: Dict
    ) -> MediumLevelILFunctionGraph:
        """
        This method deserializes a dictionary to a graph.
        """
        call_graph: MediumLevelILFunctionGraph = cls()
        # Deserialize nodes
        for node in d["nodes"]:
            addr = int(node["adr"], 0)
            func = bv.get_function_at(addr)
            atts = node["att"]
            call_graph.add_node(func.mlil.ssa_form, **atts)
        # Deserialize edges
        for edge in d["edges"]:
            src_addr = int(edge["src"], 0)
            src_func = bv.get_function_at(src_addr)
            tgt_addr = int(edge["snk"], 0)
            tgt_func = bv.get_function_at(tgt_addr)
            atts = edge["att"]
            call_graph.add_edge(src_func.mlil.ssa_form, tgt_func.mlil.ssa_form, **atts)
        return call_graph


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
        """
        This method initializes a backward slicer for for MLIL instructions.
        """
        self._bv: bn.BinaryView = bv
        self._tag = custom_tag if custom_tag else tag
        self._origin = None
        if "src" in self._tag.lower():
            self._origin = "src"
        elif "snk" in self._tag.lower():
            self._origin = "snk"
        self._max_call_level: int = max_call_level
        self._max_memory_slice_depth: int = max_memory_slice_depth
        self._cancelled = cancelled
        self._inst_visited: Set[bn.MediumLevelILInstruction] = set()
        self.inst_graph: MediumLevelILInstructionGraph = MediumLevelILInstructionGraph()
        self.call_graph: MediumLevelILFunctionGraph = MediumLevelILFunctionGraph()
        return

    def _slice_params(
        self,
        inst: bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa,
        call_level: int = 0,
        caller_site: bn.MediumLevelILFunction = None,
    ) -> None:
        """
        This method slices all parameters of the function call instruction `inst`.
        """
        call_info = InstructionHelper.get_inst_info(inst, False)
        for parm_idx, parm in enumerate(inst.params, start=1):
            parm_info = InstructionHelper.get_inst_info(parm, False)
            log.debug(
                self._tag,
                f"Follow parameter {parm_idx:d} '{parm_info:s}' of function call '{call_info:s}'",
            )
            self.inst_graph.add_node(inst, call_level, caller_site, origin=self._origin)
            self.inst_graph.add_node(parm, call_level, caller_site, origin=self._origin)
            self.inst_graph.add_edge(inst, parm)
            self._slice_backwards(parm, call_level, caller_site)
        return

    def _slice_ssa_var_definition(
        self,
        ssa_var: bn.SSAVariable,
        inst: bn.MediumLevelILInstruction,
        call_level: int = 0,
        caller_site: bn.MediumLevelILFunction = None,
    ) -> None:
        """
        This method first tries to find the instruction defining variable `ssa_var` within
        `inst.function`. If it is found, slicing proceeds at the identified defining instruction. If
        no defining instruction is found, the method distinguishes whether we went up
        (caller_level <= call_level) or down (caller_level > call_level) the call stack. If we went
        up, we know from which caller we came from and can proceed only this single caller site. If
        we went down, we don't know this and need to follow all caller sites.
        """
        # Try finding the definition withing the current function
        inst_def = inst.function.get_ssa_var_definition(ssa_var)
        if inst_def:
            self.inst_graph.add_node(inst, call_level, caller_site, origin=self._origin)
            self.inst_graph.add_node(
                inst_def, call_level, caller_site, origin=self._origin
            )
            self.inst_graph.add_edge(inst, inst_def)
            self._slice_backwards(inst_def, call_level, caller_site)
            return
        # Try finding the definition in another function
        if self._max_call_level >= 0 and abs(call_level) > self._max_call_level:
            return
        caller_level = self.call_graph.nodes.get(caller_site, {}).get(
            "call_level", None
        )
        for parm_idx, parm_var in enumerate(
            inst.function.source_function.parameter_vars, start=1
        ):
            if parm_var != ssa_var.var:
                continue
            for cs in inst.function.source_function.caller_sites:
                # Determine caller sites call instructions
                call_insts: Set[
                    bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa
                ] = set()
                if cs.function is None:
                    log.warn(
                        tag,
                        f"Caller site at address 0x{cs.address:x} contains no valid function",
                    )
                    continue
                if (
                    cs.function.mlil is None or cs.function.mlil.ssa_form is None
                ) and cs.function.analysis_skipped:
                    log.info(
                        tag,
                        f"Forcing analysis of caller site at address 0x{cs.address:x}",
                    )
                    cs.function.analysis_skipped = False
                    if cs.function.mlil is None or cs.function.mlil.ssa_form is None:
                        log.warn(
                            tag,
                            f"Caller site at address 0x{cs.address:x} contains no valid function even after forcing analysis",
                        )
                        continue
                func = cs.function.mlil.ssa_form
                for func_inst in func.instructions:
                    if func_inst.address == cs.address:
                        call_insts.update(
                            InstructionHelper.get_mlil_call_insts(func_inst)
                        )
                # Iterate all call instructions
                for call_inst in call_insts:
                    call_parm = call_inst.params[parm_idx - 1]
                    # Visit specific caller site if we go up the call stack (all caller sites otherwise)
                    if caller_level is not None and caller_level <= call_level:
                        # Ignore if the actual call instruction is not within the caller site
                        if caller_site != call_inst.function:
                            continue
                        # Ignore if the actual call instruction was not sliced before
                        if call_inst not in self.inst_graph:
                            continue
                    var_info = VariableHelper.get_ssavar_info(ssa_var)
                    call_info = InstructionHelper.get_inst_info(call_inst, False)
                    log.debug(
                        self._tag,
                        f"Follow parameter '{var_info:s}' to caller '{call_info:s}'",
                    )
                    self.inst_graph.add_node(
                        inst, call_level, caller_site, origin=self._origin
                    )
                    self.inst_graph.add_node(
                        call_parm, call_level - 1, inst.function, origin=self._origin
                    )
                    self.inst_graph.add_edge(inst, call_parm)
                    self.call_graph.add_node(call_inst.function, call_level - 1)
                    self.call_graph.add_node(inst.function, call_level)
                    self.call_graph.add_edge(call_inst.function, inst.function)
                    self._slice_backwards(call_parm, call_level - 1, inst.function)
        return

    def _slice_backwards(
        self,
        inst: bn.MediumLevelILInstruction,
        call_level: int = 0,
        caller_site: bn.MediumLevelILFunction = None,
    ) -> None:
        """
        This method backward slices instruction `inst` based on its type. Parameter `call_level` is
        expected to be `inst`'s level within the call stack. Parameter `caller_site` is expected to
        be the function that called `inst.function`.
        """
        if self._cancelled and self._cancelled():
            return
        info = InstructionHelper.get_inst_info(inst)
        # Maxium call level
        if self._max_call_level >= 0 and abs(call_level) > self._max_call_level:
            log.debug(self._tag, f"Maximum call level {self._max_call_level:d} reached")
            return
        # Instruction sliced before
        if inst in self._inst_visited:
            log.debug(self._tag, f"Ignore instruction '{info:s}' since sliced before")
            return
        # Slice instruction
        self._inst_visited.add(inst)
        log.debug(self._tag, f"[{call_level:+d}] {info:s}")
        match inst:
            # TODO: Support all instructions
            # NOTE: Case order matters
            case bn.MediumLevelILConstPtr():
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
                    if mem_def_inst in self._inst_visited:
                        log.debug(
                            self._tag,
                            f"Ignore '{mem_def_inst_info:s}' since sliced before",
                        )
                        continue
                    match mem_def_inst:
                        # Slice calls having the same pointer as parameter
                        case bn.MediumLevelILCallSsa(params=params):
                            followed = False
                            for param in params:
                                match param:
                                    case bn.MediumLevelILConstPtr(
                                        constant=constant
                                    ) if constant == inst.constant:
                                        log.debug(
                                            self._tag,
                                            f"Follow '{mem_def_inst_info:s}' since it uses '0x{inst.constant:x}'",
                                        )
                                        self.inst_graph.add_node(
                                            inst,
                                            call_level,
                                            caller_site,
                                            origin=self._origin,
                                        )
                                        self.inst_graph.add_node(
                                            mem_def_inst,
                                            call_level,
                                            caller_site,
                                            origin=self._origin,
                                        )
                                        self.inst_graph.add_edge(inst, mem_def_inst)
                                        self._slice_backwards(
                                            mem_def_inst, call_level, caller_site
                                        )
                                        followed = True
                                if followed:
                                    break
                            if not followed:
                                log.debug(
                                    self._tag,
                                    f"Do not follow '{mem_def_inst_info:s}' since it not uses '0x{inst.constant:x}'",
                                )
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
                # Get all instructions in the current function defining the current memory version
                mem_def_insts = FunctionHelper.get_ssa_memory_definitions(
                    inst.function,
                    inst.ssa_memory_version,
                    self._max_memory_slice_depth,
                )
                for mem_def_inst in mem_def_insts:
                    mem_def_inst_info = InstructionHelper.get_inst_info(
                        mem_def_inst, False
                    )
                    # Check if sliced before
                    if mem_def_inst in self._inst_visited:
                        log.debug(
                            self._tag,
                            f"Ignore '{mem_def_inst_info:s}' since sliced before",
                        )
                        continue
                    # Check if memory defining instruction is in the use sites
                    if mem_def_inst not in dest_var_use_sites:
                        log.debug(
                            self._tag,
                            f"Do not follow '{mem_def_inst_info:s}' since it not uses '&{var_info:s}'",
                        )
                        continue
                    match mem_def_inst:
                        # Slice calls having the referenced variable address (`&var_y`) as parameter
                        case bn.MediumLevelILCallSsa():
                            var_addr_ass_inst = dest_var_use_sites[mem_def_inst]
                            var_addr_ass_inst_info = InstructionHelper.get_inst_info(
                                var_addr_ass_inst, False
                            )
                            log.debug(
                                self._tag,
                                f"Follow '{mem_def_inst_info:s}' since it uses '{var_addr_ass_inst_info:s}'",
                            )
                            self.inst_graph.add_node(
                                inst, call_level, caller_site, origin=self._origin
                            )
                            self.inst_graph.add_node(
                                mem_def_inst,
                                call_level,
                                caller_site,
                                origin=self._origin,
                            )
                            self.inst_graph.add_edge(inst, mem_def_inst)
                            self._slice_backwards(mem_def_inst, call_level, caller_site)
            case (
                bn.MediumLevelILVarSsa()
                | bn.MediumLevelILVarSsaField()
                | bn.MediumLevelILVarField()
                | bn.MediumLevelILUnimplMem()
            ):
                self._slice_ssa_var_definition(inst.src, inst, call_level, caller_site)
            case bn.MediumLevelILRet():
                for ret in inst.src:
                    self.inst_graph.add_node(
                        inst, call_level, caller_site, origin=self._origin
                    )
                    self.inst_graph.add_node(
                        ret, call_level, caller_site, origin=self._origin
                    )
                    self.inst_graph.add_edge(inst, ret)
                    self._slice_backwards(ret, call_level, caller_site)
            case bn.MediumLevelILVarSplitSsa():
                self._slice_ssa_var_definition(inst.high, inst, call_level, caller_site)
                self._slice_ssa_var_definition(inst.low, inst, call_level, caller_site)
            case bn.MediumLevelILVarPhi():
                for var in inst.src:
                    self._slice_ssa_var_definition(var, inst, call_level, caller_site)
            case (
                bn.MediumLevelILCallSsa(dest=dest_inst)
                | bn.MediumLevelILCallUntypedSsa(dest=dest_inst)
                | bn.MediumLevelILTailcallSsa(dest=dest_inst)
                | bn.MediumLevelILTailcallUntypedSsa(dest=dest_inst)
            ):
                call_info = InstructionHelper.get_inst_info(inst, False)
                dest_info = InstructionHelper.get_inst_info(dest_inst)

                match dest_inst:
                    # Direct function calls
                    case (
                        bn.MediumLevelILConstPtr(constant=func_addr)
                        | bn.MediumLevelILImport(constant=func_addr)
                    ):
                        # Get function at destination
                        func = self._bv.get_function_at(func_addr)
                        # No valid function found within the binary
                        if not func or not func.mlil or not func.mlil.ssa_form:
                            self._slice_params(inst, call_level, caller_site)
                        # Valid function found within the binary
                        else:
                            func = func.mlil.ssa_form
                            symb = func.source_function.symbol

                            for func_inst in func.instructions:
                                # TODO: Support all return instructions
                                match func_inst:
                                    case (
                                        bn.MediumLevelILRet()
                                        | bn.MediumLevelILTailcallSsa()
                                    ):
                                        # Function
                                        if symb.type in [
                                            bn.SymbolType.FunctionSymbol,
                                            bn.SymbolType.LibraryFunctionSymbol,
                                        ]:
                                            ret_info = InstructionHelper.get_inst_info(
                                                func_inst, False
                                            )
                                            log.debug(
                                                self._tag,
                                                f"Follow return instruction '{ret_info:s}' of function '{call_info:s}'",
                                            )
                                            self.inst_graph.add_node(
                                                inst,
                                                call_level,
                                                caller_site,
                                                origin=self._origin,
                                            )
                                            self.inst_graph.add_node(
                                                func_inst,
                                                call_level + 1,
                                                inst.function,
                                                origin=self._origin,
                                            )
                                            self.inst_graph.add_edge(inst, func_inst)
                                            self.call_graph.add_node(
                                                inst.function, call_level
                                            )
                                            self.call_graph.add_node(
                                                func, call_level + 1
                                            )
                                            self.call_graph.add_edge(
                                                inst.function, func
                                            )
                                            self._slice_backwards(
                                                func_inst,
                                                call_level + 1,
                                                inst.function,
                                            )
                                        # Imported function
                                        elif (
                                            symb.type
                                            == bn.SymbolType.ImportedFunctionSymbol
                                        ):
                                            self._slice_params(
                                                inst, call_level, caller_site
                                            )
                                        else:
                                            log.warn(
                                                self._tag,
                                                f"Function '{call_info:s}' has an unexpected type '{str(symb.type):s}'",
                                            )
                    # Indirect function calls
                    case bn.MediumLevelILVarSsa():
                        self._slice_params(inst, call_level, caller_site)
                    # Unhandled function calls
                    case _:
                        log.warn(
                            self._tag,
                            f"[{call_level:+d}] {dest_info:s}: Missing handler for function call",
                        )
            case (
                bn.MediumLevelILSyscallSsa()
                | bn.MediumLevelILSyscallUntypedSsa()
                | bn.MediumLevelILIntrinsicSsa()
                | bn.MediumLevelILSeparateParamList()
            ):
                for par in inst.params:
                    self.inst_graph.add_node(
                        inst, call_level, caller_site, origin=self._origin
                    )
                    self.inst_graph.add_node(
                        par, call_level, caller_site, origin=self._origin
                    )
                    self.inst_graph.add_edge(inst, par)
                    self._slice_backwards(par, call_level, caller_site)
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
                | bn.MediumLevelILLoadSsa()
                | bn.MediumLevelILLoadStructSsa()
                | bn.MediumLevelILStoreSsa()
                | bn.MediumLevelILStoreStructSsa()
            ):
                self.inst_graph.add_node(
                    inst, call_level, caller_site, origin=self._origin
                )
                self.inst_graph.add_node(
                    inst.src, call_level, caller_site, origin=self._origin
                )
                self.inst_graph.add_edge(inst, inst.src)
                self._slice_backwards(inst.src, call_level, caller_site)
            case bn.MediumLevelILBinaryBase() | bn.MediumLevelILCarryBase():
                self.inst_graph.add_node(
                    inst, call_level, caller_site, origin=self._origin
                )
                self.inst_graph.add_node(
                    inst.left, call_level, caller_site, origin=self._origin
                )
                self.inst_graph.add_edge(inst, inst.left)
                self._slice_backwards(inst.left, call_level, caller_site)
                self.inst_graph.add_node(
                    inst, call_level, caller_site, origin=self._origin
                )
                self.inst_graph.add_node(
                    inst.right, call_level, caller_site, origin=self._origin
                )
                self.inst_graph.add_edge(inst, inst.right)
                self._slice_backwards(inst.right, call_level, caller_site)
            case bn.MediumLevelILJump() | bn.MediumLevelILJumpTo():
                self.inst_graph.add_node(
                    inst, call_level, caller_site, origin=self._origin
                )
                self.inst_graph.add_node(
                    inst.dest, call_level, caller_site, origin=self._origin
                )
                self.inst_graph.add_edge(inst, inst.dest)
                self._slice_backwards(inst.dest, call_level, caller_site)
            case _:
                log.warn(self._tag, f"[{call_level:+d}] {info:s}: Missing handler")
        return

    def slice_backwards(self, inst: bn.MediumLevelILInstruction) -> None:
        """
        This method backward slices the instruction `inst`.
        """
        for _ in inst.ssa_form.traverse(self._slice_backwards):
            pass
        return


class NewMediumLevelILBackwardSlicer:
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
        call_insts: Set[bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa] = set()
        for caller_site in inst.function.source_function.caller_sites:
            # Ensure the caller site is a valid function
            caller_func = caller_site.function
            if caller_func is None:
                log.warn(
                    self._tag,
                    f"Caller site at address 0x{caller_site.address:x} contains no valid function",
                )
                continue
            # Ensure the caller site has a valid MLIL representation
            if (
                caller_func.mlil is None or caller_func.mlil.ssa_form is None
            ) and caller_func.analysis_skipped:
                log.info(
                    self._tag,
                    f"Forcing analysis of caller site at address 0x{caller_site.address:x}",
                )
                caller_func.analysis_skipped = False
                if caller_func.mlil is None or caller_func.mlil.ssa_form is None:
                    log.warn(
                        self._tag,
                        f"Caller site at address 0x{caller_site.address:x} contains no valid function even after forcing analysis",
                    )
                    continue
            # Find all instructions calling the current function
            for caller_inst in caller_func.mlil.ssa_form.instructions:
                if caller_inst.address == caller_site.address:
                    call_insts.update(
                        InstructionHelper.get_mlil_call_insts(caller_inst)
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
                for call_inst in call_insts:
                    call_inst_info = InstructionHelper.get_inst_info(call_inst, False)
                    log.debug(
                        self._tag,
                        f"Follow parameter {param_idx:d} '{ssa_var_info:s}' to possible caller '{call_inst_info:s}'",
                    )
                    self._call_tracker.push_func(call_inst.function, reverse=True)
                    self._slice_backwards(call_inst.params[param_idx - 1])
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
            case bn.MediumLevelILConstPtr():
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
                    if self._call_tracker.is_in_current_call_frame(mem_def_inst):
                        log.debug(
                            self._tag,
                            f"Do not follow instruction '{mem_def_inst_info:s}' since followed before in the current call frame",
                        )
                        continue
                    match mem_def_inst:
                        # Slice calls having the same pointer as parameter
                        case bn.MediumLevelILCallSsa(params=params):
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
                                        self._slice_backwards(mem_def_inst)
                                        followed = True
                                if followed:
                                    break
                            if not followed:
                                log.debug(
                                    self._tag,
                                    f"Do not follow instruction '{mem_def_inst_info:s}' since it does not use '0x{inst.constant:x}'",
                                )
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
                    if self._call_tracker.is_in_current_call_frame(mem_def_inst):
                        log.debug(
                            self._tag,
                            f"Do not follow instruction '{mem_def_inst_info:s}' since followed before in the current call frame",
                        )
                        continue
                    match mem_def_inst:
                        # Slice calls having the referenced variable address (`&var_y`) as parameter
                        case bn.MediumLevelILCallSsa():
                            var_addr_ass_inst = dest_var_use_sites[mem_def_inst]
                            var_addr_ass_inst_info = InstructionHelper.get_inst_info(
                                var_addr_ass_inst, False
                            )
                            log.debug(
                                self._tag,
                                f"Follow call instruction '{mem_def_inst_info:s}' since it uses '{var_addr_ass_inst_info:s}'",
                            )
                            self._slice_backwards(mem_def_inst)
            case (
                bn.MediumLevelILVarSsa()
                | bn.MediumLevelILVarSsaField()
                | bn.MediumLevelILVarField()
                | bn.MediumLevelILUnimplMem()
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
                                            dest_func_inst_info = (
                                                InstructionHelper.get_inst_info(
                                                    dest_func_inst, False
                                                )
                                            )
                                            log.debug(
                                                self._tag,
                                                f"Follow return instruction '{dest_func_inst_info:s}' of function '{dest_inst_info:s}'",
                                            )
                                            self._call_tracker.push_func(dest_func)
                                            self._slice_backwards(dest_func_inst)
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
                | bn.MediumLevelILLoadSsa()
                | bn.MediumLevelILLoadStructSsa()
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
        self._call_tracker.push_func(inst.function, reverse=True)
        deque(
            inst.ssa_form.traverse(lambda inst: self._slice_backwards(inst)),
            maxlen=0,
        )
        self._call_tracker.pop_func()
        return

    def get_call_graph(self) -> nx.DiGraph:
        """
        This method returns a copy of the call graph built during slicing.
        """
        if not self._call_tracker:
            return nx.DiGraph()
        return self._call_tracker.get_call_graph().copy()

    def get_inst_graph(self) -> nx.DiGraph:
        """
        This method returns a copy of the instruction graph built during slicing.
        """
        if not self._call_tracker:
            return nx.DiGraph()
        return self._call_tracker.get_inst_graph().copy()
