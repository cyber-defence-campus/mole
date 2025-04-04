from __future__ import annotations
from mole.common.help import FunctionHelper, InstructionHelper, VariableHelper
from functools import lru_cache
from mole.common.log import log
from typing import Any, Dict, List, Set, Tuple
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

    def reverse(self) -> MediumLevelILInstructionGraph:
        """
        This method returns a copy of the graph with the directions of edges reversed. All node and
        edge attributes are preserved.
        """
        reversed_graph = MediumLevelILInstructionGraph()
        for node, attrs in self.nodes(data=True):
            reversed_graph.add_node(node, **attrs)
        for from_node, to_node, edge_attrs in self.edges(data=True):
            reversed_graph.add_edge(to_node, from_node, **edge_attrs)
        return reversed_graph


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

    def to_dict(self) -> Dict:
        """
        This method serializes the graph to a dictionary.
        """
        # Serialize nodes
        nodes: List[Dict[str, Any]] = []
        for node, atts in self.nodes(data=True):
            nodes.append({"adr": hex(node.source_function.start), "att": atts})
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
        self, bv: bn.BinaryView, custom_tag: str = "", max_call_level: int = -1
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
        self._inst_visited: Set[bn.MediumLevelILInstruction] = set()
        self.inst_graph: MediumLevelILInstructionGraph = MediumLevelILInstructionGraph()
        self.call_graph: MediumLevelILFunctionGraph = MediumLevelILFunctionGraph()
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
            inst.function.source_function.parameter_vars
        ):
            if parm_var != ssa_var.var:
                continue
            for cs in inst.function.source_function.caller_sites:
                try:
                    cs_inst = cs.mlil.ssa_form
                    cs_parm = cs_inst.params[parm_idx]
                    # Visit specific caller site if we go up the call stack (all caller sites otherwise)
                    if caller_level is not None and caller_level <= call_level:
                        if caller_site != cs_inst.function:
                            continue
                    var_info = VariableHelper.get_ssavar_info(ssa_var)
                    cs_info = InstructionHelper.get_inst_info(cs_inst, False)
                    log.debug(
                        self._tag,
                        f"Follow parameter '{var_info:s}' to caller '{cs_info:s}'",
                    )
                    self.inst_graph.add_node(
                        inst, call_level, caller_site, origin=self._origin
                    )
                    self.inst_graph.add_node(
                        cs_parm, call_level - 1, inst.function, origin=self._origin
                    )
                    self.inst_graph.add_edge(inst, cs_parm)
                    self.call_graph.add_node(cs_inst.function, call_level - 1)
                    self.call_graph.add_node(inst.function, call_level)
                    self.call_graph.add_edge(cs_inst.function, inst.function)
                    self._slice_backwards(cs_parm, call_level - 1, inst.function)
                except Exception as _:
                    continue
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
            case (
                bn.MediumLevelILConst()
                | bn.MediumLevelILConstData()
                | bn.MediumLevelILFloatConst()
                | bn.MediumLevelILImport()
            ):
                pass
            case bn.MediumLevelILConstPtr():
                # Iterate all memory defining instructions
                for mem_def_inst in self.get_mem_definitions(inst):
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
            case bn.MediumLevelILVarAliased() | bn.MediumLevelILAddressOf():
                # Find all assignment instructions using the same variable as a source
                var, var_addr_ass_insts = self.get_var_addr_assignments(inst)
                var_info = VariableHelper.get_var_info(var)
                # Determine all use sites of assignment instructions' destinations
                var_use_sites: Dict[
                    bn.MediumLevelILInstruction, bn.MediumLevelILSetVarSsa
                ] = {}
                for var_addr_ass_inst in var_addr_ass_insts:
                    for var_use_site in var_addr_ass_inst.dest.use_sites:
                        var_use_sites[var_use_site] = var_addr_ass_inst
                # Iterate all memory defining instructions
                for mem_def_inst in self.get_mem_definitions(inst):
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
                        # Slice calls having the same variable address as parameter
                        case bn.MediumLevelILCallSsa():
                            if mem_def_inst in var_use_sites.keys():
                                var_addr_ass_inst = var_use_sites[mem_def_inst]
                                var_addr_ass_inst_info = (
                                    InstructionHelper.get_inst_info(
                                        var_addr_ass_inst, False
                                    )
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
                                self._slice_backwards(
                                    mem_def_inst, call_level, caller_site
                                )
                            else:
                                log.debug(
                                    self._tag,
                                    f"Do not follow '{mem_def_inst_info:s}' since it not uses '&{var_info:s}'",
                                )
            case (
                bn.MediumLevelILVarSsa()
                | bn.MediumLevelILVarAliasedField()
                | bn.MediumLevelILVarSsaField()
            ):
                self._slice_ssa_var_definition(inst.src, inst, call_level, caller_site)
            case (
                bn.MediumLevelILNot()
                | bn.MediumLevelILSx()
                | bn.MediumLevelILZx()
                | bn.MediumLevelILBoolToInt()
                | bn.MediumLevelILLoadSsa()
                | bn.MediumLevelILLoadStructSsa()
                | bn.MediumLevelILLowPart()
                | bn.MediumLevelILFneg()
                | bn.MediumLevelILFloatConv()
            ):
                self.inst_graph.add_node(
                    inst, call_level, caller_site, origin=self._origin
                )
                self.inst_graph.add_node(
                    inst.src, call_level, caller_site, origin=self._origin
                )
                self.inst_graph.add_edge(inst, inst.src)
                self._slice_backwards(inst.src, call_level, caller_site)
            case (
                bn.MediumLevelILAdd()
                | bn.MediumLevelILAdc()
                | bn.MediumLevelILSub()
                | bn.MediumLevelILSbb()
                | bn.MediumLevelILAnd()
                | bn.MediumLevelILOr()
                | bn.MediumLevelILXor()
                | bn.MediumLevelILLsl()
                | bn.MediumLevelILLsr()
                | bn.MediumLevelILAsr()
                | bn.MediumLevelILRor()
                | bn.MediumLevelILMul()
                | bn.MediumLevelILMuluDp()
                | bn.MediumLevelILMulsDp()
                | bn.MediumLevelILDivu()
                | bn.MediumLevelILDivuDp()
                | bn.MediumLevelILDivs()
                | bn.MediumLevelILDivsDp()
                | bn.MediumLevelILFadd()
                | bn.MediumLevelILFsub()
                | bn.MediumLevelILFmul()
                | bn.MediumLevelILFdiv()
                | bn.MediumLevelILCmpUlt()
            ):
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
            case (
                bn.MediumLevelILSetVarSsa()
                | bn.MediumLevelILSetVarAliased()
                | bn.MediumLevelILSetVarAliasedField()
                | bn.MediumLevelILSetVarSsaField()
                | bn.MediumLevelILSetVarSplitSsa()
            ):
                self.inst_graph.add_node(
                    inst, call_level, caller_site, origin=self._origin
                )
                self.inst_graph.add_node(
                    inst.src, call_level, caller_site, origin=self._origin
                )
                self.inst_graph.add_edge(inst, inst.src)
                self._slice_backwards(inst.src, call_level, caller_site)
            case bn.MediumLevelILVarSplitSsa():
                self._slice_ssa_var_definition(inst.high, inst, call_level, caller_site)
                self._slice_ssa_var_definition(inst.low, inst, call_level, caller_site)
            case bn.MediumLevelILVarPhi():
                for var in inst.src:
                    self._slice_ssa_var_definition(var, inst, call_level, caller_site)
            case (
                bn.MediumLevelILCallSsa(dest=dest_inst)
                | bn.MediumLevelILTailcallSsa(dest=dest_inst)
            ):
                call_info = InstructionHelper.get_inst_info(inst, False)
                dest_info = InstructionHelper.get_inst_info(dest_inst)
                match dest_inst:
                    # Direct function calls
                    case (
                        bn.MediumLevelILConstPtr(constant=func_addr)
                        | bn.MediumLevelILImport(constant=func_addr)
                    ):
                        try:
                            func = self._bv.get_function_at(func_addr).mlil.ssa_form
                            symb = func.source_function.symbol
                            for func_inst in func.instructions:
                                # TODO: Support all return instructions
                                match func_inst:
                                    case (
                                        bn.MediumLevelILRet()
                                        | bn.MediumLevelILTailcallSsa()
                                    ):
                                        # Function
                                        if symb.type == bn.SymbolType.FunctionSymbol:
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
                                                func_inst, call_level + 1, inst.function
                                            )
                                        # Imported function
                                        elif (
                                            symb.type
                                            == bn.SymbolType.ImportedFunctionSymbol
                                        ):
                                            for par_idx, par in enumerate(inst.params):
                                                par_info = (
                                                    InstructionHelper.get_inst_info(
                                                        par, False
                                                    )
                                                )
                                                log.debug(
                                                    self._tag,
                                                    f"Follow parameter {par_idx:d} '{par_info:s}' of imported function '{call_info:s}'",
                                                )
                                                self.inst_graph.add_node(
                                                    inst,
                                                    call_level,
                                                    caller_site,
                                                    origin=self._origin,
                                                )
                                                self.inst_graph.add_node(
                                                    par,
                                                    call_level,
                                                    caller_site,
                                                    origin=self._origin,
                                                )
                                                self.inst_graph.add_edge(inst, par)
                                                self._slice_backwards(
                                                    par, call_level, caller_site
                                                )
                                        else:
                                            log.warn(
                                                self._tag,
                                                f"Function '{call_info:s}' has an unexpected type '{str(symb.type):s}'",
                                            )
                        except Exception as _:
                            # Function not found within the binary
                            pass
                    # Indirect function calls
                    case bn.MediumLevelILVarSsa():
                        for par_idx, par in enumerate(inst.params):
                            par_info = InstructionHelper.get_inst_info(par, False)
                            log.debug(
                                self._tag,
                                f"Follow parameter {par_idx:d} '{par_info:s}' of indirect function call '{call_info:s}'",
                            )
                            self.inst_graph.add_node(
                                inst, call_level, caller_site, origin=self._origin
                            )
                            self.inst_graph.add_node(
                                par, call_level, caller_site, origin=self._origin
                            )
                            self.inst_graph.add_edge(inst, par)
                            self._slice_backwards(par, call_level, caller_site)
                    case _:
                        log.warn(
                            self._tag,
                            f"[{call_level:+d}] {dest_info:s}: Missing handler",
                        )
            case bn.MediumLevelILSyscallSsa():
                for par in inst.params:
                    self.inst_graph.add_node(
                        inst, call_level, caller_site, origin=self._origin
                    )
                    self.inst_graph.add_node(
                        par, call_level, caller_site, origin=self._origin
                    )
                    self.inst_graph.add_edge(inst, par)
                    self._slice_backwards(par, call_level, caller_site)
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

    @staticmethod
    @lru_cache(maxsize=None)
    def _get_mem_definitions(
        inst: bn.MediumLevelILInstruction,
        ssa_memory_versions: frozenset[int] = frozenset(),
    ) -> List[bn.MediumLevelILInstruction]:
        # Empty instruction or memory version already seen
        if inst is None or inst.ssa_memory_version in ssa_memory_versions:
            return []
        ssa_memory_versions = ssa_memory_versions.union({inst.ssa_memory_version})
        # Current memory defining instruction
        mem_def_inst = inst.function.get_ssa_memory_definition(inst.ssa_memory_version)
        if mem_def_inst is None:
            return []
        mem_def_insts: List[bn.MediumLevelILInstruction] = [mem_def_inst]
        # Recursive memory defining instructions
        for mem_def_inst in MediumLevelILBackwardSlicer._get_mem_definitions(
            mem_def_inst, ssa_memory_versions
        ):
            if mem_def_inst not in mem_def_insts:
                mem_def_insts.append(mem_def_inst)
        return mem_def_insts

    def get_mem_definitions(
        self,
        inst: bn.MediumLevelILInstruction,
    ) -> List[bn.MediumLevelILInstruction]:
        """
        This method backtraces all the memory defining instructions of `inst` within its function
        (i.e. `inst.function`).
        """
        return MediumLevelILBackwardSlicer._get_mem_definitions(inst)

    @staticmethod
    @lru_cache(maxsize=None)
    def _get_var_addr_assignments(
        func: bn.MediumLevelILFunction,
    ) -> Dict[bn.Variable, List[bn.MediumLevelILSetVarSsa]]:
        var_addr_assignments = {}
        for bb in func.ssa_form:
            for inst in bb:
                # Match assignments of variable addresses (e.g. `var_x = &var_y`)
                match inst:
                    case bn.MediumLevelILSetVarSsa(
                        src=bn.MediumLevelILAddressOf(src=src)
                    ):
                        var_addr_assignments.setdefault(src, []).append(inst)
        return var_addr_assignments

    def get_var_addr_assignments(
        self,
        inst: bn.MediumLevelILInstruction,
    ) -> Tuple[bn.Variable, List[bn.MediumLevelILSetVarSsa]]:
        """
        This method returns a list of assignment instructions (`bn.MediumLevelILSetVarSSA`) that use
        in their source the same variable as in `inst`. Only instructions within the same function
        as `inst` are considered.
        """
        var_addr_assignments = MediumLevelILBackwardSlicer._get_var_addr_assignments(
            inst.function
        )
        match inst:
            case bn.MediumLevelILAddressOf(src=src):
                return src, var_addr_assignments.get(src, [])
            case bn.MediumLevelILVarAliased(src=src):
                return src.var, var_addr_assignments.get(src.var, [])
        return (None, [])
