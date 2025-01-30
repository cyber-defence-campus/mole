from __future__      import annotations
from ..common.help   import FunctionHelper, InstructionHelper
from ..common.log    import Logger
from typing          import Generator, List, Set, Tuple
import binaryninja as bn
import networkx    as nx


class MediumLevelILInstructionGraph(nx.DiGraph):
    """
    This class represents a directed graph that stores the `MediumLevelILInstruction` of a slice.
    """

    def __init__(
            self,
            tag: str = "InstructionGraph",
            log: Logger = Logger()
        ) -> None:
        """
        This method initializes an empty graph.
        """
        self._tag = tag
        self._log = log
        return super().__init__()
    
    def add_node(
            self,
            inst: bn.MediumLevelILInstruction,
            call_level: int = None,
            caller_site: bn.MediumLevelILFunction = None
        ) -> None:
        """
        This method adds a node for the given instruction `inst` with the following node attributes:
        The attribute `call_level` is expected to be `inst`'s level within the call stack. The
        attribute `caller_site` is expected to be the function that called `inst.function`.
        """
        super().add_node(
            inst,
            call_level=call_level,
            caller_site=caller_site
        )
        return
    
    def add_edge(
            self,
            from_inst: bn.MediumLevelILInstruction,
            to_inst:   bn.MediumLevelILInstruction
        ) -> None:
        """
        This method adds an edge from `from_inst` to `to_inst`.
        """
        if not from_inst in self.nodes:
            info = InstructionHelper.get_inst_info(from_inst)
            self._log.warn(
                self._tag,
                f"Edge not added to instruction graph due to an inexisting from node ({info:s})"
            )
            return
        if not to_inst in self.nodes:
            info = InstructionHelper.get_inst_info(to_inst)
            self._log.warn(
                self._tag,
                f"Edge not added to instruction graph due to an inexisting to node ({info:s})"
            )
            return
        super().add_edge(from_inst, to_inst)
        return


class MediumLevelILFunctionGraph(nx.DiGraph):
    """
    This class represents a directed graph that stores the `MediumLevelILFunction` call graph of a
    slice.
    """

    def __init__(
            self,
            tag: str = "FunctionGraph",
            log: Logger = Logger()
        ) -> None:
        """
        This method initializes an empty graph.
        """
        self._tag = tag
        self._log = log
        return super().__init__()
    
    def add_node(
            self,
            call_site: bn.MediumLevelILFunction,
            call_level: int = None
        ) -> None:
        """
        This method adds a node for the given `call_site`, with the following node attribute: The
        attribute `call_level` is expected to be the `call_site`'s level within the call stack.
        """
        super().add_node(
            call_site,
            call_level=call_level
        )
        return
    
    def add_edge(
            self,
            from_call_site: bn.MediumLevelILFunction,
            to_call_site:   bn.MediumLevelILFunction,
        ) -> None:
        """
        This method adds an edge from `from_call_site` to `to_call_site`.
        """
        if not from_call_site in self.nodes:
            info = FunctionHelper.get_func_info(from_call_site)
            self._log.warn(
                self._tag,
                f"Edge not added to function graph due to an inexisting from node ({info:s})"
            )
            return
        if not to_call_site in self.nodes:
            info = FunctionHelper.get_func_info(to_call_site)
            self._log.warn(
                self._tag,
                f"Edge not added to function graph due to an inexisting to node ({info:s})"
            )
            return
        super().add_edge(from_call_site, to_call_site)
        return
    

class MediumLevelILBackwardSlicer:
    """
    This class implements backward slicing for MLIL instructions.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            max_call_level: int = -1,
            tag: str = "BackSlicer",
            log: Logger = Logger()
        ) -> None:
        """
        This method initializes a backward slicer for for MLIL instructions.
        """
        self._bv: bn.BinaryView = bv
        self._max_call_level: int = max_call_level
        self._tag: str = tag
        self._log: Logger = log
        self._inst_visited: Set[bn.MediumLevelILInstruction] = set()
        self._inst_graph: MediumLevelILInstructionGraph = MediumLevelILInstructionGraph(tag, log)
        self._call_graph: MediumLevelILFunctionGraph = MediumLevelILFunctionGraph(tag, log)
        return
    
    def _slice_ssa_var_definition(
            self,
            ssa_var: bn.SSAVariable,
            inst: bn.MediumLevelILInstruction,
            call_level: int = 0,
            caller_site: bn.MediumLevelILFunction = None
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
            self._inst_graph.add_node(inst, call_level, caller_site)
            self._inst_graph.add_node(inst_def, call_level, caller_site)
            self._inst_graph.add_edge(inst, inst_def)
            self._slice_backwards(inst_def, call_level, caller_site)
            return
        # Try finding the definition in another function
        if self._max_call_level >= 0 and abs(call_level) > self._max_call_level: return
        caller_level = self._call_graph.nodes.get(caller_site, {}).get("call_level", None)
        for parm_idx, parm_var in enumerate(inst.function.source_function.parameter_vars):
            if parm_var != ssa_var.var: continue
            for cs in inst.function.source_function.caller_sites:
                try:
                    cs_inst = cs.mlil.ssa_form
                    cs_parm = cs_inst.params[parm_idx]
                    # Visit specific caller site if we go up the call stack (all caller sites otherwise)
                    if not caller_level is None and caller_level <= call_level:
                        if caller_site != cs_inst.function:
                            continue
                    cs_info = InstructionHelper.get_inst_info(cs_inst, False)
                    self._log.debug(
                        self._tag,
                        f"Follow parameter '{ssa_var.name}#{ssa_var.version}' to caller '{cs_info:s}'"
                    )
                    self._inst_graph.add_node(inst, call_level, caller_site)
                    self._inst_graph.add_node(cs_parm, call_level-1, inst.function)
                    self._inst_graph.add_edge(inst, cs_parm)
                    self._call_graph.add_node(cs_inst.function, call_level-1)
                    self._call_graph.add_node(inst.function, call_level)
                    self._call_graph.add_edge(cs_inst.function, inst.function)
                    self._slice_backwards(cs_parm, call_level-1, inst.function)
                except:
                    continue
        return
    
    def _slice_backwards(
            self,
            inst: bn.MediumLevelILInstruction,
            call_level: int = 0,
            caller_site: bn.MediumLevelILFunction = None
        ) -> None:
        """
        This method backward slices instruction `inst` based on its type. Parameter `call_level` is
        expected to be `inst`'s level within the call stack. Parameter `caller_site` is expected to
        be the function that called `inst.function`.
        """
        info = InstructionHelper.get_inst_info(inst)
        # Maxium call level
        if self._max_call_level >= 0 and abs(call_level) > self._max_call_level:
            self._log.warn(
                self._tag,
                f"Maximum call level {self._max_call_level:d} reached"
            )
            return
        # Instruction sliced before
        if inst in self._inst_visited:
            self._log.debug(
                self._tag,
                f"[{call_level:+d}] {info:s}: Sliced before"
            )
            return
        # Slice instruction
        self._inst_visited.add(inst)
        self._log.debug(self._tag, f"[{call_level:+d}] {info:s}")
        match inst:
            # TODO: Support all instructions
            case (bn.MediumLevelILConst() |
                  bn.MediumLevelILConstData() |
                  bn.MediumLevelILConstPtr() |
                  bn.MediumLevelILFloatConst() |
                  bn.MediumLevelILImport()):
                pass
            case (bn.MediumLevelILAddressOf()):
                # Backward slice at all possible variable definitions
                for ssa_var in inst.function.ssa_vars:
                    if ssa_var.var == inst.src:
                        self._slice_ssa_var_definition(ssa_var, inst, call_level, caller_site)
            case (bn.MediumLevelILVarSsa() |
                  bn.MediumLevelILVarAliased() |
                  bn.MediumLevelILVarAliasedField() |
                  bn.MediumLevelILVarSsaField()):
                self._slice_ssa_var_definition(inst.src, inst, call_level, caller_site)
            case (bn.MediumLevelILNot() |
                  bn.MediumLevelILSx() |
                  bn.MediumLevelILZx() |
                  bn.MediumLevelILLoadSsa() |
                  bn.MediumLevelILLoadStructSsa() |
                  bn.MediumLevelILLowPart() |
                  bn.MediumLevelILFneg() |
                  bn.MediumLevelILFloatConv()):
                self._inst_graph.add_node(inst, call_level, caller_site)
                self._inst_graph.add_node(inst.src, call_level, caller_site)
                self._inst_graph.add_edge(inst, inst.src)
                self._slice_backwards(inst.src, call_level, caller_site)
            case (bn.MediumLevelILAdd() |
                  bn.MediumLevelILAdc() |
                  bn.MediumLevelILSub() |
                  bn.MediumLevelILSbb() |
                  bn.MediumLevelILAnd() |
                  bn.MediumLevelILOr() |
                  bn.MediumLevelILXor() |
                  bn.MediumLevelILLsl() |
                  bn.MediumLevelILLsr() |
                  bn.MediumLevelILAsr() |
                  bn.MediumLevelILRor() |
                  bn.MediumLevelILMul() |
                  bn.MediumLevelILMuluDp() |
                  bn.MediumLevelILMulsDp() |
                  bn.MediumLevelILDivu() |
                  bn.MediumLevelILDivuDp() |
                  bn.MediumLevelILDivs() |
                  bn.MediumLevelILDivsDp() |
                  bn.MediumLevelILFadd() |
                  bn.MediumLevelILFsub() |
                  bn.MediumLevelILFmul() |
                  bn.MediumLevelILFdiv()):
                self._inst_graph.add_node(inst, call_level, caller_site)
                self._inst_graph.add_node(inst.left, call_level, caller_site)
                self._inst_graph.add_edge(inst, inst.left)
                self._slice_backwards(inst.left, call_level, caller_site)
                self._inst_graph.add_node(inst, call_level, caller_site)
                self._inst_graph.add_node(inst.right, call_level, caller_site)
                self._inst_graph.add_edge(inst, inst.right)
                self._slice_backwards(inst.right, call_level, caller_site)
            case (bn.MediumLevelILRet()):
                for ret in inst.src:
                    self._inst_graph.add_node(inst, call_level, caller_site)
                    self._inst_graph.add_node(ret, call_level, caller_site)
                    self._inst_graph.add_edge(inst, ret)
                    self._slice_backwards(ret, call_level, caller_site)
            case (bn.MediumLevelILSetVarSsa() |
                  bn.MediumLevelILSetVarAliased() |
                  bn.MediumLevelILSetVarAliasedField() |
                  bn.MediumLevelILSetVarSsaField() |
                  bn.MediumLevelILSetVarSplitSsa()):
                self._inst_graph.add_node(inst, call_level, caller_site)
                self._inst_graph.add_node(inst.src, call_level, caller_site)
                self._inst_graph.add_edge(inst, inst.src)
                self._slice_backwards(inst.src, call_level, caller_site)
            case (bn.MediumLevelILVarPhi()):
                for var in inst.src:
                    self._slice_ssa_var_definition(var, inst, call_level, caller_site)
            case (bn.MediumLevelILCallSsa(dest=dest_inst) |
                  bn.MediumLevelILTailcallSsa(dest=dest_inst)):
                call_info = InstructionHelper.get_inst_info(inst, False)
                dest_info = InstructionHelper.get_inst_info(dest_inst)
                match dest_inst:
                    # Direct function calls
                    case (bn.MediumLevelILConstPtr(constant=func_addr) |
                          bn.MediumLevelILImport(constant=func_addr)):
                        try:
                            func = self._bv.get_function_at(func_addr).mlil.ssa_form
                            symb = func.source_function.symbol
                            for func_inst in func.instructions:
                                # TODO: Support all return instructions
                                match func_inst:
                                    case (bn.MediumLevelILRet() |
                                          bn.MediumLevelILTailcallSsa()):
                                        # Function
                                        if symb.type == bn.SymbolType.FunctionSymbol:
                                            ret_info = InstructionHelper.get_inst_info(func_inst, False)
                                            self._log.debug(
                                                self._tag,
                                                f"Follow return instruction '{ret_info:s}' of function '{call_info:s}'"
                                            )
                                            self._inst_graph.add_node(inst, call_level, caller_site)
                                            self._inst_graph.add_node(func_inst, call_level+1, inst.function)
                                            self._inst_graph.add_edge(inst, func_inst)
                                            self._call_graph.add_node(inst.function, call_level)
                                            self._call_graph.add_node(func, call_level+1)
                                            self._call_graph.add_edge(inst.function, func)
                                            self._slice_backwards(func_inst, call_level+1, inst.function)
                                        # Imported function
                                        elif symb.type == bn.SymbolType.ImportedFunctionSymbol:
                                            for par in inst.params:
                                                par_info = InstructionHelper.get_inst_info(par, False)
                                                self._log.debug(
                                                    self._tag,
                                                    f"Follow parameter '{par_info:s}' of imported function '{call_info:s}'"
                                                )
                                                self._inst_graph.add_node(inst, call_level, caller_site)
                                                self._inst_graph.add_node(par, call_level, caller_site)
                                                self._inst_graph.add_edge(inst, par)
                                                self._slice_backwards(par, call_level, caller_site)
                                        else:
                                            self._log.warn(self._tag, f"Function '{call_info:s}' has an unexpected type '{str(symb.type):s}'")
                        except:
                            # Function not found within the binary
                            pass
                    # Indirect function calls
                    case (bn.MediumLevelILVarSsa()):
                        for par in inst.params:
                            par_info = InstructionHelper.get_inst_info(par, False)
                            self._log.debug(
                                self._tag,
                                f"Follow parameter '{par_info:s}' of indirect function call '{call_info:s}'"
                            )
                            self._inst_graph.add_node(inst, call_level, caller_site)
                            self._inst_graph.add_node(par, call_level, caller_site)
                            self._inst_graph.add_edge(inst, par)
                            self._slice_backwards(par, call_level, caller_site)
                    case _:
                        self._log.warn(self._tag, f"[{call_level:+d}] {dest_info:s}: Missing handler")
            case (bn.MediumLevelILSyscallSsa()):
                for par in inst.params:
                    self._inst_graph.add_node(inst, call_level, caller_site)
                    self._inst_graph.add_node(par, call_level, caller_site)
                    self._inst_graph.add_edge(inst, par)
                    self._slice_backwards(par, call_level, caller_site)
            case _:
                self._log.warn(self._tag, f"[{call_level:+d}] {info:s}: Missing handler")
        return
    
    def slice_backwards(
            self,
            inst: bn.MediumLevelILInstruction
        ) -> None:
        """
        This method backward slices the instruction `inst`.
        """
        for _ in inst.ssa_form.traverse(self._slice_backwards): pass
        return
    
    def get_insts(self) -> Generator[bn.MediumLevelILInstruction]:
        """
        This method returns all sliced instructions.
        """
        return self._inst_graph.nodes()
    
    def find_paths(
            self,
            snk_inst: bn.MediumLevelILInstruction,
            src_inst: bn.MediumLevelILInstruction
        ) -> List[Tuple[List[bn.MediumLevelILInstruction], MediumLevelILFunctionGraph]]:
        """
        This method finds all simple paths from `snk_inst` to `src_inst`. For each found path, the
        following is returned: First, a list of instructions belonging to the path. And second, a
        function call graph, where nodes and edges belonging to the path, have an attribute
        `in_path` set to `True`.
        """
        paths = []
        # Find all simple paths
        try:
            simple_paths: List[List[bn.MediumLevelILInstruction]] = list(
                nx.all_simple_paths(self._inst_graph, snk_inst, src_inst)
            )
        except (nx.NodeNotFound, nx.NetworkXNoPath):
            return paths
        # Process all simple paths
        for simple_path in simple_paths:
            # Copy the call graph
            call_graph = self._call_graph.copy()
            # Add attribute `in_path = False` to all nodes
            for node in call_graph.nodes():
                call_graph.nodes[node]["in_path"] = False
            # Change attribute to `in_path = True` where functions are part of the path
            for inst in simple_path:
                func = inst.function
                if func in call_graph:
                    call_graph.nodes[func]["in_path"] = True
            # Add attribute `ìn_path` to edges where both nodes have `in_path = True`
            for node_from, node_to in call_graph.edges():
                call_graph[node_from][node_to]["in_path"] = (
                    call_graph.nodes[node_from]["in_path"] and
                    call_graph.nodes[node_to]["in_path"]
                )
            # Add path and call graph
            paths.append((simple_path, call_graph))
        return paths