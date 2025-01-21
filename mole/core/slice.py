from __future__      import annotations
from ..common.help   import FunctionHelper, InstructionHelper
from ..common.log    import Logger
from typing          import Generator, List, Set
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
            is_definition: bool = None,
            call_level: int = None,
            caller_site: bn.MediumLevelILFunction = None
        ) -> None:
        """
        This method adds a node for the given instruction `inst` with the following node attributes:
        The attribute `is_definition` should indicate whether or not instruction `inst` defines a
        SSA variable, i.e. represents an assigning instruction. The attribute `call_level` should
        indicate the `inst`'s level within the call stack. The attribute `caller_site` should
        indicate the function that called `inst.function`.
        """
        super().add_node(
            inst,
            is_definition=is_definition,
            call_level=call_level,
            caller_site=caller_site
        )
        return
    
    def add_edge(
            self,
            inst_from: bn.MediumLevelILInstruction,
            inst_to:   bn.MediumLevelILInstruction
        ) -> None:
        """
        This method adds an edge from `inst_from` to `inst_to`.
        """
        if not inst_from in self.nodes:
            info = InstructionHelper.get_inst_info(inst_from)
            self._log.warn(
                self._tag,
                f"Edge not added to instruction graph due to an inexisting from node ({info:s})"
            )
            return
        if not inst_to in self.nodes:
            info = InstructionHelper.get_inst_info(inst_to)
            self._log.warn(
                self._tag,
                f"Edge not added to instruction graph due to an inexisting to node ({info:s})"
            )
            return
        super().add_edge(inst_from, inst_to)
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
        attribute `call_level` should indicate the `call_site`'s level within the call stack.
        """
        super().add_node(
            call_site,
            call_level=call_level
        )
        return
    
    def add_edge(
            self,
            call_site_from: bn.MediumLevelILFunction,
            call_site_to:   bn.MediumLevelILFunction,
        ) -> None:
        """
        This method adds an edge from `call_site_from` to `call_site_to`.
        """
        if not call_site_from in self.nodes:
            info = FunctionHelper.get_func_info(call_site_from)
            self._log.warn(
                self._tag,
                f"Edge not added to function graph due to an inexisting from node ({info:s})"
            )
            return
        if not call_site_to in self.nodes:
            info = FunctionHelper.get_func_info(call_site_to)
            self._log.warn(
                self._tag,
                f"Edge not added to function graph due to an inexisting to node ({info:s})"
            )
            return
        super().add_edge(call_site_from, call_site_to)
        return
    

class MediumLevelILBackwardSlicer:
    """
    This class implements backward slicing for MLIL instructions.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            max_call_level: int = -1,
            max_vdef_level: int = -1,
            tag: str = "BackSlicer",
            log: Logger = Logger()
        ) -> None:
        """
        This method initializes a backward slicer for for MLIL instructions.
        """
        self._bv: bn.BinaryView = bv
        self._max_call_level: int = max_call_level
        self._max_vdef_level: int = max_vdef_level
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
            caller_site: bn.MediumLevelILFunction = None,
            vdef_level: int = 0
        ) -> None:
        """
        This method first tries to find the instruction defining variable `ssa_var` within `inst`'s
        function. If it is found, slicing proceeds at the identified defining instruction. If no
        defining instruction is found, it is checked whether `ssa_var` belongs to a function
        argument, and if so, defining instructions are searched within the callers (only if we go
        down the call stack). Slicing then proceeds in all found defining instructions.
        """
        # Try finding the definition withing the current function
        inst_def = inst.function.get_ssa_var_definition(ssa_var)
        if inst_def:
            self._inst_graph.add_node(inst, False, call_level, caller_site)
            self._inst_graph.add_node(inst_def, True, call_level, caller_site)
            self._inst_graph.add_edge(inst, inst_def)
            self._slice_backwards(inst_def, call_level, caller_site, vdef_level+1)
            return
        # Try finding the definition in another function if we go down the call stack
        if abs(call_level) > self._max_call_level and self._max_call_level >= 0: return
        caller_site_level = self._call_graph.nodes.get(caller_site, {}).get("call_level", None)
        if caller_site_level is None or call_level < caller_site_level:
            for parm_idx, parm_var in enumerate(inst.function.source_function.parameter_vars):
                if parm_var != ssa_var.var: continue
                for cs in inst.function.source_function.caller_sites:
                    try:
                        inst_caller: bn.MediumLevelILInstruction = cs.mlil.ssa_form
                        parm_caller: bn.MediumLevelILInstruction = inst_caller.params[parm_idx]
                        func_caller: bn.MediumLevelILFunction = parm_caller.function
                        self._log.debug(
                            self._tag,
                            f"[{call_level:+d}] Follow '{ssa_var.name}#{ssa_var.version}' to caller '0x{inst_caller.address:x}: {str(inst_caller):s}'"
                        )
                        self._inst_graph.add_node(inst, False, call_level, caller_site)
                        self._inst_graph.add_node(parm_caller, False, call_level-1, inst.function)
                        self._inst_graph.add_edge(inst, parm_caller)
                        self._call_graph.add_node(inst.function, call_level)
                        self._call_graph.add_node(func_caller, call_level-1)
                        self._call_graph.add_edge(inst.function, func_caller)
                        self._slice_backwards(parm_caller, call_level-1, inst.function, vdef_level+1)
                    except:
                        continue
        return
    
    def _slice_backwards(
            self,
            inst: bn.MediumLevelILInstruction,
            call_level: int = 0,
            caller_site: bn.MediumLevelILFunction = None,
            vdef_level: int = 0
        ) -> None:
        """
        This method backward slices instruction `inst` based on its type.
        """
        info = InstructionHelper.get_inst_info(inst)
        # Instruction sliced before
        if inst in self._inst_visited:
            self._log.debug(
                self._tag,
                f"[{call_level:+d}] {info:s}: Sliced before"
            )
            return
        # Limit number of variable definitions
        if vdef_level > self._max_vdef_level and self._max_vdef_level >= 0:
            self._log.debug(
                self._tag,
                f"[{call_level:+d}] {info:s}: Maximum variable definition level {self._max_vdef_level} reached"
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
                        self._slice_ssa_var_definition(ssa_var, inst, call_level, caller_site, vdef_level)
            case (bn.MediumLevelILVarSsa() |
                  bn.MediumLevelILVarAliased() |
                  bn.MediumLevelILVarAliasedField() |
                  bn.MediumLevelILVarSsaField()):
                self._slice_ssa_var_definition(inst.src, inst, call_level, caller_site, vdef_level)
            case (bn.MediumLevelILNot() |
                  bn.MediumLevelILSx() |
                  bn.MediumLevelILZx() |
                  bn.MediumLevelILLoadSsa() |
                  bn.MediumLevelILLoadStructSsa() |
                  bn.MediumLevelILLowPart() |
                  bn.MediumLevelILFneg() |
                  bn.MediumLevelILFloatConv()):
                self._inst_graph.add_node(inst, False, call_level, caller_site)
                self._inst_graph.add_node(inst.src, None, call_level, caller_site)
                self._inst_graph.add_edge(inst, inst.src)
                self._slice_backwards(inst.src, call_level, caller_site, vdef_level)
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
                self._inst_graph.add_node(inst, False, call_level, caller_site)
                self._inst_graph.add_node(inst.left, None, call_level, caller_site)
                self._inst_graph.add_edge(inst, inst.left)
                self._slice_backwards(inst.left, call_level, caller_site, vdef_level)
                self._inst_graph.add_node(inst, False, call_level, caller_site)
                self._inst_graph.add_node(inst.right, None, call_level, caller_site)
                self._inst_graph.add_edge(inst, inst.right)
                self._slice_backwards(inst.right, call_level, caller_site, vdef_level)
            case (bn.MediumLevelILRet()):
                for ret in inst.src:
                    self._inst_graph.add_node(inst, False, call_level, caller_site)
                    self._inst_graph.add_node(ret, None, call_level, caller_site)
                    self._inst_graph.add_edge(inst, ret)
                    self._slice_backwards(ret, call_level, caller_site, vdef_level)
            case (bn.MediumLevelILSetVarSsa() |
                  bn.MediumLevelILSetVarAliased() |
                  bn.MediumLevelILSetVarAliasedField() |
                  bn.MediumLevelILSetVarSsaField() |
                  bn.MediumLevelILSetVarSplitSsa()):
                self._inst_graph.add_node(inst, True, call_level, caller_site)
                self._inst_graph.add_node(inst.src, None, call_level, caller_site)
                self._inst_graph.add_edge(inst, inst.src)
                self._slice_backwards(inst.src, call_level, caller_site, vdef_level)
            case (bn.MediumLevelILVarPhi()):
                for var in inst.src:
                    self._slice_ssa_var_definition(var, inst, call_level, caller_site, vdef_level)
            case (bn.MediumLevelILCallSsa(dest=dest_inst) |
                  bn.MediumLevelILTailcallSsa(dest=dest_inst)):
                dest_info = InstructionHelper.get_inst_info(dest_inst)
                match dest_inst:
                    case (bn.MediumLevelILConstPtr(constant=func_addr) |
                          bn.MediumLevelILImport(constant=func_addr)):
                        # Backward slice into functions defined within the binary
                        try:
                            func = self._bv.get_function_at(func_addr).mlil.ssa_form
                            for func_inst in func.instructions:
                                match func_inst:
                                    # TODO: Support all return instructions
                                    # Backward slice starting from possible return instructions
                                    case (bn.MediumLevelILRet() |
                                            bn.MediumLevelILTailcallSsa()):
                                        if abs(call_level) <= self._max_call_level or self._max_call_level < 0:
                                            self._inst_graph.add_node(inst, True, call_level, caller_site)
                                            self._inst_graph.add_node(func_inst, None, call_level+1, inst.function)
                                            self._inst_graph.add_edge(inst, func_inst)
                                            self._call_graph.add_node(inst.function, call_level)
                                            self._call_graph.add_node(func, call_level+1)
                                            self._call_graph.add_edge(inst.function, func)
                                            self._slice_backwards(func_inst, call_level+1, inst.function, vdef_level)
                                        else:
                                            self._log.debug(
                                                self._tag,
                                                f"[{call_level:+d}] {dest_info:s}: Maximum function depth {self._max_call_level:d} reached"
                                            )
                        except:
                            pass
                    case _:
                        self._log.warn(self._tag, f"[{call_level:+d}] {dest_info:s}: Missing handler")
                # Backward slice function parameters
                for par in inst.params:
                    self._inst_graph.add_node(inst, True, call_level, caller_site)
                    self._inst_graph.add_node(par, None, call_level, caller_site)
                    self._inst_graph.add_edge(inst, par)
                    self._slice_backwards(par, call_level, caller_site, vdef_level)
            case (bn.MediumLevelILSyscallSsa()):
                for par in inst.params:
                    self._inst_graph.add_node(inst, False, call_level, caller_site)
                    self._inst_graph.add_node(par, None, call_level, caller_site)
                    self._inst_graph.add_edge(inst, par)
                    self._slice_backwards(par, call_level, caller_site, vdef_level)
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
        ) -> Generator[List[bn.MediumLevelILInstruction], None, None]:
        """
        This method finds paths from `snk_inst` to `src_inst`.
        """
        try:
            yield from nx.all_simple_paths(self._inst_graph, snk_inst, src_inst)
        except (nx.NodeNotFound, nx.NetworkXNoPath):
            pass
        yield from ()