from __future__      import annotations
from ..common.help import InstructionHelper
from ..common.log    import Logger
from typing          import Generator, List
import binaryninja as bn
import networkx    as nx


# class MediumLevelILGraph(nx.DiGraph):
#     """
#     TODO:
#     - Do something like this if we need each node (`MediumLevelILInstruction`) to have associated
#       parameters (e.g. `func_depth`,`vdef_depth` or `ssa_vars`)
#     """

#     def __init__(self) -> None:
#         super().__init__()
#         return
    
#     def add_node(
#             self,
#             inst: bn.MediumLevelILInstruction,
#             ssa_vars: Set[bn.SSAVariable] = set()
#         ) -> None:
#         """
#         """
#         super().add_node(inst, ssa_vars=ssa_vars)
#         return
    
#     def get_ssa_vars(
#             self,
#             inst: bn.MediumLevelILInstruction
#         ) -> Set[bn.SSAVariable]:
#         """
#         """
#         return self.nodes[inst]["ssa_vars"]
    
#     def update_ssa_vars(
#             self,
#             inst: bn.MediumLevelILInstruction,
#             ssa_vars: Set[bn.SSAVariable]
#         ) -> None:
#         """
#         """
#         self.get_ssa_vars(inst).update(ssa_vars)
#         return
    
class MediumLevelILBackwardSlicer:
    """
    This class implements backward slicing for MLIL instructions.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            max_func_depth: int = -1,
            max_vdef_depth: int = -1,
            tag: str = "BackSlicer",
            log: Logger = Logger()
        ) -> None:
        self._bv: bn.BinaryView = bv
        self._max_func_depth: int = max_func_depth
        self._max_vdef_depth: int = max_vdef_depth
        self._tag: str = tag
        self._log: Logger = log
        self._sliced_insts: nx.DiGraph = nx.DiGraph()
        return
    
    def _slice_ssa_var_definition(
            self,
            ssa_var: bn.SSAVariable,
            inst: bn.MediumLevelILInstruction,
            func_depth: int = 0,
            vdef_depth: int = 0
        ) -> None:
        """
        This method determines and slices the instruction defining variable `ssa_var` of instruction
        `inst`. The definition is searched within `inst`'s function first. If not found, it checks
        whether `ssa_var` corresponds to a function argument and if so, searches its definition in
        callers.
        """
        # Defined withing the same function
        def_inst = inst.function.get_ssa_var_definition(ssa_var)
        if def_inst:
            self._slice_backwards(def_inst, func_depth, vdef_depth+1)
            self._sliced_insts.add_edge(inst, def_inst)
            return
        # Defined in another function
        for par_idx, par_var in enumerate(inst.function.source_function.parameter_vars):
            if par_var != ssa_var.var: continue
            for caller_site in inst.function.source_function.caller_sites:
                try:
                    caller_inst = caller_site.mlil.ssa_form
                    caller_parm: bn.MediumLevelILInstruction = caller_inst.params[par_idx]
                    self._log.debug(
                        self._tag,
                        f"Follow '{ssa_var.name}#{ssa_var.version}' to caller '0x{caller_inst.address:x} {str(caller_inst):s}'"
                    )
                    self._slice_backwards(caller_parm, func_depth-1, vdef_depth+1)
                    self._sliced_insts.add_edge(inst, caller_parm)
                except:
                    continue
        return
    
    def _slice_backwards(
            self,
            inst: bn.MediumLevelILInstruction,
            func_depth: int = 0,
            vdef_depth: int = 0
        ) -> None:
        """
        This method backward slices instruction `inst` based on its type.
        """
        info = InstructionHelper.get_inst_info(inst)
        # Instruction sliced before
        if inst in self._sliced_insts:
            self._log.debug(
                self._tag,
                f"[{func_depth:+d}] {info:s}: Sliced before"
            )
            return
        if vdef_depth > self._max_vdef_depth and self._max_vdef_depth >= 0:
            self._log.debug(
                self._tag,
                f"[{func_depth:+d}] {info:s}: Maximum variable definition depth {self._max_vdef_depth} reached"
            )
            return
        self._log.debug(self._tag, f"[{func_depth:+d}] {info:s}")
        # Slice instruction
        self._sliced_insts.add_node(inst)
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
                        self._slice_ssa_var_definition(ssa_var, inst, func_depth, vdef_depth)
            case (bn.MediumLevelILVarSsa() |
                  bn.MediumLevelILVarAliased() |
                  bn.MediumLevelILVarAliasedField() |
                  bn.MediumLevelILVarSsaField()):
                self._slice_ssa_var_definition(inst.src, inst, func_depth, vdef_depth)
            case (bn.MediumLevelILNot() |
                  bn.MediumLevelILSx() |
                  bn.MediumLevelILZx() |
                  bn.MediumLevelILLoadSsa() |
                  bn.MediumLevelILLoadStructSsa() |
                  bn.MediumLevelILLowPart() |
                  bn.MediumLevelILFneg() |
                  bn.MediumLevelILFloatConv()):
                self._slice_backwards(inst.src, func_depth, vdef_depth)
                self._sliced_insts.add_edge(inst, inst.src)
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
                self._slice_backwards(inst.left, func_depth, vdef_depth)
                self._sliced_insts.add_edge(inst, inst.left)
                self._slice_backwards(inst.right, func_depth, vdef_depth)
                self._sliced_insts.add_edge(inst, inst.right)
            case (bn.MediumLevelILRet()):
                for ret in inst.src:
                    self._slice_backwards(ret, func_depth, vdef_depth)
                    self._sliced_insts.add_edge(inst, ret)
            case (bn.MediumLevelILSetVarSsa() |
                  bn.MediumLevelILSetVarAliased() |
                  bn.MediumLevelILSetVarAliasedField() |
                  bn.MediumLevelILSetVarSsaField()):
                # TODO: If we do not use `vars`, merge with above case
                self._slice_backwards(inst.src, func_depth, vdef_depth)
                self._sliced_insts.add_edge(inst, inst.src)
            case (bn.MediumLevelILSetVarSplitSsa()):
                # TODO: If we do not use `vars`, merge with above case
                self._slice_backwards(inst.src, func_depth, vdef_depth)
                self._sliced_insts.add_edge(inst, inst.src)
            case (bn.MediumLevelILVarPhi()):
                for var in inst.src:
                    self._slice_ssa_var_definition(var, inst, func_depth, vdef_depth)
            case (bn.MediumLevelILCallSsa(dest=dest_inst) |
                  bn.MediumLevelILTailcallSsa(dest=dest_inst)):
                dest_info = InstructionHelper.get_inst_info(dest_inst)
                match dest_inst:
                    case (bn.MediumLevelILConstPtr(constant=func_addr) |
                          bn.MediumLevelILImport(constant=func_addr)):
                        # TODO: Backward slice into functions defined within the binary
                        try:
                            func = self._bv.get_function_at(func_addr).mlil.ssa_form
                            for func_inst in func.instructions:
                                match func_inst:
                                    # TODO: Support all return instructions
                                    # Backward slice starting from possible return instructions
                                    case (bn.MediumLevelILRet() |
                                            bn.MediumLevelILTailcallSsa()):
                                        if func_depth < self._max_func_depth or self._max_func_depth < 0:
                                            self._slice_backwards(func_inst, func_depth+1, vdef_depth)
                                            self._sliced_insts.add_edge(inst, func_inst)
                                        else:
                                            self._log.debug(
                                                self._tag,
                                                f"[{func_depth:+d}] {dest_info:s}: Maximum function depth {self._max_func_depth:d} reached"
                                            )
                        except:
                            pass
                    case _:
                        self._log.warn(self._tag, f"[{func_depth:+d}] {dest_info:s}: Missing handler")
                for par in inst.params:
                    self._slice_backwards(par, func_depth, vdef_depth)
                    self._sliced_insts.add_edge(inst, par)
            case (bn.MediumLevelILSyscallSsa()):
                for par in inst.params:
                    self._slice_backwards(par, func_depth, vdef_depth)
                    self._sliced_insts.add_edge(inst, par)
            case _:
                self._log.warn(self._tag, f"[{func_depth:+d}] {info:s}: Missing handler")
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
        return self._sliced_insts.nodes()
    
    def find_paths(
            self,
            snk_inst: bn.MediumLevelILInstruction,
            src_inst: bn.MediumLevelILInstruction
        ) -> Generator[List[bn.MediumLevelILInstruction], None, None]:
        """
        This method finds paths from `snk_inst` to `src_inst`.
        """
        try:
            yield from nx.all_simple_paths(self._sliced_insts, snk_inst, src_inst)
        except (nx.NodeNotFound, nx.NetworkXNoPath):
            pass
        yield from ()