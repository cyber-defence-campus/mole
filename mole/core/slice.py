from __future__      import annotations
from ..common.help import InstructionHelper
from ..common.log    import Logger
from typing          import Dict, Set
import binaryninja as bn


class MediumLevelILBackwardSlicer:
    """
    This class implements backward slicing for MLIL instructions.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            max_func_depth: int,
            tag: str = "BackSlicer",
            log: Logger = Logger()
        ) -> None:
        self._bv: bn.BinaryView = bv
        self._tag: str = tag
        self._log: Logger = log
        self._max_func_depth: int = max_func_depth
        self._sliced_insts: Dict[bn.MediumLevelILInstruction, Set[bn.SSAVariable]] = {}
        self._log.info(self._tag, f"Slicer initialized with max_func_depth={max_func_depth}")
        return
    
    def _slice_ssa_var_definition(
            self,
            ssa_var: bn.SSAVariable,
            func: bn.MediumLevelILFunction,
            func_depth: int = 0
        ) -> Set[bn.SSAVariable]:
        """
        This method determines the instruction defining variable `ssa_var` within the function
        `func` and if found, backward slices it. If no defining instruction is found within `func`,
        it is checked whether the variable `ssa_var` corresponds to a function argument. If so,
        backward slicing continues at the calling instruction.
        """
        # SSAVariable defined within the function
        inst = func.get_ssa_var_definition(ssa_var)
        if inst is not None:
            return self._slice_backwards(inst, func_depth)
        # SSAVariable defined in another function
        vars: set[bn.SSAVariable] = set()
        func_addr = func.llil[0].address
        for parm_num, parm_var in enumerate(func.source_function.parameter_vars):
            if parm_var != ssa_var.var:
                continue
            for code_ref in self._bv.get_code_refs(func_addr):
                try:
                    r_addr = code_ref.address
                    r_func = code_ref.function
                    r_call = r_func.get_low_level_il_at(r_addr).mlil.ssa_form
                    r_parm = r_call.params[parm_num]
                except:
                    continue
                vars.update(self._slice_backwards(r_parm, func_depth))
        return vars

    def _slice_backwards(
            self,
            inst: bn.MediumLevelILInstruction,
            func_depth: int = 0
        ) -> Set[bn.SSAVariable]:
        """
        This method backward slices instruction `inst` based on its type.
        """
        vars: set[bn.SSAVariable] = set()
        info = InstructionHelper.get_inst_info(inst)
        #self._log.debug(self._tag, f"{info:s}")
        func = self._bv.get_functions_containing(inst.instr.address)[0]
        self._log.info(self._tag, f"[{func.name:<20s} | {func_depth:<2d}] {info:s}")
        # Instruction sliced before
        if inst in self._sliced_insts:
            return self._sliced_insts[inst]
        # Slice instruction
        self._sliced_insts[inst] = set()
        # TODO: Support all instructions
        match inst:
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
                        vars.update(self._slice_ssa_var_definition(ssa_var, inst.function, func_depth))
            case (bn.MediumLevelILVarSsa() |
                  bn.MediumLevelILVarAliased() |
                  bn.MediumLevelILVarAliasedField() |
                  bn.MediumLevelILVarSsaField()):
                vars.update(self._slice_ssa_var_definition(inst.src, inst.function, func_depth))
            case (bn.MediumLevelILNot() |
                  bn.MediumLevelILSx() |
                  bn.MediumLevelILZx() |
                  bn.MediumLevelILLoadSsa() |
                  bn.MediumLevelILLoadStructSsa() |
                  bn.MediumLevelILLowPart() |
                  bn.MediumLevelILFneg() |
                  bn.MediumLevelILFloatConv()):
                vars.update(self._slice_backwards(inst.src, func_depth))
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
                vars.update(self._slice_backwards(inst.left, func_depth))
                vars.update(self._slice_backwards(inst.right, func_depth))
            case (bn.MediumLevelILRet()):
                for ret in inst.src:
                    vars.update(self._slice_backwards(ret, func_depth))
            case (bn.MediumLevelILSetVarSsa() |
                  bn.MediumLevelILSetVarAliased() |
                  bn.MediumLevelILSetVarAliasedField() |
                  bn.MediumLevelILSetVarSsaField()):
                vars.add(inst.dest)
                vars.update(self._slice_backwards(inst.src, func_depth))
            case (bn.MediumLevelILSetVarSplitSsa()):
                vars.add(inst.high)
                vars.add(inst.low)
                vars.update(self._slice_backwards(inst.src, func_depth))
            case (bn.MediumLevelILVarPhi()):
                vars.add(inst.dest)
                for var in inst.src:
                    vars.update(self._slice_ssa_var_definition(var, inst.function, func_depth))
            case (bn.MediumLevelILCallSsa(dest=dest_inst)) | bn.MediumLevelILTailcallSsa(dest=dest_inst):
                match dest_inst:
                    case (bn.MediumLevelILConstPtr(constant=func_addr) |
                         bn.MediumLevelILImport(constant=func_addr)):
                        # TODO: Backward slice into functions defined within the binary
                        func = self._bv.get_function_at(func_addr)
                        if func is not None:
                            try:
                                func = func.mlil.ssa_form
                            except bn.ILException as ilex:
                                self._log.warn(self._tag, f"{info:s}: Missing MLIL {str(ilex)}")
                                func = None
                            if func is not None:
                                for c_inst in func.instructions:
                                    # TODO: Support all return instructions
                                    match c_inst:
                                        # Backward slice starting from possible return instructions
                                        case (bn.MediumLevelILRet() |
                                            bn.MediumLevelILTailcallSsa()):
                                            if func_depth < self._max_func_depth:
                                                vars.update(self._slice_backwards(c_inst, func_depth+1))
                                            else:
                                                self._log.warn(self._tag, f"{info:s}: Maximum function depth {func_depth} reached")
                                        case _:
                                            self._log.warn(self._tag, f"{info:s}: Missing return instruction")
                        else:
                            self._log.warn(self._tag, f"{info:s}: Missing function @ {hex(func_addr)}")
                    case _:
                        self._log.warn(self._tag, f"{info:s}: {dest_inst.__class__.__name__:s} not supported")
                vars.update(self._slice_backwards(inst.dest, func_depth))
                for out in inst.output:
                    vars.add(out)
                for par in inst.params:
                    vars.update(self._slice_backwards(par, func_depth))
            case (bn.MediumLevelILSyscallSsa()):
                for out in inst.output:
                    vars.add(out)
                for par in inst.params:
                    vars.update(self._slice_backwards(par, func_depth))
            case _:
                self._log.warn(self._tag, f"{info:s}: Missing handler")
        
        self._sliced_insts[inst] = vars
        self._log.debug(self._tag, f"--- [{len(vars):>3d}] {','.join([v.name for v in vars])}")
        return vars

    def slice_backwards(
            self,
            inst: bn.MediumLevelILInstruction
        ) -> Dict[bn.MediumLevelILInstruction, Set[bn.SSAVariable]]:
        """
        This method backward slices the instruction `inst`. It returns the slice as a dictionary,
        where keys correspond to the sliced instructions (1st key == 1st instruction in the backward
        slice), and values to sets of corresponding static single assignment variables.
        """
        for _ in inst.ssa_form.traverse(self._slice_backwards): pass
        return self._sliced_insts
    
    def includes(
            self,
            inst: bn.MediumLevelILInstruction
        ) -> bool:
        """
        This method returns whether or not instruction `inst` was part of a previously conducted
        backward slice.
        """
        return inst in self._sliced_insts