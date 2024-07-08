import binaryninja     as bn
from   typing          import List, Set
from   ..common.helper import InstructionHelper
from   ..common.log    import Logger


class MediumLevelILBackwardSlicer:
    """
    This class implements backward slicing for MLIL instructions.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "BackSlicer",
            log: Logger = Logger(),
        ) -> None:
        self._bv = bv
        self._tag = tag
        self._log = log
        self._sliced_insts = {}
        return
    
    def _slice_ssa_var_definition(
            self,
            ssa_var: bn.SSAVariable,
            func: bn.MediumLevelILFunction
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
            return self._slice_backwards(inst)
        # SSAVariable defined in another function
        vars = set()
        func_addr = func.llil[0].address
        for parm_num, parm_var in enumerate(func.source_function.parameter_vars):
            if parm_var != ssa_var.var:
                continue
            for code_ref in self._bv.get_code_refs(func_addr):
                r_addr = code_ref.address
                r_func = code_ref.function
                r_call = r_func.get_low_level_il_at(r_addr).mlil.ssa_form
                r_parm = r_call.params[parm_num]
                vars.update(self._slice_backwards(r_parm))
        return vars

    def _slice_backwards(
            self,
            inst: bn.MediumLevelILInstruction
        ) -> Set[bn.SSAVariable]:
        """
        This method backward slices instruction `inst` based on its type.

        TODO:
        - Review `MediumLevelILVarAliased`
        """
        vars = set()
        info = InstructionHelper.get_inst_info(inst)
        self._log.debug(self._tag, f"{info:s}")
        # Instruction sliced before
        if inst in self._sliced_insts:
            return self._sliced_insts[inst]
        # Slice instruction
        self._sliced_insts[inst] = set()
        # TODO: Support all instructions
        match inst:
            case (bn.MediumLevelILConst() |
                  bn.MediumLevelILConstPtr() |
                  bn.MediumLevelILConstData() |
                  bn.MediumLevelILAddressOf()):
                pass
            case (bn.MediumLevelILVarSsa() |
                  bn.MediumLevelILVarAliased()):
                vars.update(self._slice_ssa_var_definition(inst.src, inst.function))
            case (bn.MediumLevelILLoadSsa()):
                vars.update(self._slice_backwards(inst.src))
            case (bn.MediumLevelILAdd() |
                  bn.MediumLevelILSub() |
                  bn.MediumLevelILLsl() |
                  bn.MediumLevelILLsr()):
                vars.update(self._slice_backwards(inst.left))
                vars.update(self._slice_backwards(inst.right))
            case (bn.MediumLevelILRet()):
                for ret in inst.src:
                    vars.update(self._slice_backwards(ret))
            case (bn.MediumLevelILSetVarSsa()):
                vars.add(inst.dest)
                vars.update(self._slice_backwards(inst.src))
            case (bn.MediumLevelILVarPhi()):
                vars.add(inst.dest)
                for var in inst.src:
                    vars.update(self._slice_ssa_var_definition(var, inst.function))
            case (bn.MediumLevelILCallSsa(dest=dest_inst) |
                  bn.MediumLevelILTailcallSsa(dest=dest_inst)):
                match dest_inst:
                    case bn.MediumLevelILConstPtr(constant=func_addr):
                        func_symb = self._bv.get_symbol_at(func_addr)
                        # Backward slice into functions defined within the binary itself
                        if func_symb.type == bn.SymbolType.FunctionSymbol:
                            func = self._bv.get_function_at(func_addr)
                            if func is not None:
                                for c_inst in func.mlil.ssa_form.instructions:
                                    # TODO: Support all return instructions
                                    match c_inst:
                                        # Backward slice starting from possible return instructions
                                        case (bn.MediumLevelILRet() |
                                              bn.MediumLevelILTailcallSsa()):
                                            vars.update(self._slice_backwards(c_inst))
                vars.update(self._slice_backwards(inst.dest))
                for out in inst.output:
                    vars.add(out)
                for par in inst.params:
                    vars.update(self._slice_backwards(par))
            case _:
                self._log.warn(self._tag, f"{info:s}: Missing handler")
        self._sliced_insts[inst] = vars
        return vars
    
    def includes(
            self,
            inst: bn.MediumLevelILInstruction
        ) -> bool:
        """
        This method returns whether or not instruction `inst` was part of a previously conducted
        backward slice.
        """
        return inst in self._sliced_insts

    def slice_backwards(
            self,
            inst: bn.MediumLevelILInstruction
        ) -> List[Set[bn.SSAVariable]]:
        """
        This method backward slices instruction `inst`.
        """
        return list(inst.ssa_form.traverse(self._slice_backwards))