from binaryninja import (BinaryView, MediumLevelILInstruction, MediumLevelILOperation,
                         MediumLevelILVarSsa, RegisterValueType)
from typing      import List
from z3          import Solver, BitVec
from .common.log import Logger


# class ByteSwapSource:
#     """
#     """
    
#     def __init__(self, mlil_var_ssa: MediumLevelILVarSsa) -> None:
#         super().__init__()
#         self._mlil_var_ssa = mlil_var_ssa
#         return
    
#     def test(self) -> None:
#         var_def = self._mlil_var_ssa.function.get_ssa_var_definition(self._mlil_var_ssa.src)
#         return

class MediumLevelILInstructionVisitor:
    """
    Base class for visiting MLIL instructions.
    """

    def visit(self, inst: MediumLevelILInstruction) -> BitVec:
        """
        Call visit function based on operation name.
        """
        o_name = inst.operation.name
        f_name = f"visit_{o_name:s}"
        if hasattr(self, f_name):
            return getattr(self, f_name)(inst)
        return None


class MediumLevelILVarSsaModeler(MediumLevelILInstructionVisitor):
    """
    """

    def __init__(self, var: MediumLevelILVarSsa) -> None:
        self._var = var
        self._solver = Solver()
        self._to_visit = list()
        return
    
    def model(self) -> None:
        """
        """
        # Add instruction that defines the variable
        var_def = self._var.function.get_ssa_var_definition(self._var.src)
        self._to_visit.append(var_def)

        # Visit instructions
        while self._to_visit:
            inst = self._to_visit.pop()
            if inst is not None:
                self.visit(self._var.function[inst])
        return



class SymbolSink:
    """
    """

    def __init__(self, bv: BinaryView, symbol_names: List[str]) -> None:
        self._bv = bv
        self._symbol_names = symbol_names
        return
    
    def get_mlil_insts(self) -> List[MediumLevelILInstruction]:
        """
        Get MLIL instructions of all symbols' code references.
        """
        mlil_insts = [] 
        for symbol_name in self._symbol_names:
            for symbol in self._bv.symbols.get(symbol_name, []):
                for code_ref in self._bv.get_code_refs(symbol.address):
                    inst = code_ref.function.get_low_level_il_at(code_ref.address).medium_level_il
                    if inst is None: continue
                    mlil_insts.append(inst)
        return mlil_insts


class LibcMemcpy:
    """
    """

    def __init__(self, bv: BinaryView) -> None:
        self._bv = bv
        return
    
    def find_controllable_param_size(self) -> None:
        """
        """
        Logger.info("LibcMemcpy", f"Start finding calls with controllable `size` parameter...")
        sinks = SymbolSink(self._bv, ["memcpy", "__builtin_memcpy"]).get_mlil_insts()
        for sink in sinks:
            # Skip invalid `memcpy` calls
            mlil_call_ssa = sink.ssa_form
            if mlil_call_ssa is None:
                Logger.warn("LibcMemcpy", f"0x{sink.address:x} (Ignore - no SSA form)")
                continue
            if mlil_call_ssa.operation != MediumLevelILOperation.MLIL_CALL_SSA:
                Logger.warn("LibcMemcpy", f"0x{sink.address:x} (Ignore - not a call instruction)")
                continue
            if len(mlil_call_ssa.params) != 3:
                Logger.warn("LibcMemcpy", f"0x{sink.address:x} (Ignore - invalid number of parameters)")
                continue
            # Ignore `memcpy` calls with a constant `size` parameter
            size_param = mlil_call_ssa.params[2]
            if size_param.operation != MediumLevelILOperation.MLIL_VAR_SSA:
                Logger.debug("LibcMemcpy", f"0x{sink.address:x} (Ignore - `size` parameter is constant)")
                continue
            # Ignore `memcpy` calls where the `size` parameter can be determined with dataflow
            # analysis
            possible_sizes = size_param.possible_values
            if possible_sizes.type != RegisterValueType.UndeterminedValue:
                Logger.debug("LibcMemcpy", f"0x{sink.address:x} (Ignore - `size` parameter determined with dataflow analysis)")
                continue
            # TODO:
            Logger.info("LibcMemcpy", f"0x{sink.address:x} (Interesting call)")
            MediumLevelILVarSsaModeler(size_param).model()
        Logger.info("LibcMemcpy", f"... stop finding calls with controllable `size` parameter.")
        return
    
    def find_all(self) -> None:
        self.find_controllable_param_size()
        return


# class ReverseTracker:
#     """
#     """
#     pass