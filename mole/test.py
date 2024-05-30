from binaryninja import (BinaryView, MediumLevelILAdd, MediumLevelILInstruction, MediumLevelILConst,
                         MediumLevelILOperation, MediumLevelILVarSsa, MediumLevelILSetVarSsa,
                         MediumLevelILVarPhi, RegisterValueType, SSAVariable)
from functools   import reduce
from typing      import List, Optional
from z3          import Or, Solver, BitVec, BitVecRef
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

    def __init__(self, tag: str = "Visitor") -> None:
        self._tag = tag
        return

    def _visit(self, inst: MediumLevelILInstruction) -> Optional[MediumLevelILInstruction]:
        """
        Call dedicated visit function based on operation name.
        """
        o_name = inst.operation.name.lower()
        f_name = f"_visit_{o_name:s}"
        if hasattr(self, f_name):
            return getattr(self, f_name)(inst)
        Logger.warn(self._tag, f"Visit function for operation `{o_name:s}` not implemented")
        return None


class MediumLevelILVarSsaModeler(MediumLevelILInstructionVisitor):
    """
    """

    def __init__(self, mlil_var_ssa: MediumLevelILVarSsa, tag: str = "Modeler") -> None:
        super().__init__(tag)
        self._mlil_var_ssa = mlil_var_ssa
        self._solver = Solver()
        self._visited_var_ssas = set()
        self._to_visit_mlil_instrs = set()
        self._visit_ssa_var_definition(mlil_var_ssa)
        return
    
    # def _create_bitvec(self, ssa_var: SSAVariable, size: int) -> BitVecRef:
    #     name = f"{ssa_var.name:s}#{ssa_var.version:d}"
    #     return BitVec(name, size)

    def _visit_ssa_var_definition(self, mlil_var_ssa: MediumLevelILVarSsa) -> None:
        """
        Visit the instruction defining `mlil_var_ssa`.
        """
        if mlil_var_ssa.src not in self._visited_var_ssas:
            mlil_var_ssa_def = mlil_var_ssa.function.get_ssa_var_definition(mlil_var_ssa.src)
            if mlil_var_ssa_def is not None:
                self._to_visit_mlil_instrs.add(mlil_var_ssa_def)
        return
    
    def model(self) -> None:
        """
        """
        while self._to_visit_mlil_instrs:
            mlil_instr = self._to_visit_mlil_instrs.pop()
            if mlil_instr is not None:
                self._visit(mlil_instr)
        print(self._solver)
        return
    
    def _visit_mlil_var_ssa(self, var_ssa: MediumLevelILVarSsa) -> Optional[BitVecRef]:
        Logger.debug(self._tag, f"0x{var_ssa.instr.address:x} {str(var_ssa):s} (MLIL_VAR_SSA)")
        # Visit variable definition (static backward slice)
        if var_ssa.src not in self._visited_var_ssas:
            var_def = var_ssa.function.get_ssa_var_definition(var_ssa.src)
            if var_def is not None:
                self._to_visit_mlil_instrs.add(var_def)

        # New Z3 bit-vector for the src variable
        src_name = var_ssa.src.name
        src_vers = var_ssa.src.version
        src_size = var_ssa.size
        bv_src = BitVec(f"{src_name:s}#{src_vers:d}", src_size*8)

        # TODO: Model byte swap

        # Constrain model
        return bv_src

    def _visit_mlil_set_var_ssa(self, set_var_ssa: MediumLevelILSetVarSsa) -> Optional[BitVecRef]:
        Logger.debug(self._tag, f"0x{set_var_ssa.instr.address:x} {str(set_var_ssa):s} (MLIL_SET_VAR_SSA)")
        # New Z3 bit-vector for the dest variable
        dest_name = set_var_ssa.dest.name
        dest_vers = set_var_ssa.dest.version
        dest_size = set_var_ssa.size
        bv_dest = BitVec(f"{dest_name:s}#{dest_vers:d}", dest_size*8)

        # Visit src variable
        bv_src = self._visit(set_var_ssa.src)

        # Constrain the model
        if bv_src is not None:
            self._solver.add(bv_dest == bv_src)

        # TODO: Model byte swap

        # TODO: Mark destinaton as visited
        self._visited_var_ssas.add(set_var_ssa.dest)
        if set_var_ssa in self._to_visit_mlil_instrs:
            self._to_visit_mlil_instrs.remove(set_var_ssa)

        return

    def _visit_mlil_var_phi(self, var_phi: MediumLevelILVarPhi) -> Optional[BitVecRef]:
        Logger.debug(self._tag, f"0x{var_phi.instr.address:x} {str(var_phi):s} (MLIL_SET_VAR_PHI)")
        # New Z3 bit-vector for the dest variable
        dest_name = var_phi.dest.name
        dest_vers = var_phi.dest.version
        dest_size = var_phi.dest.var.type.width
        bv_dest = BitVec(f"{dest_name:s}#{dest_vers:d}", dest_size*8)

        # Visit src variables
        bv_srcs = []
        for ssa_var in var_phi.src:
            # Visit variable definition (static backward slice)
            if ssa_var not in self._visited_var_ssas:
                var_def = var_phi.function.get_ssa_var_definition(ssa_var)
                if var_def is not None:
                    self._to_visit_mlil_instrs.add(var_def)

            # New Z3 bit-vector for the src variable
            src_name = ssa_var.name
            src_vers = ssa_var.version
            src_size = ssa_var.var.type.width
            bv_src = BitVec(f"{src_name:s}#{src_vers:d}", src_size*8)

            bv_srcs.append(bv_src)

        # Constrain the model
        if bv_srcs:
            self._solver.add(reduce(
                lambda i, j: Or(i, j),
                [bv_dest == bv_src for bv_src in bv_srcs]
            ))

        # TODO: Model byte swap

        # TODO: Mark destinaton as visited
        self._visited_var_ssas.add(var_phi.dest)
        if var_phi in self._to_visit_mlil_instrs:
            self._to_visit_mlil_instrs.remove(var_phi)
        
        return

    def _visit_mlil_add(self, add: MediumLevelILAdd) -> Optional[BitVecRef]:
        Logger.debug(self._tag, f"0x{add.instr.address:x} {str(add):s} (MLIL_ADD)")
        l = self._visit(add.left)
        r = self._visit(add.right)
        if None not in (l, r):
            return l + r
        
    def _visit_mlil_const(self, const: MediumLevelILConst) -> Optional[BitVecRef]:
        Logger.debug(self._tag, f"0x{const.instr.address:x} {str(const):s} (MLIL_CONST)")
        return const.constant


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
            # TODO: Remove break
            Logger.info("LibcMemcpy", f"0x{sink.address:x} (Interesting call)")
            MediumLevelILVarSsaModeler(size_param).model()
            break
        Logger.info("LibcMemcpy", f"... stop finding calls with controllable `size` parameter.")
        return
    
    def find_all(self) -> None:
        self.find_controllable_param_size()
        return


# class ReverseTracker:
#     """
#     """
#     pass