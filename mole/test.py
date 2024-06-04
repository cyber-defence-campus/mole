from binaryninja import (BinaryView, Endianness, MediumLevelILAdd, MediumLevelILConst,
                         MediumLevelILInstruction, MediumLevelILLoadSsa, MediumLevelILLsl,
                         MediumLevelILLsr, MediumLevelILOperation, MediumLevelILSetVarSsa,
                         MediumLevelILSub, MediumLevelILVarAliased, MediumLevelILVarPhi,
                         MediumLevelILVarSsa, RegisterValueType, SSAVariable)
from functools   import reduce
from typing      import List, Optional
from z3          import Array, Concat, LShR, Or, Solver, BitVec, BitVecRef, BitVecSort
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

    def __init__(self, bv: BinaryView, tag: str = "Visitor") -> None:
        self._bv = bv
        self._tag = tag
        return
    
    def _visit_var_ssa_definition(self, var: SSAVariable, expr: MediumLevelILInstruction) -> BitVecRef:
        """
        Visit the expression defining a variable.
        """
        # Get variable definnition
        var_def = expr.function.get_ssa_var_definition(var)
        # Return new Z3 bit-vector if variable is undefined
        if var_def is None:
            name = expr.src.name
            vers = expr.src.version
            size = expr.size
            return BitVec(f"{name:s}#{vers:d}", size*8)
        # Visit variable definition
        return self._visit(var_def)

    def _visit(self, instr: MediumLevelILInstruction) -> Optional[MediumLevelILInstruction]:
        """
        Call dedicated visit function based on operation name.
        """
        o_name = instr.operation.name.lower()
        f_name = f"_visit_{o_name:s}"
        if hasattr(self, f_name):
            return getattr(self, f_name)(instr)
        Logger.warn(self._tag, f"Visit function for operation `{o_name:s}` not implemented")
        return None


class MediumLevelILVarSsaModeler(MediumLevelILInstructionVisitor):
    """
    """

    def __init__(self, bv: BinaryView, expr: MediumLevelILVarSsa, tag: str = "Modeler") -> None:
        super().__init__(bv, tag)
        self._expr = expr
        self._memory = Array("memory", BitVecSort(self._bv.address_size*8), BitVecSort(8))
        self._solver = Solver()
        # self._defined_vars = {}
        # self._visited_vars = set()
        self._visited_exprs = {}
        self._to_visit_exprs = set([expr])
        # self._visit_ssa_var_definition(expr.src, expr)
        return
    
    def _get_memory_value(self, mem_addr: BitVecRef) -> BitVecRef:
        mem = self._memory
        addr_size = self._bv.address_size
        # 2-byte memory addressing
        if addr_size == 2:
            if self._bv.endianness == Endianness.LittleEndian:
                mem_val = Concat(
                    mem[mem_addr+1],
                    mem[mem_addr+0]
                )
            else:
                mem_val = Concat(
                    mem[mem_addr+0],
                    mem[mem_addr+1]
                )
        # 4-byte memory addressing
        elif addr_size == 4:
            if self._bv.endianness == Endianness.LittleEndian:
                mem_val = Concat(
                    mem[mem_addr+3],
                    mem[mem_addr+2],
                    mem[mem_addr+1],
                    mem[mem_addr+0],
                )
            else:
                mem_val = Concat(
                    mem[mem_addr+0],
                    mem[mem_addr+1],
                    mem[mem_addr+2],
                    mem[mem_addr+3]
                )
        # 8-byte memory addressing
        elif addr_size == 8:
            if self._bv.endianness == Endianness.LittleEndian:
                mem_val = Concat(
                    mem[mem_addr+7],
                    mem[mem_addr+6],
                    mem[mem_addr+5],
                    mem[mem_addr+4],
                    mem[mem_addr+3],
                    mem[mem_addr+2],
                    mem[mem_addr+1],
                    mem[mem_addr+0]
                )
            else:
                mem_val = Concat(
                    mem[mem_addr+0],
                    mem[mem_addr+1],
                    mem[mem_addr+2],
                    mem[mem_addr+3],
                    mem[mem_addr+4],
                    mem[mem_addr+5],
                    mem[mem_addr+6],
                    mem[mem_addr+7]
                )
        # Default to 1-byte memory addressing
        else:
            mem_val = mem[mem_addr+0]
        return mem_val
    
    def _visit_mlil_add(self, expr: MediumLevelILAdd) -> BitVecRef:
        # Expression visited before
        if expr in self._visited_exprs:
            return self._visited_exprs[expr]
        # Visit child expressions
        lft_bv = self._visit(expr.left)
        rht_bv = self._visit(expr.right)
        add_bv = lft_bv + rht_bv
        # Mark expression as visited
        self._visited_exprs[expr] = add_bv
        return add_bv
    
    def _visit_mlil_const(self, expr: MediumLevelILConst) -> int:
        return expr.constant
    
    def _visit_mlil_load_ssa(self, expr: MediumLevelILLoadSsa) -> BitVecRef:
        # Expression visited before
        if expr in self._visited_exprs:
            return self._visited_exprs[expr]
        # Visit memory address
        mem_addr_bv = self._visit(expr.src)
        # Get memory value
        mem_val_bv = self._get_memory_value(mem_addr_bv)
        # Mark expression as visited
        self._visited_exprs[expr] = mem_val_bv
        return mem_val_bv
    
    def _visit_mlil_lsl(self, expr: MediumLevelILLsl) -> BitVecRef:
        # Expression visited before
        if expr in self._visited_exprs:
            return self._visited_exprs[expr]
        # Visit child expressions
        lft_bv = self._visit(expr.left)
        rht_bv = self._visit(expr.right)
        lsl_bv = lft_bv << rht_bv
        # Mark expression as visited
        self._visited_exprs[expr] = lsl_bv
        return lsl_bv
    
    def _visit_mlil_lsr(self, expr: MediumLevelILLsr) -> BitVecRef:
        # Expression visited before
        if expr in self._visited_exprs:
            return self._visited_exprs[expr]
        # Visit child expressions
        lft_bv = self._visit(expr.left)
        rht_bv = self._visit(expr.right)
        lsr_bv = LShR(lft_bv, rht_bv)
        # Mark expression as visited
        self._visited_exprs[expr] = lsr_bv
        return lsr_bv
    
    # def _create_bitvec(self, ssa_var: SSAVariable, size: int) -> BitVecRef:
    #     name = f"{ssa_var.name:s}#{ssa_var.version:d}"
    #     return BitVec(name, size)

    # def _visit_ssa_var_definition(self, mlil_var_ssa: MediumLevelILVarSsa) -> None:
    #     """
    #     Visit the instruction defining `mlil_var_ssa`.
    #     """
    #     if mlil_var_ssa.src not in self._visited_vars:
    #         mlil_var_ssa_def = mlil_var_ssa.function.get_ssa_var_definition(mlil_var_ssa.src)
    #         if mlil_var_ssa_def is not None:
    #             self._to_visit_exprs.add(mlil_var_ssa_def)
    #     return


    #     if var not in self._visited_vars:
    #         var_def = expr.function.get_ssa_var_definition(var)
    #         if var_def is not None:
    #             self._to_visit_exprs.add(var_def)
    #     return
    
    # def _visit_mlil_var_ssa(self, var_ssa: MediumLevelILVarSsa) -> Optional[BitVecRef]:
    #     Logger.debug(self._tag, f"0x{var_ssa.instr.address:x} {str(var_ssa):s} (MLIL_VAR_SSA)")
    #     # Visit variable definition (static backward slice)
    #     if var_ssa.src not in self._visited_vars:
    #         var_def = var_ssa.function.get_ssa_var_definition(var_ssa.src)
    #         if var_def is not None:
    #             self._to_visit_exprs.add(var_def)

    #     # New Z3 bit-vector for the src variable
    #     src_name = var_ssa.src.name
    #     src_vers = var_ssa.src.version
    #     src_size = var_ssa.size
    #     bv_src = BitVec(f"{src_name:s}#{src_vers:d}", src_size*8)

    #     # TODO: Model byte swap

    #     # Constrain model
    #     return bv_src

    def _visit_mlil_set_var_ssa(self, expr: MediumLevelILSetVarSsa) -> BitVecRef:
        # Log SSA expression
        Logger.debug(self._tag, f"0x{expr.instr.address:x} {str(expr):s} (MLIL_SET_VAR_SSA)")
        # Expression visited before
        if expr in self._visited_exprs:
            return self._visited_exprs[expr]
        # New Z3 bit-vector for the `dest` variable
        dest_name = expr.dest.name
        dest_vers = expr.dest.version
        dest_size = expr.size
        dest_bv = BitVec(f"{dest_name:s}#{dest_vers:d}", dest_size*8)
        # Mark expression as visited
        self._visited_exprs[expr] = dest_bv
        # Visit `src` variable
        src_bv = self._visit(expr.src)
        # Constrain the model
        if src_bv is not None:
            self._solver.add(dest_bv == src_bv)
        return dest_bv
    
    def _visit_mlil_sub(self, expr: MediumLevelILSub) -> BitVecRef:
        # Expression visited before
        if expr in self._visited_exprs:
            return self._visited_exprs[expr]
        # Visit child expressions
        lft_bv = self._visit(expr.left)
        rht_bv = self._visit(expr.right)
        sub_bv = lft_bv - rht_bv
        # Mark expression as visited
        self._visited_exprs[expr] = sub_bv
        return sub_bv
    
    # def visit_MLIL_ADD(self, expr):
    #     left = self.visit(expr.left)
    #     right = self.visit(expr.right)

    #     if None not in (left, right):
    #         return left + right
    
    def _visit_mlil_var_aliased(self, expr: MediumLevelILVarAliased) -> BitVecRef:
        # Expression visited before
        if expr in self._visited_exprs:
            return self._visited_exprs[expr]
        # Visit variable
        var_bv = self._visit_mlil_var_ssa(expr)
        # Mark expression as visited
        self._visited_exprs[expr] = var_bv
        return var_bv

    def _visit_mlil_var_ssa(self, expr: MediumLevelILVarSsa) -> BitVecRef:
        # Expression visited before
        if expr in self._visited_exprs:
            return self._visited_exprs[expr]
        # Visit variable definition
        src_bv = self._visit_var_ssa_definition(expr.src, expr)
        # Mark expression as visited
        self._visited_exprs[expr] = src_bv
        return src_bv

    # def _visit_mlil_set_var_ssa(self, set_var_ssa: MediumLevelILSetVarSsa) -> Optional[BitVecRef]:
    #     Logger.debug(self._tag, f"0x{set_var_ssa.instr.address:x} {str(set_var_ssa):s} (MLIL_SET_VAR_SSA)")
    #     # New Z3 bit-vector for the dest variable
    #     dest_name = set_var_ssa.dest.name
    #     dest_vers = set_var_ssa.dest.version
    #     dest_size = set_var_ssa.size
    #     dest_bv = BitVec(f"{dest_name:s}#{dest_vers:d}", dest_size*8)

    #     # Visit src variable
    #     bv_src = self._visit(set_var_ssa.src)

    #     # Constrain the model
    #     if bv_src is not None:
    #         self._solver.add(dest_bv == bv_src)

    #     # TODO: Model byte swap

    #     # TODO: Mark destinaton as visited
    #     self._visited_vars.add(set_var_ssa.dest)
    #     if set_var_ssa in self._to_visit_exprs:
    #         self._to_visit_exprs.remove(set_var_ssa)

    #     return

    # def _visit_mlil_var_phi(self, expr: MediumLevelILVarPhi) -> Optional[BitVecRef]:
    #     Logger.debug(self._tag, f"0x{expr.instr.address:x} {str(expr):s} (MLIL_SET_VAR_PHI)")
    #     # New Z3 bit-vector for the dest variable
    #     dest_name = expr.dest.name
    #     dest_vers = expr.dest.version
    #     dest_size = expr.dest.var.type.width
    #     dest_bv = BitVec(f"{dest_name:s}#{dest_vers:d}", dest_size*8)

    #     # Visit src variables
    #     src_bvs = []
    #     for var in expr.src:
    #         # Visit variable definition (static backward slice)
    #         self._visit_ssa_var_definition(var, expr)

    #         # New Z3 bit-vector for the src variable
    #         src_name = var.name
    #         src_vers = var.version
    #         src_size = var.var.type.width
    #         src_bv = BitVec(f"{src_name:s}#{src_vers:d}", src_size*8)

    #         src_bvs.append(src_bv)

    #     # Constrain the model
    #     if src_bvs:
    #         self._solver.add(reduce(
    #             lambda i, j: Or(i, j),
    #             [dest_bv == src_bv for src_bv in src_bvs]
    #         ))

    #     # TODO: Model byte swap

    #     # TODO: Mark destinaton as visited
    #     self._visited_vars.add(expr.dest)
    #     if expr in self._to_visit_exprs:
    #         self._to_visit_exprs.remove(expr)
        
    #     return

    def _visit_mlil_var_phi(self, expr: MediumLevelILVarPhi) -> BitVecRef:
        # Log SSA expression
        Logger.debug(self._tag, f"0x{expr.instr.address:x} {str(expr):s} (MLIL_SET_VAR_PHI)")
        # Expression visited before
        if expr in self._visited_exprs:
            return self._visited_exprs[expr]
        # New Z3 bit-vector for the `dest` variable
        dest_name = expr.dest.name
        dest_vers = expr.dest.version
        dest_size = expr.dest.var.type.width
        dest_bv = BitVec(f"{dest_name:s}#{dest_vers:d}", dest_size*8)
        # Mark expression as visited
        self._visited_exprs[expr] = dest_bv
        # Visit `src` variables
        src_bvs = []
        for var in expr.src:
            # Visit variable definition
            src_bv = self._visit_var_ssa_definition(var, expr)
            if src_bv is not None:
                src_bvs.append(src_bv)
        # Constrain the model
        if src_bvs:
            self._solver.add(reduce(
                lambda i, j: Or(i, j),
                [dest_bv == src_bv for src_bv in src_bvs]
            ))
        return dest_bv

    # def _visit_mlil_add(self, expr: MediumLevelILAdd) -> Optional[BitVecRef]:
    #     Logger.debug(self._tag, f"0x{expr.instr.address:x} {str(expr):s} (MLIL_ADD)")
    #     l = self._visit(expr.left)
    #     r = self._visit(expr.right)
    #     if None not in (l, r):
    #         return l + r
    #     return None

    def model(self) -> None:
        """
        """
        while self._to_visit_exprs:
            expr = self._to_visit_exprs.pop()
            if expr is not None:
                self._visit(expr)
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
            if sink.address in [0xa9c0, 0xaa60, 0xae0c]:
                continue
            MediumLevelILVarSsaModeler(self._bv, size_param).model()
        Logger.info("LibcMemcpy", f"... stop finding calls with controllable `size` parameter.")
        return
    
    def find_all(self) -> None:
        self.find_controllable_param_size()
        return


# class ReverseTracker:
#     """
#     """
#     pass