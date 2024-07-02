# import binaryninja  as bn
# from binaryninja         import (BinaryView, Endianness, MediumLevelILAdd, MediumLevelILAddressOf,
#                                  MediumLevelILCallSsa, MediumLevelILCmpE, MediumLevelILCmpNe,
#                                  MediumLevelILCmpSge, MediumLevelILCmpSlt, MediumLevelILCmpUge,
#                                  MediumLevelILCmpUgt, MediumLevelILCmpUle, MediumLevelILConst,
#                                  MediumLevelILFunction, MediumLevelILGoto, MediumLevelILIf,
#                                  MediumLevelILInstruction, MediumLevelILLoadSsa, MediumLevelILLsl,
#                                  MediumLevelILLsr, MediumLevelILOperation, MediumLevelILSetVarSsa,
#                                  MediumLevelILSub, MediumLevelILVarAliased, MediumLevelILVarPhi,
#                                  MediumLevelILVarSsa, RegisterValueType, SSAVariable)
# from binaryninja.enums  import ILBranchDependence
# from binaryninja.types  import BoolType, IntegerType, PointerType
# from functools          import reduce
# from typing             import Dict, List, Optional, Set, Tuple
# from z3                 import (Array, BitVec, BitVecRef, BitVecSort, Bool, BoolRef, Concat,
#                                 ExprRef, LShR, Or, Solver, UGE, UGT, ULE)
# from .common.log        import Logger
# from .model.back_slicer import MediumLevelILVarSsaSlicer


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


# class MediumLevelILInstructionVisitor:
#     """
#     Base class for visiting MLIL instructions.
#     """

#     def __init__(self, bv: BinaryView, tag: str = "Visitor") -> None:
#         self._bv = bv
#         self._tag = tag
#         return
    
#     def _create_z3_variable(self, var: SSAVariable) -> ExprRef:
#         """
#         Create a Z3 variable for `var`.
#         """
#         name = f"{var.name:s}#{var.version:d}"
#         if name not in self._vars:
#             if isinstance(var.type, BoolType):
#                 self._vars[name] = Bool(name)
#             else:
#                 if not (isinstance(var.type, IntegerType) or isinstance(var.type, PointerType)):
#                     Logger.warn(self._tag, f"Variable type `{str(var.type):s}` not implemented")
#                 size = var.type.width
#                 self._vars[name] = BitVec(name, size*8)
#         return self._vars[name]
    
#     def _visit_var_ssa_definition(self, var: SSAVariable, fun: MediumLevelILFunction) -> ExprRef:
#         """
#         Visit the expression defining variable `var` in function `fun`.
#         """
#         # Get variable definnition
#         var_def = fun.get_ssa_var_definition(var)
#         # Return new Z3 bit-vector if variable is undefined
#         if var_def is None:
#             return self._create_z3_variable(var)
#         # Visit variable definition
#         return self._visit(var_def)

#     def _visit(self, instr: MediumLevelILInstruction) -> Optional[MediumLevelILInstruction]:
#         """
#         Call dedicated visit function based on operation name of instruction `instr`.
#         """
#         o_name = instr.operation.name.lower()
#         f_name = f"_visit_{o_name:s}"
#         if hasattr(self, f_name):
#             return getattr(self, f_name)(instr)
#         Logger.warn(self._tag, f"Visit function for operation `{o_name:s}` not implemented")
#         return None




# class MediumLevelILVarSsaModeler(MediumLevelILInstructionVisitor):
#     """
#     TODO: What are the correct typing return values for the _visit methods?
#     """

#     def __init__(self, bv: BinaryView, expr: MediumLevelILVarSsa, tag: str = "Modeler") -> None:
#         super().__init__(bv, tag)
#         self._expr = expr
#         self._func = expr.function
#         self._visited_exprs = {}
#         self._memory = Array("memory", BitVecSort(self._bv.address_size*8), BitVecSort(8))
#         self._vars = {}
#         self._constraints = {}
#         self._branch_constraints = {}
#         self._solver = Solver()
#         self._branches = set()
#         # self._defined_vars = {}
#         # self._visited_vars = set()
#         # self._to_visit_exprs = set([expr])
#         # self._visit_ssa_var_definition(expr.src, expr)
#         return
    
#     def _get_memory_value(self, mem_addr: BitVecRef) -> BitVecRef:
#         mem = self._memory
#         addr_size = self._bv.address_size
#         # 2-byte memory addressing
#         if addr_size == 2:
#             if self._bv.endianness == Endianness.LittleEndian:
#                 mem_val = Concat(
#                     mem[mem_addr+1],
#                     mem[mem_addr+0]
#                 )
#             else:
#                 mem_val = Concat(
#                     mem[mem_addr+0],
#                     mem[mem_addr+1]
#                 )
#         # 4-byte memory addressing
#         elif addr_size == 4:
#             if self._bv.endianness == Endianness.LittleEndian:
#                 mem_val = Concat(
#                     mem[mem_addr+3],
#                     mem[mem_addr+2],
#                     mem[mem_addr+1],
#                     mem[mem_addr+0],
#                 )
#             else:
#                 mem_val = Concat(
#                     mem[mem_addr+0],
#                     mem[mem_addr+1],
#                     mem[mem_addr+2],
#                     mem[mem_addr+3]
#                 )
#         # 8-byte memory addressing
#         elif addr_size == 8:
#             if self._bv.endianness == Endianness.LittleEndian:
#                 mem_val = Concat(
#                     mem[mem_addr+7],
#                     mem[mem_addr+6],
#                     mem[mem_addr+5],
#                     mem[mem_addr+4],
#                     mem[mem_addr+3],
#                     mem[mem_addr+2],
#                     mem[mem_addr+1],
#                     mem[mem_addr+0]
#                 )
#             else:
#                 mem_val = Concat(
#                     mem[mem_addr+0],
#                     mem[mem_addr+1],
#                     mem[mem_addr+2],
#                     mem[mem_addr+3],
#                     mem[mem_addr+4],
#                     mem[mem_addr+5],
#                     mem[mem_addr+6],
#                     mem[mem_addr+7]
#                 )
#         # Default to 1-byte memory addressing
#         else:
#             mem_val = mem[mem_addr+0]
#         return mem_val
    
#     def _visit_mlil_add(self, expr: MediumLevelILAdd) -> BitVecRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit child expressions
#         lft = self._visit(expr.left)
#         rgt = self._visit(expr.right)
#         add = lft + rgt
#         # Mark expression as visited
#         self._visited_exprs[expr] = add
#         return add
    
#     # def _visit_mlil_address_of(self, expr: MediumLevelILAddressOf) -> None:
#     #     # Expression visited before
#     #     if expr in self._visited_exprs:
#     #         return self._visited_exprs[expr]
#     #     # TODO: How to implement?
#     #     # for function in self._bv.functions:
#     #     #     mlil = function.medium_level_il
#     #     #     for ssa_var in mlil.ssa_vars:
#     #     #         if ssa_var.var.name == expr.src.name:
#     #     #             pass
#     #     # Mark expression as visited
#     #     self._visited_exprs[expr] = None
#     #     return None

#     def _visit_mlil_call_ssa(self, expr: MediumLevelILCallSsa) -> BitVecRef:
#         # Log SSA expression
#         Logger.debug(self._tag, f"0x{expr.instr.address:x} {str(expr):s} (MLIL_CALL_SSA)")
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # TODO:
#         if len(expr.output) != 1:
#             Logger.warn(self._tag, f"More/less than 1 outputs not implemented")
#         out = self._create_z3_variable(expr.output[0])
#         # Mark expression as visited
#         self._visited_exprs[expr] = out
#         return out

#     def _visit_mlil_cmp_e(self, expr: MediumLevelILCmpE) -> BoolRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit child expressions
#         lft = self._visit(expr.left)
#         rgt = self._visit(expr.right)
#         e   = lft == rgt
#         # Mark expression as visited
#         self._visited_exprs[expr] = e
#         return e

#     def _visit_mlil_cmp_ne(self, expr: MediumLevelILCmpNe) -> BoolRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit child expressions
#         lft = self._visit(expr.left)
#         rgt = self._visit(expr.right)
#         ne  = lft != rgt
#         # Mark expression as visited
#         self._visited_exprs[expr] = ne
#         return ne

#     def _visit_mlil_cmp_sge(self, expr: MediumLevelILCmpSge) -> BoolRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit child expressions
#         lft = self._visit(expr.left)
#         rgt = self._visit(expr.right)
#         sge = lft >= rgt
#         # Mark expression as visited
#         self._visited_exprs[expr] = sge
#         return sge
    
#     def _visit_mlil_cmp_slt(self, expr: MediumLevelILCmpSlt) -> BoolRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit child expressions
#         lft = self._visit(expr.left)
#         rgt = self._visit(expr.right)
#         slt = lft < rgt
#         # Mark expression as visited
#         self._visited_exprs[expr] = slt
#         return slt

#     def _visit_mlil_cmp_uge(self, expr: MediumLevelILCmpUge) -> BoolRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit child expressions
#         lft = self._visit(expr.left)
#         rgt = self._visit(expr.right)
#         uge = UGE(lft, rgt)
#         # Mark expression as visited
#         self._visited_exprs[expr] = uge
#         return uge

#     def _visit_mlil_cmp_ugt(self, expr: MediumLevelILCmpUgt) -> BoolRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit child expressions
#         lft = self._visit(expr.left)
#         rgt = self._visit(expr.right)
#         ugt = UGT(lft, rgt)
#         # Mark expression as visited
#         self._visited_exprs[expr] = ugt
#         return ugt
    
#     def _visit_mlil_cmp_ule(self, expr: MediumLevelILCmpUle) -> BoolRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit child expressions
#         lft = self._visit(expr.left)
#         rgt = self._visit(expr.right)
#         ule = ULE(lft, rgt)
#         # Mark expression as visited
#         self._visited_exprs[expr] = ule
#         return ule

#     def _visit_mlil_const(self, expr: MediumLevelILConst) -> int:
#         return expr.constant

#     def _visit_mlil_goto(self, expr: MediumLevelILGoto) -> BitVecRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         dest = self._visit(self._func[expr.dest])
#         # Mark expression as visited
#         self._visited_exprs[expr] = dest
#         return dest

#     def _visit_mlil_if(self, expr: MediumLevelILIf) -> BoolRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit condition and if/then expressions
#         con = self._visit(expr.condition)
#         # ifb = self._visit(self._func[expr.operands[1]])
#         # elb = self._visit(self._func[expr.operands[2]])
#         # ite = If(con, ifb, elb)
#         # Mark expression as visited
#         self._visited_exprs[expr] = con 
#         return con
    
#     def _visit_mlil_load_ssa(self, expr: MediumLevelILLoadSsa) -> BitVecRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit memory address
#         mem_addr = self._visit(expr.src)
#         # Get memory value
#         mem_val = self._get_memory_value(mem_addr)
#         # Mark expression as visited
#         self._visited_exprs[expr] = mem_val
#         return mem_val
    
#     def _visit_mlil_lsl(self, expr: MediumLevelILLsl) -> BitVecRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit child expressions
#         lft = self._visit(expr.left)
#         rgt = self._visit(expr.right)
#         lsl = lft << rgt
#         # Mark expression as visited
#         self._visited_exprs[expr] = lsl
#         return lsl
    
#     def _visit_mlil_lsr(self, expr: MediumLevelILLsr) -> BitVecRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit child expressions
#         lft = self._visit(expr.left)
#         rgt = self._visit(expr.right)
#         lsr = LShR(lft, rgt)
#         # Mark expression as visited
#         self._visited_exprs[expr] = lsr
#         return lsr
    
#     # def _create_bitvec(self, ssa_var: SSAVariable, size: int) -> BitVecRef:
#     #     name = f"{ssa_var.name:s}#{ssa_var.version:d}"
#     #     return BitVec(name, size)

#     # def _visit_ssa_var_definition(self, mlil_var_ssa: MediumLevelILVarSsa) -> None:
#     #     """
#     #     Visit the instruction defining `mlil_var_ssa`.
#     #     """
#     #     if mlil_var_ssa.src not in self._visited_vars:
#     #         mlil_var_ssa_def = mlil_var_ssa.function.get_ssa_var_definition(mlil_var_ssa.src)
#     #         if mlil_var_ssa_def is not None:
#     #             self._to_visit_exprs.add(mlil_var_ssa_def)
#     #     return


#     #     if var not in self._visited_vars:
#     #         var_def = self._func.get_ssa_var_definition(var)
#     #         if var_def is not None:
#     #             self._to_visit_exprs.add(var_def)
#     #     return
    
#     # def _visit_mlil_var_ssa(self, var_ssa: MediumLevelILVarSsa) -> Optional[BitVecRef]:
#     #     Logger.debug(self._tag, f"0x{var_ssa.instr.address:x} {str(var_ssa):s} (MLIL_VAR_SSA)")
#     #     # Visit variable definition (static backward slice)
#     #     if var_ssa.src not in self._visited_vars:
#     #         var_def = var_ssa.function.get_ssa_var_definition(var_ssa.src)
#     #         if var_def is not None:
#     #             self._to_visit_exprs.add(var_def)

#     #     # New Z3 bit-vector for the src variable
#     #     src_name = var_ssa.src.name
#     #     src_vers = var_ssa.src.version
#     #     src_size = var_ssa.size
#     #     bv_src = BitVec(f"{src_name:s}#{src_vers:d}", src_size*8)

#     #     # TODO: Model byte swap

#     #     # Constrain model
#     #     return bv_src

#     def _visit_mlil_set_var_ssa(self, expr: MediumLevelILSetVarSsa) -> ExprRef:
#         # Log SSA expression
#         Logger.debug(self._tag, f"0x{expr.instr.address:x} {str(expr):s} (MLIL_SET_VAR_SSA)")
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # New Z3 bit-vector for the `dest` variable
#         dest = self._create_z3_variable(expr.dest)
#         # Mark expression as visited
#         self._visited_exprs[expr] = dest
#         # Visit `src` variable
#         src = self._visit(expr.src)
#         # Constrain the model
#         if src is not None:
#             self._solver.add(dest == src)
#         # # # # TODO: Branch dependencies
#         # # for instr_index, branch in expr.branch_dependence.items():
#         # #     Logger.warn(self._tag, f"Branch dependence: {instr_index:d} {str(branch):s}")
#         # branch_conditions = set()
#         # for instr_index, branch in expr.branch_dependence.items():
#         #     con = self._visit(self._func[instr_index])
#         #     if con is None:
#         #         continue
#         #     if branch.value == ILBranchDependence.TrueBranchDependent:
#         #         self._solver.add(con == True)
#         #         # branch_conditions.add(con == True)
#         #     elif branch.value == ILBranchDependence.FalseBranchDependent:
#         #         self._solver.add(con == False)
#         #         # branch_conditions.add(con == False)
#         #     # self._branches.add(branch)
#         #     # con = self._visit(self._func[instr_index])
#         #     # if con is not None:
#         #     #     branch_conditions.add(con)
#         return dest
    
#     def _visit_mlil_sub(self, expr: MediumLevelILSub) -> BitVecRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit child expressions
#         lft = self._visit(expr.left)
#         rgt = self._visit(expr.right)
#         sub = lft - rgt
#         # Mark expression as visited
#         self._visited_exprs[expr] = sub
#         return sub
    
#     def _visit_mlil_var_aliased(self, expr: MediumLevelILVarAliased) -> BitVecRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit variable
#         var = self._visit_mlil_var_ssa(expr)
#         # Mark expression as visited
#         self._visited_exprs[expr] = var
#         return var
    
#     # def _new_visit_mlil_var_ssa(self, expr: MediumLevelILVarSsa) -> Tuple[ExprRef, Dict[None]]:
#     #     # Expression visited before
#     #     if expr.instr_index in self._visited_exprs:
#     #         return self._visited_exprs[expr.instr_index]
#     #     # Visit variable definition
#     #     src, bco = self._visit_var_ssa_definition(expr.src, self._func)
#     #     # Branch dependency
#     #     for instr_index, branch in expr.branch_dependence.items():
#     #         cond, _ = self._visit(self._func[instr_index])
#     #         if cond is None: continue
#     #         if branch.value == ILBranchDependence.TrueBranchDependent:
#     #             bco[instr_index] = cond == True
#     #         elif branch.value == ILBranchDependence.FalseBranchDependent:
#     #             bco[instr_index] = cond == False
#     #     # Mark expression as visited
#     #     self._visited_exprs[expr.instr_index] = (src, bco)
#     #     return (src, bco)

#     def _visit_mlil_var_ssa(self, expr: MediumLevelILVarSsa) -> ExprRef:
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # Visit variable definition
#         src = self._visit_var_ssa_definition(expr.src, self._func)
#         # Mark expression as visited
#         self._visited_exprs[expr] = src
#         return src

#     # def _visit_mlil_set_var_ssa(self, set_var_ssa: MediumLevelILSetVarSsa) -> Optional[BitVecRef]:
#     #     Logger.debug(self._tag, f"0x{set_var_ssa.instr.address:x} {str(set_var_ssa):s} (MLIL_SET_VAR_SSA)")
#     #     # New Z3 bit-vector for the dest variable
#     #     dest_name = set_var_ssa.dest.name
#     #     dest_vers = set_var_ssa.dest.version
#     #     dest_size = set_var_ssa.size
#     #     dest_bv = BitVec(f"{dest_name:s}#{dest_vers:d}", dest_size*8)

#     #     # Visit src variable
#     #     bv_src = self._visit(set_var_ssa.src)

#     #     # Constrain the model
#     #     if bv_src is not None:
#     #         self._solver.add(dest_bv == bv_src)

#     #     # TODO: Model byte swap

#     #     # TODO: Mark destinaton as visited
#     #     self._visited_vars.add(set_var_ssa.dest)
#     #     if set_var_ssa in self._to_visit_exprs:
#     #         self._to_visit_exprs.remove(set_var_ssa)

#     #     return

#     # def _visit_mlil_var_phi(self, expr: MediumLevelILVarPhi) -> Optional[BitVecRef]:
#     #     Logger.debug(self._tag, f"0x{expr.instr.address:x} {str(expr):s} (MLIL_SET_VAR_PHI)")
#     #     # New Z3 bit-vector for the dest variable
#     #     dest_name = expr.dest.name
#     #     dest_vers = expr.dest.version
#     #     dest_size = expr.dest.var.type.width
#     #     dest_bv = BitVec(f"{dest_name:s}#{dest_vers:d}", dest_size*8)

#     #     # Visit src variables
#     #     src_bvs = []
#     #     for var in expr.src:
#     #         # Visit variable definition (static backward slice)
#     #         self._visit_ssa_var_definition(var, expr)

#     #         # New Z3 bit-vector for the src variable
#     #         src_name = var.name
#     #         src_vers = var.version
#     #         src_size = var.var.type.width
#     #         src_bv = BitVec(f"{src_name:s}#{src_vers:d}", src_size*8)

#     #         src_bvs.append(src_bv)

#     #     # Constrain the model
#     #     if src_bvs:
#     #         self._solver.add(reduce(
#     #             lambda i, j: Or(i, j),
#     #             [dest_bv == src_bv for src_bv in src_bvs]
#     #         ))

#     #     # TODO: Model byte swap

#     #     # TODO: Mark destinaton as visited
#     #     self._visited_vars.add(expr.dest)
#     #     if expr in self._to_visit_exprs:
#     #         self._to_visit_exprs.remove(expr)
        
#     #     return

#     def _visit_mlil_var_phi(self, expr: MediumLevelILVarPhi) -> ExprRef:
#         # Log SSA expression
#         Logger.debug(self._tag, f"0x{expr.instr.address:x} {str(expr):s} (MLIL_VAR_PHI)")
#         # Expression visited before
#         if expr in self._visited_exprs:
#             return self._visited_exprs[expr]
#         # New Z3 bit-vector for the `dest` variable
#         dest = self._create_z3_variable(expr.dest)
#         # Mark expression as visited
#         self._visited_exprs[expr] = dest
#         # Visit `src` variables
#         srcs = []
#         for var in expr.src:
#             # Visit variable definition
#             src = self._visit_var_ssa_definition(var, self._func)
#             if src is not None:
#                 srcs.append(src)
#         # Constrain the model
#         if srcs:
#             self._solver.add(reduce(
#                 lambda i, j: Or(i, j),
#                 [dest == src_bv for src_bv in srcs]
#             ))
#         return dest

#     # def _visit_mlil_add(self, expr: MediumLevelILAdd) -> Optional[BitVecRef]:
#     #     Logger.debug(self._tag, f"0x{expr.instr.address:x} {str(expr):s} (MLIL_ADD)")
#     #     l = self._visit(expr.left)
#     #     r = self._visit(expr.right)
#     #     if None not in (l, r):
#     #         return l + r
#     #     return None

#     def model(self) -> None:
#         """
#         """
#         # while self._to_visit_exprs:
#         #     expr = self._to_visit_exprs.pop()
#         #     if expr is not None:
#         #         self._visit(expr)
#         model_bv = self._visit(self._expr)

#         # # TODO: Branch dependencies
#         # for instr_index, branch in self._expr.branch_dependence.items():
#         #     Logger.warn(self._tag, f"{instr_index:d} {str(branch):s}")
#         return