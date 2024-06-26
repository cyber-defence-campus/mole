import binaryninja as bn
import z3
from functools    import reduce
from typing       import Callable, List, Optional, Set, Tuple
from ..common.log import Logger

# TODO:
# - Cleanup functions/variables starting with `_`

class MediumLevelILInstructionVisitor:
    """
    Base class for visiting MLIL instructions.
    """

    def __init__(self, bv: bn.BinaryView, tag: str = "Visitor") \
        -> None:
        self._bv = bv
        self._tag = tag
        self._bn_exprs = {}
        self._bn_exprs_bde = {}
        self._z3_solver = z3.Solver()
        return
    
    def _get_instr_info(
            self,
            bn_expr: bn.MediumLevelILInstruction
        ) -> str:
        """
        Returns a string with information about the `bn_expr` instruction.
        """
        return f"0x{bn_expr.instr.address:x} {str(bn_expr):s} {str(bn_expr.branch_dependence):s}"

    # def _visit(self, bn_expr: bn.MediumLevelILInstruction) \
    #     -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
    #     """
    #     Call dedicated visit function based on operation name of expression `expr`.
    #     """
    #     # Expression visited before
    #     if bn_expr in self._bn_exprs:
    #         return self._bn_exprs[bn_expr]
    #     # Call dedicated visit function
    #     o_name = bn_expr.operation.name.lower()
    #     f_name = f"_visit_{o_name:s}"
    #     if hasattr(self, f_name):
    #         self._bn_exprs[bn_expr] = getattr(self, f_name)(bn_expr)
    #         return self._bn_exprs[bn_expr]
    #     # Warn on missing visit function
    #     Logger.warn(self._tag, f"Visit function for operation `{o_name:s}` not implemented")
    #     return (None, None)
    
    def _visit(
            self,
            bn_expr: bn.MediumLevelILInstruction
        ) -> Optional[z3.ExprRef]:
        """
        Call dedicated visit function based on the operation name of expression `bn_expr`.
        """
        # Expression visited before
        if bn_expr in self._bn_exprs:
            return self._bn_exprs[bn_expr]
        # Call dedicated visit functions
        o_name = bn_expr.operation.name.lower()
        f_name = f"_visit_{o_name:s}"
        if hasattr(self, f_name):
            self._bn_exprs[bn_expr] = getattr(self, f_name)(bn_expr)
            return self._bn_exprs[bn_expr]
        # Warn on missing visit function
        Logger.warn(self._tag, f"Visit function `{f_name:s}` not implemented")
        return None
    
    def _visit_bde(
            self,
            bn_expr: bn.MediumLevelILInstruction
        ) -> List[Optional[z3.BoolRef]]:
        """
        Call dedicated visit function based on the operation name of expression `bn_expr`.
        """
        # Expression visited before
        if bn_expr in self._bn_exprs_bde:
            return self._bn_exprs_bde[bn_expr]
        # Call dedicated visit functions
        o_name = bn_expr.operation.name.lower()
        f_name = f"_visit_bde_{o_name:s}"
        if hasattr(self, f_name):
            self._bn_exprs_bde[bn_expr] = getattr(self, f_name)(bn_expr)
            return self._bn_exprs_bde[bn_expr]
        # Warn on missing visit function
        Logger.warn(self._tag, f"Visit function `{f_name:s}` not implemented")
        return []
    
    # def _new_visit_bde(
    #         self,
    #         bn_expr: bn.MediumLevelILInstruction
    # ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Call dedicated visit function based on the operation name of expression `bn_expr`.
    #     """
    #     # Expression visited before
    #     if bn_expr in self._bn_exprs_bde:
    #         return self._bn_exprs_bde[bn_expr]
    #     # Call dedicated visit functions
    #     o_name = bn_expr.operation.name.lower()
    #     f_name = f"_new_visit_bde_{o_name:s}"
    #     if hasattr(self, f_name):
    #         self._bn_exprs_bde[bn_expr] = getattr(self, f_name)(bn_expr)
    #         return self._bn_exprs_bde[bn_expr]
    #     # Warn on missing visit function
    #     Logger.warn(self._tag, f"Visit function `{f_name:s}` not implemented")
    #     return (None, set())
    
    # def _visit_brn(
    #         self,
    #         bn_expr: bn.MediumLevelILInstruction
    #     ) -> Optional[z3.BoolRef]:
    #     """
    #     Call dedicated branch dependence visit function based on the operation name of expression
    #     `bn_expr`.
    #     """
    #     # Expression visited before
    #     if bn_expr in self._bn_brn_exprs:
    #         return self._bn_brn_exprs[bn_expr]
    #     # Call dedicated visit functions
    #     o_name = bn_expr.operation.name.lower()
    #     f_name = f"_visit_brn_{o_name:s}"
    #     if hasattr(self, f_name):
    #         self._bn_brn_exprs[bn_expr] = getattr(self, f_name)(bn_expr)
    #         return self._bn_brn_exprs[bn_expr]
    #     # Warn on missing visit function
    #     Logger.warn(self._tag, f"Visit function `{f_name:s}` not implemented")
    #     return None


class MediumLevelILVarSsaVisitor(MediumLevelILInstructionVisitor):
    """
    """

    def __init__(self, bv: bn.BinaryView, tag: str = "Modeler") \
        -> None:
        super().__init__(bv, tag)
        self._z3_exprs = {}
        self._z3_var_csts = {}
        return
    
    def _reduce(
            self,
            operation: Callable[[z3.BoolRef, z3.BoolRef], z3.BoolRef],
            operands: List[Optional[z3.BoolRef]]
        ) -> Optional[z3.BoolRef]:
        """
        Reduce all `operands` with `operation`. An `operand` may be `None`.
        """
        result = None
        for operand in operands:
            if operand is None:
                continue
            if result is None:
                result = operand
                continue
            result = operation(result, operand)
        return result
    
    def _create_z3_expression(
            self,
            bn_var: bn.SSAVariable,
            name: str = None
        ) -> Optional[z3.ExprRef]:
        """
        Create a Z3 expression for the variable `bn_var`.
        """
        if not name:
            name = f"{bn_var.name:s}#{bn_var.version:d}"
        if name not in self._z3_exprs:
            if isinstance(bn_var.type, bn.BoolType):
                self._z3_exprs[name] = z3.Bool(name)
            elif isinstance(bn_var.type, bn.IntegerType) or isinstance(bn_var.type, bn.PointerType):
                size = bn_var.type.width
                self._z3_exprs[name] = z3.BitVec(name, size*8)
            else:
                Logger.warn(self._tag, f"Variable type `{str(bn_var.type):s}` not implemented")
                self._z3_exprs[name] = None
        return self._z3_exprs[name]
    
    # def _get_branch_dependencies(
    #         self,
    #         bn_expr: bn.MediumLevelILInstruction
    #     ) -> Optional[z3.BoolRef]:
    #     """
    #     Get all branch dependencies of expression `bn_expr`.
    #     """
    #     # Collect branch dependencies
    #     z3_brn_cnst = []
    #     for instr_index, branch in bn_expr.branch_dependence.items():
    #         bn_expr = self._bn_func[instr_index]
    #         z3_expr, z3_expr_brn = self._visit(bn_expr)
    #         if z3_expr is None: continue
    #         if branch.value == bn.ILBranchDependence.TrueBranchDependent:
    #             z3_brn_cnst.append(self._reduce(z3.And, [z3_expr == True, z3_expr_brn]))
    #         elif branch.value == bn.ILBranchDependence.FalseBranchDependent:
    #             z3_brn_cnst.append(self._reduce(z3.And, [z3_expr == False, z3_expr_brn]))
    #         elif z3_expr_brn is not None:
    #             z3_brn_cnst.append(z3_expr_brn)
    #     # No branch dependencies
    #     if not z3_brn_cnst: return None
    #     # And-reduce branch dependencies
    #     return reduce(
    #         lambda i, j: z3.And(i, j),
    #         z3_brn_cnst
    #     )

    def _get_branch_dependencies(
            self,
            bn_expr: bn.MediumLevelILInstruction
        ) -> List[Optional[z3.BoolRef]]:
        """
        Get all branch dependencies of expression `bn_expr`.
        """
        # Collect branch dependencies
        z3_brn_bdes = []
        for instr_index, branch in bn_expr.branch_dependence.items():
            bn_brn = bn_expr.function[instr_index]
            # TODO:
            z3_brn = self._visit(bn_brn)
            z3_brn_cst = self._z3_var_csts.get(z3_brn, None)
            z3_brn_bde = self._visit_bde(bn_brn)
            if z3_brn is None: continue
            if branch.value == bn.ILBranchDependence.TrueBranchDependent:
                z3_brn_bdes.append(self._reduce(z3.And, [z3_brn == True, z3_brn_cst] + z3_brn_bde))
            elif branch.value == bn.ILBranchDependence.FalseBranchDependent:
                z3_brn_bdes.append(self._reduce(z3.And, [z3_brn == False, z3_brn_cst] + z3_brn_bde))
        # No branch dependencies
        if not z3_brn_bdes: return []
        # And-reduce branch dependencies
        return z3_brn_bdes
    
    # def _new_get_branch_dependencies(
    #         self,
    #         bn_expr: bn.MediumLevelILInstruction
    #     ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Get all branch dependencies of expression `bn_expr`.
    #     """
    #     # Collect branch dependencies
    #     z3_brn_bdes = []
    #     bd_brn_bdes = set()
    #     for instr_index, branch in bn_expr.branch_dependence.items():
    #         bn_brn = bn_expr.function[instr_index]
    #         z3_brn = self._visit(bn_brn)
    #         z3_brn_bde, bd_brn_bde = self._new_visit_bde(bn_brn)
    #         if z3_brn is not None:
    #             if branch.value == bn.ILBranchDependence.TrueBranchDependent:
    #                 z3_brn_bdes.append(self._reduce(z3.And, [z3_brn == True, z3_brn_bde]))
    #             elif branch.value == bn.ILBranchDependence.FalseBranchDependent:
    #                 z3_brn_bdes.append(self._reduce(z3.And, [z3_brn == False, z3_brn_bde]))
    #         bd_brn_bdes.add(branch)
    #         bd_brn_bdes.update(bd_brn_bde)
    #     # And-reduce branch dependencies
    #     return (self._reduce(z3.And, z3_brn_bdes), bd_brn_bdes)
    
    def _find_basic_block(
            self,
            bn_expr: bn.MediumLevelILInstruction
    ) -> Optional[bn.MediumLevelILBasicBlock]:
        """
        Return the basic block containing instruction `bn_expr`.
        """
        bn_func = bn_expr.function
        for basic_block in bn_func.basic_blocks:
            if bn_expr in basic_block:
                return basic_block
        return None

    def _find_paths(
            self,
            bb_crr: bn.MediumLevelILBasicBlock,
            bb_end: bn.MediumLevelILBasicBlock,
            bb_paths: List[List[bn.MediumLevelILBasicBlock]],
            ed_paths: List[List[bn.BasicBlockEdge]],
            bb_path: List[bn.MediumLevelILBasicBlock] = [],
            ed_path: List[bn.BasicBlockEdge] = [],
            in_edge: bn.BasicBlockEdge = None
    ) -> None:
        """
        Find all acyclic paths from basic block `bb_crr` to `bb_end`.
        """
        bb_path.append(bb_crr)
        ed_path.append(in_edge)
        if bb_crr == bb_end:
            bb_paths.append(list(bb_path))
            ed_paths.append(list(ed_path))
        else:
            for out_edge in bb_crr.outgoing_edges:
                # Avoid cycles
                if out_edge.target not in bb_path:
                    self._find_paths(out_edge.target, bb_end, bb_paths, ed_paths, bb_path, ed_path, out_edge)
        bb_path.pop()
        ed_path.pop()
        return
    
    # def _visit_var_ssa_definition(self, bn_var: bn.SSAVariable, bn_fun: bn.MediumLevelILFunction) \
    #     -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
    #     """
    #     Visit the expression defining the variable `bn_var` (backward slice).
    #     """
    #     bn_def_expr = bn_fun.get_ssa_var_definition(bn_var)
    #     if bn_def_expr is None:
    #         return (self._create_z3_expression(bn_var), None)
    #     return self._visit(bn_def_expr)
    
    def _visit_var_ssa_definition(
            self,
            bn_var: bn.SSAVariable,
            bn_fun: bn.MediumLevelILFunction
        ) -> Optional[z3.ExprRef]:
        """
        Visit the expression defining the variable `bn_var` (backward slice).
        """
        bn_expr = bn_fun.get_ssa_var_definition(bn_var)
        if bn_expr is None:
            return self._create_z3_expression(bn_var)
        return self._visit(bn_expr)
    
    def _visit_bde_var_ssa_definition(
            self,
            bn_var: bn.SSAVariable,
            bn_fun: bn.MediumLevelILFunction
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit the branch dependencies of the expression defining the variable `bn_var` (backward
        slice).
        """
        bn_expr = bn_fun.get_ssa_var_definition(bn_var)
        if bn_expr is None:
            return []
        return self._visit_bde(bn_expr)
    
    # def _new_visit_bde_var_ssa_definition(
    #         self,
    #         bn_var: bn.SSAVariable,
    #         bn_fun: bn.MediumLevelILFunction
    #     ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Visit the branch dependencies of the expression defining the variable `bn_var` (backward
    #     slice).
    #     """
    #     bn_expr = bn_fun.get_ssa_var_definition(bn_var)
    #     if bn_expr is None:
    #         return (None, None)
    #     return self._new_visit_bde(bn_expr)
    
    def _visit_bde_mlil_address_of(
            self,
            bn_expr: bn.MediumLevelILAddressOf
    ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILAddressOf` expression `bn_expr`.
        """
        return self._get_branch_dependencies(bn_expr)
    
    # def _new_visit_bde_mlil_address_of(
    #         self,
    #         bn_expr: bn.MediumLevelILAddressOf
    # ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Visit branch dependencies of `MediumLevelILAddressOf` expression `bn_expr`.
    #     """
    #     return self._new_get_branch_dependencies(bn_expr)
    
    # def _visit_brn_var_ssa_definition(
    #         self,
    #         bn_var: bn.SSAVariable,
    #         bn_fun: bn.MediumLevelILFunction
    #     ) -> Optional[z3.BoolRef]:
    #     """
    #     Visit the branch dependencies of the expression defining the variable `bn_var` (backward
    #     slice).
    #     """
    #     bn_var_def = bn_fun.get_ssa_var_definition(bn_var)
    #     if bn_var_def is None:
    #         return None
    #     return self._visit_brn(bn_var_def)
    
    # def _visit_mlil_call_ssa(self, bn_expr: bn.MediumLevelILCallSsa) \
    #     -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
    #     """
    #     Visit expressions of type `MediumLevelILCallSsa`.
    #     """
    #     # Log assigning expression (SSA)
    #     Logger.debug(self._tag, f"0x{bn_expr.instr.address:x} {str(bn_expr):s} (MLIL_CALL_SSA)")
    #     # Current expression's constraints
    #     if len(bn_expr.output) == 0:
    #         z3_dest = None
    #     elif len(bn_expr.output) == 1:
    #         z3_dest = self._create_z3_expression(bn_expr.output[0])
    #     else:
    #         # TODO: Support more than 1 output
    #         z3_dest = None
    #         Logger.warn(self._tag, f"0x{bn_expr.instr.address:x} More than 1 output not supported (MLIL_CALL_SSA)")
    #     z3_cal_brn = self._get_branch_dependencies(bn_expr)
    #     return (z3_dest, z3_cal_brn)

    # def _visit_mlil_call_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILCallSsa
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     Visit `MediumLevelILCallSsa` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CALL_SSA)")
    #     # New Z3 expression for the desination
    #     if len(bn_expr.output) <= 0:
    #         z3_dest = None
    #     elif len(bn_expr.output) == 1:
    #         z3_dest = self._create_z3_expression(bn_expr.output[0])
    #     else:
    #         # TODO: Support more than 1 output
    #         z3_dest = None
    #         Logger.warn(self._tag, f"0x{bn_expr.instr.address:x} More than 1 output not supported (MLIL_CALL_SSA)")
    #     return z3_dest
    
    # def _visit_brn_mlil_call_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILCallSsa
    #     ) -> Optional[z3.BoolRef]:
    #     """
    #     Visit branch dependencies of `MediumLevelILCallSsa` expression `bn_expr`.
    #     """
    #     # Branch dependencies of the current expression
    #     z3_crr = self._get_branch_dependencies(bn_expr)
    #     return z3_crr
    
    # def _new_visit_mlil_call_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILCallSsa
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     TODO: Visit `MediumLevelILCallSsa` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CALL_SSA)")
    #     # New Z3 expression for the desination
    #     if len(bn_expr.output) <= 0:
    #         z3_dest = None
    #     elif len(bn_expr.output) == 1:
    #         z3_dest = self._create_z3_expression(bn_expr.output[0])
    #     else:
    #         # TODO: Support more than 1 output
    #         z3_dest = None
    #         Logger.warn(self._tag, f"0x{bn_expr.instr.address:x} More than 1 output not supported (MLIL_CALL_SSA)")
    #     # Branch dependencies of the current expression
    #     z3_crr_cst = self._get_branch_dependencies(bn_expr)
    #     # Constrain the model
    #     if z3_dest is not None and z3_crr_cst is not None:
    #         self._z3_var_csts[z3_dest] = z3.simplify(z3_crr_cst)
    #     return z3_dest
    
    def _visit_mlil_call_ssa(
            self,
            bn_expr: bn.MediumLevelILCallSsa
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILCallSsa` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CALL_SSA)")
        # TODO: Branch dependencies
        # z3_bdes = self._visit_bde_mlil_call_ssa(bn_expr)
        z3_bde = self._reduce(z3.Or, self._visit_bde(bn_expr))
        # New Z3 expression for the desination
        if len(bn_expr.output) <= 0:
            z3_dest = None
            z3_src = None
        elif len(bn_expr.output) == 1:
            bn_var = bn_expr.output[0]
            z3_dest = self._create_z3_expression(bn_var)
            z3_src = self._create_z3_expression(bn_var, name=f"call_ssa#{bn_expr.instr_index:d}")
        else:
            # TODO: Support more than 1 output
            z3_dest = None
            z3_src = None
            Logger.warn(    self._tag, f"0x{bn_expr.instr.address:x} More than 1 output not supported (MLIL_CALL_SSA)")
        z3_src_cst = self._z3_var_csts.get(z3_src, None)
        # # Constrain the model
        if z3_dest is not None and z3_src is not None:
            self._z3_var_csts[z3_dest] = z3.simplify(self._reduce(z3.And, [z3_dest == z3_src, z3_src_cst, z3_bde]))
        return z3_dest
    
    def _visit_bde_mlil_call_ssa(
            self,
            bn_expr: bn.MediumLevelILCallSsa
        ) -> List[Optional[z3.BoolRef]]:
        """ 
        Visit branch dependencies of `MediumLevelILCallSsa` expression `bn_expr`.
        """
        z3_crr_bde = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_par_bdes = [z3_crr_bde]
        for param in bn_expr.params:
            z3_par_bde = self._reduce(z3.And, self._visit_bde(param))
            z3_par_bdes.append(z3_par_bde)
        return z3_par_bdes
    
    # def _new_visit_bde_mlil_call_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILCallSsa
    #     ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Visit branch dependencies of `MediumLevelILCallSsa` expression `bn_expr`.
    #     """
    #     z3_crr, bd_crr = self._new_get_branch_dependencies(bn_expr)
    #     z3_pars = [z3_crr]
    #     bd_pars = set()
    #     for param in bn_expr.params:
    #         z3_par, bd_par = self._new_visit_bde(param)
    #         z3_pars.append(z3_par)
    #         bd_pars.update(bd_par)
    #     return (self._reduce(z3.And, z3_pars), bd_pars)
    
    # def _visit_mlil_cmp_sge(self, bn_expr: bn.MediumLevelILCmpSge) \
    #     -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
    #     """
    #     Visit expressions of type `MediumLevelILCmpSge`.
    #     """
    #     # Visit child expressions
    #     z3_lft, z3_lft_brn = self._visit(bn_expr.left)
    #     z3_rgt, z3_rgt_brn = self._visit(bn_expr.right)
    #     # Current expression's constraints
    #     # TODO: Check for None in other functions also
    #     if z3_lft is not None and z3_rgt is not None:
    #         z3_sge = z3_lft >= z3_rgt
    #     else:
    #         z3_sge = None
    #     z3_sge_brn = self._reduce(
    #         z3.And, [
    #             self._get_branch_dependencies(bn_expr),
    #             z3_lft_brn,
    #             z3_rgt_brn
    #         ])
    #     return (z3_sge, z3_sge_brn)

    # def _visit_mlil_cmp_sge(
    #         self,
    #         bn_expr: bn.MediumLevelILCmpSge
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     Visit `MediumLevelILCmpSge` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_SGE)")
    #     # Visit the expression's child expressions
    #     z3_lft = self._visit(bn_expr.left)
    #     z3_rgt = self._visit(bn_expr.right)
    #     if z3_lft is None or z3_rgt is None:
    #         z3_sge = None
    #     else:
    #         z3_sge = z3_lft >= z3_rgt
    #     return z3_sge
    
    # def _visit_brn_mlil_cmp_sge(
    #         self,
    #         bn_expr: bn.MediumLevelILCmpSge
    #     ) -> Optional[z3.BoolRef]:
    #     """
    #     Visit branch dependencies of `MediumLevelILCmpSge` expression `bn_expr`.
    #     """
    #     # Branch dependencies of the current expression
    #     z3_crr = self._get_branch_dependencies(bn_expr)
    #     # Branch dependencies of the child expressions
    #     z3_lft = self._visit_brn(bn_expr.left)
    #     z3_rgt = self._visit_brn(bn_expr.right)
    #     return self._reduce(z3.And, [z3_crr, z3_lft, z3_rgt])
    
    # def _new_visit_mlil_cmp_sge(
    #         self,
    #         bn_expr: bn.MediumLevelILCmpSge
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     TODO: Visit `MediumLevelILCmpSge` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_SGE)")
    #     # Visit the expression's child expressions
    #     z3_lft = self._visit(bn_expr.left)
    #     z3_rgt = self._visit(bn_expr.right)
    #     if z3_lft is None or z3_rgt is None:
    #         z3_sge = None
    #     else:
    #         z3_sge = z3_lft >= z3_rgt
    #     return z3_sge
    
    def _visit_mlil_cmp_sge(
            self,
            bn_expr: bn.MediumLevelILCmpSge
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILCmpSge` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_SGE)")
        # Visit the expression's child expressions
        z3_lft = self._visit(bn_expr.left)
        z3_rgt = self._visit(bn_expr.right)
        if z3_lft is None or z3_rgt is None:
            z3_sge = None
        else:
            z3_sge = z3_lft >= z3_rgt
        return z3_sge
    
    def _visit_bde_mlil_cmp_sge(
            self,
            bn_expr: bn.MediumLevelILCmpSge
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILCmpSge` expression `bn_expr`.
        """
        z3_crr_bde = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_lft_bde = self._reduce(z3.And, self._visit_bde(bn_expr.left))
        z3_rgt_bde = self._reduce(z3.And, self._visit_bde(bn_expr.right))
        return [z3_crr_bde, z3_lft_bde, z3_rgt_bde]
    
    # def _new_visit_bde_mlil_cmp_sge(
    #         self,
    #         bn_expr: bn.MediumLevelILCmpSge
    #     ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Visit branch dependencies of `MediumLevelILCmpSge` expression `bn_expr`.
    #     """
    #     z3_crr, bd_crr = self._new_get_branch_dependencies(bn_expr)
    #     z3_lft, bd_lft = self._new_visit_bde(bn_expr.left)
    #     z3_rgt, bd_rgt = self._new_visit_bde(bn_expr.right)
    #     return (self._reduce(z3.And, [z3_crr, z3_lft, z3_rgt]), bd_crr.union(bd_lft).union(bd_rgt))
    
    # def _visit_mlil_cmp_ugt(self, bn_expr: bn.MediumLevelILCmpUgt) \
    #     -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
    #     """
    #     Visit expressions of type `MediumLevelILCmpUgt`.
    #     """
    #     # Visit child expressions
    #     z3_lft, z3_lft_brn = self._visit(bn_expr.left)
    #     z3_rgt, z3_rgt_brn = self._visit(bn_expr.right)
    #     # Current expression's constraints
    #     if z3_lft is not None and z3_rgt is not None:
    #         z3_ugt = z3.UGT(z3_lft, z3_rgt)
    #     else:
    #         z3_ugt = None
    #     z3_ugt_brn = self._reduce(
    #         z3.And, [
    #             self._get_branch_dependencies(bn_expr),
    #             z3_lft_brn,
    #             z3_rgt_brn
    #         ])
    #     return (z3_ugt, z3_ugt_brn)

    # def _visit_mlil_cmp_ugt(
    #         self,
    #         bn_expr: bn.MediumLevelILCmpUgt
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     Visit `MediumLevelILCmpUgt` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_UGT)")
    #     # Visit the expression's child expressions
    #     z3_lft = self._visit(bn_expr.left)
    #     z3_rgt = self._visit(bn_expr.right)
    #     if z3_lft is None or z3_rgt is None:
    #         z3_ugt = None
    #     else:
    #         z3_ugt = z3.UGT(z3_lft, z3_rgt)
    #     return z3_ugt
    
    # def _visit_brn_mlil_cmp_ugt(
    #         self,
    #         bn_expr: bn.MediumLevelILCmpUgt
    #     ) -> Optional[z3.BoolRef]:
    #     """
    #     Visit branch dependencies of `MediumLevelILCmpUgt` expression `bn_expr`.
    #     """
    #     # Branch dependencies of the current expression
    #     z3_crr = self._get_branch_dependencies(bn_expr)
    #     # Branch dependencies of the child expressions
    #     z3_lft = self._visit_brn(bn_expr.left)
    #     z3_rgt = self._visit_brn(bn_expr.right)
    #     return self._reduce(z3.And, [z3_crr, z3_lft, z3_rgt])
    
    # def _new_visit_mlil_cmp_ugt(
    #         self,
    #         bn_expr: bn.MediumLevelILCmpUgt
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     TODO: Visit `MediumLevelILCmpUgt` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_UGT)")
    #     # Visit the expression's child expressions
    #     z3_lft = self._visit(bn_expr.left)
    #     z3_rgt = self._visit(bn_expr.right)
    #     if z3_lft is None or z3_rgt is None:
    #         z3_ugt = None
    #     else:
    #         z3_ugt = z3.UGT(z3_lft, z3_rgt)
    #     return z3_ugt
    
    def _visit_mlil_cmp_ugt(
            self,
            bn_expr: bn.MediumLevelILCmpUgt
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILCmpUgt` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_UGT)")
        # Visit the expression's child expressions
        z3_lft = self._visit(bn_expr.left)
        z3_rgt = self._visit(bn_expr.right)
        if z3_lft is None or z3_rgt is None:
            z3_ugt = None
        else:
            z3_ugt = z3.UGT(z3_lft, z3_rgt)
        return z3_ugt
    
    def _visit_bde_mlil_cmp_ugt(
            self,
            bn_expr: bn.MediumLevelILCmpUgt
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILCmpUgt` expression `bn_expr`.
        """
        z3_crr_bde = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_lft_bde = self._reduce(z3.And, self._visit_bde(bn_expr.left))
        z3_rgt_bde = self._reduce(z3.And, self._visit_bde(bn_expr.right))
        return [z3_crr_bde, z3_lft_bde, z3_rgt_bde]
    
    # def _new_visit_bde_mlil_cmp_ugt(
    #         self,
    #         bn_expr: bn.MediumLevelILCmpUgt
    #     ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Visit branch dependencies of `MediumLevelILCmpUgt` expression `bn_expr`.
    #     """
    #     z3_crr, bd_crr = self._new_get_branch_dependencies(bn_expr)
    #     z3_lft, bd_lft = self._new_visit_bde(bn_expr.left)
    #     z3_rgt, bd_rgt = self._new_visit_bde(bn_expr.right)
    #     return (self._reduce(z3.And, [z3_crr, z3_lft, z3_rgt]), bd_crr.union(bd_lft).union(bd_rgt))
    
    # def _visit_mlil_cmp_ule(self, bn_expr: bn.MediumLevelILCmpUle) \
    #     -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
    #     """
    #     Visit expressions of type `MediumLevelILCmpUle`.
    #     """
    #     # Visit child expressions
    #     z3_lft, z3_lft_brn = self._visit(bn_expr.left)
    #     z3_rgt, z3_rgt_brn = self._visit(bn_expr.right)
    #     # Current expression's constraints
    #     if z3_lft is not None and z3_rgt is not None:
    #         z3_ule = z3.ULE(z3_lft, z3_rgt)
    #     else:
    #         z3_ule = None
    #     z3_ule_brn = self._reduce(
    #         z3.And, [
    #             self._get_branch_dependencies(bn_expr),
    #             z3_lft_brn,
    #             z3_rgt_brn
    #         ])
    #     return (z3_ule, z3_ule_brn)

    # def _visit_mlil_cmp_ule(
    #         self,
    #         bn_expr: bn.MediumLevelILCmpUle
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     Visit `MediumLevelILCmpUle` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_ULE)")
    #     # Visit the expression's child expressions
    #     z3_lft = self._visit(bn_expr.left)
    #     z3_rgt = self._visit(bn_expr.right)
    #     if z3_lft is None or z3_rgt is None:
    #         z3_ule = None
    #     else:
    #         z3_ule = z3.ULE(z3_lft, z3_rgt)
    #     return z3_ule
    
    # def _visit_brn_mlil_cmp_ule(
    #         self,
    #         bn_expr: bn.MediumLevelILCmpUle
    #     ) -> Optional[z3.BoolRef]:
    #     """
    #     Visit branch dependencies of `MediumLevelILCmpUle` expression `bn_expr`.
    #     """
    #     # Branch dependencies of the current expression
    #     z3_crr = self._get_branch_dependencies(bn_expr)
    #     # Branch dependencies of the child expressions
    #     z3_lft = self._visit_brn(bn_expr.left)
    #     z3_rgt = self._visit_brn(bn_expr.right)
    #     return self._reduce(z3.And, [z3_crr, z3_lft, z3_rgt])
    
    # def _new_visit_mlil_cmp_ule(
    #         self,
    #         bn_expr: bn.MediumLevelILCmpUle
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     TODO: Visit `MediumLevelILCmpUle` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_ULE)")
    #     # Visit the expression's child expressions
    #     z3_lft = self._visit(bn_expr.left)
    #     z3_rgt = self._visit(bn_expr.right)
    #     if z3_lft is None or z3_rgt is None:
    #         z3_ule = None
    #     else:
    #         z3_ule = z3.ULE(z3_lft, z3_rgt)
    #     return z3_ule
    
    def _visit_mlil_cmp_ule(
            self,
            bn_expr: bn.MediumLevelILCmpUle
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILCmpUle` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_ULE)")
        # Visit the expression's child expressions
        z3_lft = self._visit(bn_expr.left)
        z3_rgt = self._visit(bn_expr.right)
        if z3_lft is None or z3_rgt is None:
            z3_ule = None
        else:
            z3_ule = z3.ULE(z3_lft, z3_rgt)
        return z3_ule
    
    def _visit_bde_mlil_cmp_ule(
            self,
            bn_expr: bn.MediumLevelILCmpUle
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILCmpUle` expression `bn_expr`.
        """
        z3_crr_bde = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_lft_bde = self._reduce(z3.And, self._visit_bde(bn_expr.left))
        z3_rgt_bde = self._reduce(z3.And, self._visit_bde(bn_expr.right))
        return [z3_crr_bde, z3_lft_bde, z3_rgt_bde]
    
    # def _new_visit_bde_mlil_cmp_ule(
    #         self,
    #         bn_expr: bn.MediumLevelILCmpUle
    #     ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Visit branch dependencies of `MediumLevelILCmpUle` expression `bn_expr`.
    #     """
    #     z3_crr, bd_crr = self._new_get_branch_dependencies(bn_expr)
    #     z3_lft, bd_lft = self._new_visit_bde(bn_expr.left)
    #     z3_rgt, bd_rgt = self._new_visit_bde(bn_expr.right)
    #     return (self._reduce(z3.And, [z3_crr, z3_lft, z3_rgt]), bd_crr.union(bd_lft).union(bd_rgt))
    
    # def _visit_mlil_const(self, bn_expr: bn.MediumLevelILConst) \
    #     -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
    #     """
    #     Visit expressions of type `MediumLevelILConst`.
    #     """
    #     # Current expression's constraints
    #     z3_cst = bn_expr.constant
    #     z3_cst_brn = self._get_branch_dependencies(bn_expr)
    #     return (z3_cst, z3_cst_brn)

    # def _visit_mlil_const(
    #         self,
    #         bn_expr: bn.MediumLevelILConst
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     Visit `MediumLevelILConst` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CONST)")
    #     return bn_expr.constant
    
    # def _visit_brn_mlil_const(
    #         self,
    #         bn_expr: bn.MediumLevelILConst
    #     ) -> Optional[z3.BoolRef]:
    #     """
    #     Visit branch dependencies of `MediumLevelILConst` expression `bn_expr`.
    #     """
    #     z3_crr = self._get_branch_dependencies(bn_expr)
    #     return z3_crr
    
    # def _new_visit_mlil_const(
    #         self,
    #         bn_expr: bn.MediumLevelILConst
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     TODO: Visit `MediumLevelILConst` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CONST)")
    #     return bn_expr.constant
    
    def _visit_mlil_const(
            self,
            bn_expr: bn.MediumLevelILConst
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILConst` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CONST)")
        return bn_expr.constant
    
    def _visit_bde_mlil_const(
            self,
            bn_expr: bn.MediumLevelILConst
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILConst` expression `bn_expr`.
        """
        return self._get_branch_dependencies(bn_expr)
    
    # def _new_visit_bde_mlil_const(
    #         self,
    #         bn_expr: bn.MediumLevelILConst
    #     ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Visit branch dependencies of `MediumLevelILConst` expression `bn_expr`.
    #     """
    #     return self._new_get_branch_dependencies(bn_expr)
    
    # def _visit_mlil_if(self, bn_expr: bn.MediumLevelILIf) \
    #     -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
    #     """
    #     Visit expressions of type `MediumLevelILIf`.
    #     """
    #     # Visit condition expression
    #     z3_con, z3_con_brn = self._visit(bn_expr.condition)
    #     # Current expression's constraints
    #     z3_ite = z3_con
    #     z3_ite_brn = self._reduce(
    #         z3.And, [
    #             self._get_branch_dependencies(bn_expr),
    #             z3_con_brn
    #         ])
    #     return (z3_ite, z3_ite_brn)

    # def _visit_mlil_if(
    #         self,
    #         bn_expr: bn.MediumLevelILIf
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     Visit `MediumLevelILIf` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_IF)")
    #     # Visit the expression's `condition` expression
    #     z3_con = self._visit(bn_expr.condition)
    #     return z3_con
    
    # def _visit_brn_mlil_if(
    #         self,
    #         bn_expr: bn.MediumLevelILIf
    #     ) -> Optional[z3.BoolRef]:
    #     """
    #     Visit branch dependencies of `MediumLevelILIf` expression `bn_expr`.
    #     """
    #     # Branch dependencies of the current expression
    #     z3_crr = self._get_branch_dependencies(bn_expr)
    #     # Branch dependencies of the expression's `condition` expression
    #     z3_con = self._visit_brn(bn_expr.condition)
    #     return self._reduce(z3.And, [z3_crr, z3_con])
    
    # def _new_visit_mlil_if(
    #         self,
    #         bn_expr: bn.MediumLevelILIf
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     TODO: Visit `MediumLevelILIf` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_IF)")
    #     # Visit the expression's `condition` expression
    #     z3_con = self._visit(bn_expr.condition)
    #     # bn_expr_true = self._bn_func[bn_expr.true]
    #     # z3_true = self._visit(bn_expr_true)
    #     # z3_csts_true = self._z3_var_csts.get(bn_expr_true, None)

    #     # bn_expr_false = self._bn_func[bn_expr.false]
    #     # z3_false = self._visit(bn_expr_false)
    #     # z3_csts_false = self._z3_var_csts.get(bn_expr_false, None)
    #     return z3_con
    
    def _visit_mlil_if(
            self,
            bn_expr: bn.MediumLevelILIf
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILIf` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_IF)")
        # Visit the expression's `condition` expression
        z3_con = self._visit(bn_expr.condition)
        return z3_con
    
    def _visit_bde_mlil_if(
            self,
            bn_expr: bn.MediumLevelILIf
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILIf` expression `bn_expr`.
        """
        z3_crr_bde = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_cnd_bde = self._reduce(z3.And, self._visit_bde(bn_expr.condition))
        return [z3_crr_bde, z3_cnd_bde]
    
    # def _new_visit_bde_mlil_if(
    #         self,
    #         bn_expr: bn.MediumLevelILIf
    #     ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Visit branch dependencies of `MediumLevelILIf` expression `bn_expr`.
    #     """
    #     z3_crr, bd_crr = self._new_get_branch_dependencies(bn_expr)
    #     z3_cnd, bd_cnd = self._bew_visit_bde(bn_expr.condition)
    #     return (self._reduce(z3.And, [z3_crr, z3_cnd]), bd_crr.union(bd_cnd))
    
    # def _visit_mlil_var_phi(self, bn_expr: bn.MediumLevelILVarPhi) \
    #     -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
    #     """
    #     Visit expressions of type `MediumLevelILVarPhi`.
    #     """
    #     # Log assigning expression (SSA)
    #     Logger.debug(self._tag, f"0x{bn_expr.instr.address:x} {str(bn_expr):s} (MLIL_VAR_PHI)")
    #     # New Z3 expression for the desination
    #     z3_dest = self._create_z3_expression(bn_expr.dest)
    #     # Current expressions's branch constraints
    #     z3_crr_brn = self._get_branch_dependencies(bn_expr)
    #     # Visit src variables
    #     z3_srcs = []
    #     for var in bn_expr.src:
    #         # Visit the expression defining the src variable (backward slice)
    #         z3_def, z3_def_brn = self._visit_var_ssa_definition(var, self._bn_func)
    #         z3_srcs.append((z3_def, z3_def_brn))
    #     # Add constraint to the solver
    #     z3_phi = None
    #     z3_phi_brn = None
    #     for z3_src, z3_src_brn in z3_srcs:
    #         # TODO: Probably the bug is here!
    #         z3_phi = self._reduce(z3.Or, [z3_phi, self._reduce(z3.And, [z3_dest == z3_src, z3_src_brn])])
    #         z3_phi_brn = self._reduce(z3.Or, [z3_phi_brn, self._reduce(z3.And, [z3_crr_brn, z3_src_brn])])
    #     self._z3_solver.add(z3.simplify(z3_phi))
    #     Logger.debug(self._tag, f"0x{bn_expr.instr.address:x} {str(z3_phi):s} (CONSTRAINT)")
    #     return (z3_dest, z3_phi_brn)

    # def _visit_mlil_var_phi(
    #         self,
    #         bn_expr: bn.MediumLevelILVarPhi
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     Visit `MediumLevelILVarPhi` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_VAR_PHI)")
    #     # New Z3 expression for the desination
    #     z3_dest = self._create_z3_expression(bn_expr.dest)
    #     # Visit the expression's `src` variables
    #     z3_srcs = []
    #     for var in bn_expr.src:
    #         z3_src = self._visit_var_ssa_definition(var, self._bn_func)
    #         z3_brn = self._visit_brn_var_ssa_definition(var, self._bn_func)
    #         if z3_dest is None or z3_src is None: continue
    #         z3_cst = self._reduce(z3.And, [z3_dest == z3_src, z3_brn])
    #         z3_srcs.append(z3_cst)
    #     # Constrain the model
    #     if z3_srcs:
    #         self._z3_solver.add(z3.simplify(self._reduce(z3.Or, z3_srcs)))
    #     # Return Z3 expression
    #     return z3_dest
    
    # def _visit_brn_mlil_var_phi(
    #         self,
    #         bn_expr: bn.MediumLevelILVarPhi
    #     ) -> Optional[z3.BoolRef]:
    #     """
    #     Visit branch dependencies of `MediumLevelILVarPhi` expression `bn_expr`.
    #     """
    #     # Branch dependencies of the current expression
    #     z3_crr = self._get_branch_dependencies(bn_expr)
    #     # Branch dependencies of the expression's `src` variables
    #     z3_srcs = []
    #     for var in bn_expr.src:
    #         z3_src = self._visit_brn_var_ssa_definition(var, self._bn_func)
    #         z3_srcs.append(self._reduce(z3.And, [z3_crr, z3_src]))
    #     if not z3_srcs: return None
    #     return self._reduce(z3.Or, z3_srcs)
    
    # def _new_visit_mlil_var_phi(
    #         self,
    #         bn_expr: bn.MediumLevelILVarPhi
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     TODO: Visit `MediumLevelILVarPhi` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_VAR_PHI)")
    #     # New Z3 expression for the desination
    #     z3_dest = self._create_z3_expression(bn_expr.dest)
    #     # Branch dependencies of the current expression
    #     z3_crr_cst = self._get_branch_dependencies(bn_expr)
    #     # Visit the expression's `src` variables
    #     z3_srcs = []
    #     for var in bn_expr.src:
    #         z3_src = self._visit_var_ssa_definition(var, self._bn_func)
    #         z3_src_cst = self._z3_var_csts.get(z3_src, None)
    #         if z3_dest is None or z3_src is None: continue
    #         z3_cst = self._reduce(z3.And, [z3_dest == z3_src, z3_crr_cst, z3_src_cst])
    #         z3_srcs.append(z3_cst)
    #     # Constrain the model
    #     if z3_srcs:
    #         self._z3_var_csts[z3_dest] = z3.simplify(self._reduce(z3.Or, z3_srcs))
    #     # Return Z3 expression
    #     return z3_dest
    
    # def _visit_mlil_var_phi(
    #         self,
    #         bn_expr: bn.MediumLevelILVarPhi
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     Visit `MediumLevelILVarPhi` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_VAR_PHI)")
    #     # TODO: Branch dependencies of the current expression
    #     z3_bde = self._get_branch_dependencies(bn_expr)
    #     # New Z3 expression for the desination
    #     z3_dest = self._create_z3_expression(bn_expr.dest)
    #     # Visit the expression's `src` variables
    #     z3_srcs = []
    #     for var in bn_expr.src:
    #         z3_src = self._visit_var_ssa_definition(var, self._bn_func)
    #         z3_src_cst = None
    #         if z3_src in self._z3_var_csts:
    #             z3_src_cst = self._z3_var_csts.pop(z3_src)
    #         if z3_dest is None or z3_src is None: continue
    #         z3_srcs.append(self._reduce(z3.And, [z3_dest == z3_src, z3_src_cst]))
    #     # Constrain the model
    #     if z3_srcs:
    #         self._z3_var_csts[z3_dest] = z3.simplify(self._reduce(z3.And, [
    #             self._reduce(z3.Or, z3_srcs),
    #             z3_bde
    #         ]))
    #     # Return Z3 expression
    #     return z3_dest

    # def _visit_mlil_var_phi(
    #         self,
    #         bn_expr: bn.MediumLevelILVarPhi
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     Visit `MediumLevelILVarPhi` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_VAR_PHI)")
    #     # TODO: Branch dependencies (WRONG)
    #     z3_bde = self._visit_bde_mlil_var_phi(bn_expr)
    #     # New Z3 expression for the desination
    #     z3_dest = self._create_z3_expression(bn_expr.dest)
    #     # Visit the expression's `src` variables
    #     z3_srcs = []
    #     for var in bn_expr.src:
    #         z3_src = self._visit_var_ssa_definition(var, bn_expr.function)
    #         z3_src_cst = self._z3_var_csts.get(z3_src, None)
    #         if z3_dest is not None and z3_src is not None:
    #             # TODO: z3_bde (WRONG)
    #             z3_srcs.append(self._reduce(z3.And, [z3_dest == z3_src, z3_src_cst, z3_bde]))
    #     # Constrain the model
    #     if z3_srcs:
    #         self._z3_var_csts[z3_dest] = z3.simplify(self._reduce(z3.Or, z3_srcs))
    #     # Return Z3 expression
    #     return z3_dest

    def _visit_mlil_var_phi(
            self,
            bn_expr: bn.MediumLevelILVarPhi
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILVarPhi` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_VAR_PHI)")
        # TODO: Branch dependencies
        # z3_bdes = self._visit_bde_mlil_var_phi(bn_expr)
        z3_bdes = self._visit_bde(bn_expr)
        # New Z3 expression for the desination
        z3_dest = self._create_z3_expression(bn_expr.dest)
        # Visit the expression's `src` variables
        z3_srcs = []
        for var, z3_bde in zip(bn_expr.src, z3_bdes):
            z3_src = self._visit_var_ssa_definition(var, bn_expr.function)
            z3_src_cst = self._z3_var_csts.get(z3_src, None)
            if z3_dest is not None and z3_src is not None:
                z3_srcs.append(self._reduce(z3.And, [z3_dest == z3_src, z3_src_cst, z3_bde]))
        # Constrain the model
        if z3_srcs:
            self._z3_var_csts[z3_dest] = z3.simplify(self._reduce(z3.Or, z3_srcs))
        # Return Z3 expression
        return z3_dest
    
    # def _visit_bde_mlil_var_phi(
    #         self,
    #         bn_expr: bn.MediumLevelILVarPhi
    # ) -> Optional[z3.BoolRef]:
    #     """
    #     Visit branch dependencies of `MediumLevelILVarPhi` expression `bn_expr`.
    #     """
    #     z3_crr_bde = self._get_branch_dependencies(bn_expr)
    #     z3_src_bdes = [z3_crr_bde]
    #     for var in bn_expr.src:
    #         z3_src_bde = self._visit_bde_var_ssa_definition(var, self._bn_func)
    #         z3_src_bdes.append(z3_src_bde)
    #     return self._reduce(z3.And, z3_src_bdes)
    
    # def _visit_bde_mlil_var_phi(
    #         self,
    #         bn_expr: bn.MediumLevelILVarPhi
    # ) -> Optional[z3.BoolRef]:
    #     """
    #     Visit branch dependencies of `MediumLevelILVarPhi` expression `bn_expr`.
    #     """

    #     z3_srcs = []
    #     for var in bn_expr.src:
    #         z3_src = self._visit_bde_var_ssa_definition(var, self._bn_func)
    #         z3_srcs.append(z3_src)
    #     z3_phi = []
    #     for i, z3_src in enumerate(z3_srcs):
    #         z3_noi = z3.Not(self._reduce(z3.Or, z3_srcs[:i] + z3_srcs[i+1:]))
    #         z3_phi.append(self._reduce(z3.And, [z3_srcs[i], z3_noi]))
    #     return self._reduce(z3.Or, z3_phi)
    
    def _visit_bde_mlil_var_phi(
            self,
            bn_expr: bn.MediumLevelILVarPhi
    ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILVarPhi` expression `bn_expr`.
        """
        # Determine relevant basic blocks
        bn_func = bn_expr.function
        bb_var_phi = self._find_basic_block(bn_expr)
        bb_var_phi_srcs = []
        for var in bn_expr.src:
            bn_var_def = bn_func.get_ssa_var_definition(var)
            bb_var_def = self._find_basic_block(bn_var_def)
            bb_var_phi_srcs.append(bb_var_def)
        # Collect path constraints of all phi-sources
        z3_var_phi = []
        for i, var in enumerate(bn_expr.src):
            # Find paths from variable definition to variable usage
            bb_paths = []
            ed_paths = []
            bn_var_def = bn_func.get_ssa_var_definition(var)
            bb_var_def = self._find_basic_block(bn_var_def)
            self._find_paths(bb_var_def, bb_var_phi, bb_paths, ed_paths)
            z3_var_def = self._visit_bde(bn_var_def)
            # Basic blocks of phi-sources other the current one
            bb_var_phi_srcs_wo_i = bb_var_phi_srcs[:i] + bb_var_phi_srcs[i+1:]
            # Collect path constraints of phi-source
            z3_var_phi_src = []
            for bb_path, ed_path in zip(bb_paths, ed_paths):
                # Skip paths that contain other phi-sources (static single assignment)
                ignore = False
                for bb in bb_path:
                    if bb in bb_var_phi_srcs_wo_i:
                        ignore = True
                        break
                if ignore: continue
                # Collect path constraints
                z3_path = z3_var_def
                for in_edge in ed_path:
                    if in_edge is None: continue
                    if in_edge.type == bn.BranchType.TrueBranch:
                        bn_brn_expr = in_edge.source[-1]
                        z3_cond = self._visit(bn_brn_expr)
                        z3_cond_cst = self._z3_var_csts.get(z3_cond, None)
                        z3_path.append(self._reduce(z3.And, [z3_cond == True, z3_cond_cst]))
                    elif in_edge.type == bn.BranchType.FalseBranch:
                        bn_brn_expr = in_edge.source[-1]
                        z3_cond = self._visit(bn_brn_expr)
                        z3_cond_cst = self._z3_var_csts.get(z3_cond, None)
                        z3_path.append(self._reduce(z3.And, [z3_cond == False, z3_cond_cst]))
                z3_var_phi_src.append(self._reduce(z3.And, z3_path))
            z3_var_phi.append(self._reduce(z3.Or, z3_var_phi_src))
        return z3_var_phi

    # def _new_visit_bde_mlil_var_phi(
    #         self,
    #         bn_expr: bn.MediumLevelILVarPhi
    # ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Visit branch dependencies of `MediumLevelILVarPhi` expression `bn_expr`.
    #     """
    #     z3_crr, bd_crr = self._new_get_branch_dependencies(bn_expr)
    #     for var in bn_expr.src:
    #         z3_src, bd_src = self._new_visit_bde_var_ssa_definition(var, self._bn_func)
            

    #     z3_crr, bd_crr = self._new_get_branch_dependencies(bn_expr)
    #     z3_srcs = [z3_crr]
    #     for var in bn_expr.src:
    #         z3_src, bd_src = self._new_visit_bde_var_ssa_definition(var, self._bn_func)
    #         z3_srcs.append(z3_src)
    #         bd_crr.update(bd_src)
    #     bd_crr.difference()

    #     return (self._reduce(z3.And, z3_srcs), )

    #     z3_crr_bde = self._get_branch_dependencies(bn_expr)
    #     z3_src_bdes = [z3_crr_bde]
    #     for var in bn_expr.src:
    #         z3_src_bde = self._visit_bde_var_ssa_definition(var, self._bn_func)
    #         z3_src_bdes.append(z3_src_bde)
    #     return self._reduce(z3.And, z3_src_bdes)

    # def _visit_mlil_set_var_ssa(self, bn_expr: bn.MediumLevelILSetVar) \
    #     -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
    #     """
    #     Visit expressions of type `MediumLevelILSetVar`.
    #     """
    #     # Log assigning expression (SSA)
    #     Logger.debug(self._tag, f"0x{bn_expr.instr.address:x} {str(bn_expr):s} (MLIL_SET_VAR_SSA)")
    #     # New Z3 expression for the desination
    #     z3_dest = self._create_z3_expression(bn_expr.dest)
    #     # Visit src expression
    #     z3_src, z3_src_brn = self._visit(bn_expr.src)
    #     # Get current expression's branch constraints
    #     z3_set_brn = self._reduce(
    #         z3.And, [
    #             self._get_branch_dependencies(bn_expr),
    #             z3_src_brn
    #         ])
    #     # Add constraint to the solver
    #     if z3_dest is not None and z3_src is not None:
    #         constraint = z3_dest == z3_src
    #         if z3_set_brn is not None:
    #             constraint = z3.And(constraint, z3_set_brn)
    #         # TODO: Add `z3.simplify(constraint)` here or somewhere else.
    #         self._z3_solver.add(z3.simplify(constraint))
    #         Logger.debug(self._tag, f"0x{bn_expr.instr.address:x} {str(constraint):s} (CONSTRAINT)")
    #     return (z3_dest, z3_set_brn)

    # def _visit_mlil_set_var_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILSetVar
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     Visit `MediumLevelILSetVar` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_SET_VAR_SSA)")
    #     # New Z3 expression for the desination
    #     z3_dest = self._create_z3_expression(bn_expr.dest)
    #     # Visit the expression's `src` expression
    #     z3_src = self._visit(bn_expr.src)
    #     # Constrain the model
    #     if z3_dest is not None and z3_src is not None:
    #         z3_brn = self._visit_brn(bn_expr)
    #         z3_cst = self._reduce(z3.And, [z3_dest == z3_src, z3_brn])
    #         self._z3_solver.add(z3.simplify(z3_cst))
    #         self._z3_var_csts[z3_dest] = [z3_src, z3_brn]
    #     # Return Z3 expression
    #     return z3_dest
    
    # def _visit_brn_mlil_set_var_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILSetVar
    #     ) -> Optional[z3.BoolRef]:
    #     """
    #     Visit branch dependencies of `MediumLevelILSetVar` expression `bn_expr`.
    #     """
    #     # Branch dependencies of the current expression
    #     z3_crr = self._get_branch_dependencies(bn_expr)
    #     # Branch dependencies of the src expression
    #     z3_src = self._visit_brn(bn_expr.src)
    #     return self._reduce(z3.And, [z3_crr, z3_src])
    
    # def _new_visit_mlil_set_var_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILSetVar
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     TODO: Visit `MediumLevelILSetVar` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_SET_VAR_SSA)")
    #     # New Z3 expression for the desination
    #     z3_dest = self._create_z3_expression(bn_expr.dest)
    #     # Branch dependencies of the current expression
    #     z3_crr_cst = self._get_branch_dependencies(bn_expr)
    #     # Visit the expression's `src` expression
    #     z3_src = self._visit(bn_expr.src)
    #     z3_src_cst = self._z3_var_csts.get(z3_src, None)
    #     # Constrain the model
    #     if z3_dest is not None and z3_src is not None:
    #         z3_cst = self._reduce(z3.And, [z3_dest == z3_src, z3_crr_cst, z3_src_cst])
    #         self._z3_var_csts[z3_dest] = z3.simplify(z3_cst)
    #     return z3_dest
    
    # def _visit_mlil_set_var_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILSetVar
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     Visit `MediumLevelILSetVar` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_SET_VAR_SSA)")
    #     # TODO: Branch dependencies of the current expression
    #     z3_bde = self._get_branch_dependencies(bn_expr)
    #     # New Z3 expression for the desination
    #     z3_dest = self._create_z3_expression(bn_expr.dest)
    #     # Visit the expression's `src` expression
    #     z3_src = self._visit(bn_expr.src)
    #     z3_src_cst = None
    #     if z3_src in self._z3_var_csts:
    #         z3_src_cst = self._z3_var_csts.pop(z3_src)
    #     # Constrain the model
    #     if z3_dest is not None and z3_src is not None:
    #         self._z3_var_csts[z3_dest] = z3.simplify(self._reduce(z3.And, [
    #             z3_dest == z3_src,
    #             z3_src_cst,
    #             z3_bde
    #         ]))
    #     return z3_dest

    def _visit_mlil_set_var_ssa(
            self,
            bn_expr: bn.MediumLevelILSetVar
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILSetVar` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_SET_VAR_SSA)")
        # TODO: Branch dependencies
        # z3_bde = self._visit_bde_mlil_set_var_ssa(bn_expr)
        z3_bde = self._reduce(z3.Or, self._visit_bde(bn_expr))
        # New Z3 expression for the desination
        z3_dest = self._create_z3_expression(bn_expr.dest)
        # Expression's `src` expression
        z3_src = self._visit(bn_expr.src)
        z3_src_cst = self._z3_var_csts.get(z3_src, None)
        # Constrain the model
        if z3_dest is not None and z3_src is not None:
            self._z3_var_csts[z3_dest] = z3.simplify(self._reduce(
                z3.And, [z3_dest == z3_src, z3_src_cst, z3_bde]
            ))
        return z3_dest
    
    def _visit_bde_mlil_set_var_ssa(
            self,
            bn_expr: bn.MediumLevelILSetVar
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILSetVar` expression `bn_expr`.
        """
        z3_crr = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_src = self._reduce(z3.And, self._visit_bde(bn_expr.src))
        return [z3_crr, z3_src]
    
    # def _new_visit_bde_mlil_set_var_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILSetVar
    #     ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Visit branch dependencies of `MediumLevelILSetVar` expression `bn_expr`.
    #     """
    #     z3_crr, bd_crr = self._new_get_branch_dependencies(bn_expr)
    #     z3_src, bd_src = self._new_visit_bde(bn_expr.src)
    #     return (self._reduce(z3.And, [z3_crr, z3_src]), bd_crr.union(bd_src))
    
    # def _visit_mlil_var_ssa(self, bn_expr: bn.MediumLevelILVarSsa) \
    #     -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
    #     """
    #     Visit expressions of type `MediumLevelILVarSsa`.
    #     """
    #     # Visit the expression defining the src variable (backward slice)
    #     z3_def, z3_def_brn = self._visit_var_ssa_definition(bn_expr.src, self._bn_func)
    #     # Get current expression's branch constraints
    #     z3_var_brn = self._reduce(
    #         z3.And, [
    #             self._get_branch_dependencies(bn_expr),
    #             z3_def_brn
    #         ])
    #     return (z3_def, z3_var_brn)
    
    # def _visit_mlil_var_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILVarSsa
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     Visit `MediumLevelILVarSsa` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_VAR_SSA)")
    #     # Expression defining the `src` variable (backward slice)
    #     z3_def = self._visit_var_ssa_definition(bn_expr.src, self._bn_func)
    #     return z3_def
    
    # def _visit_brn_mlil_var_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILVarSsa
    #     ) -> Optional[z3.BoolRef]:
    #     """
    #     Visit branch dependencies of `MediumLevelILVarSsa` expression `bn_expr`.
    #     """
    #     # Branch dependencies of the current expression
    #     z3_crr = self._get_branch_dependencies(bn_expr)
    #     # Branch dependencies of the expression defining the src variable (backward slice)
    #     z3_def = self._visit_brn_var_ssa_definition(bn_expr.src, self._bn_func)
    #     return self._reduce(z3.And, [z3_crr, z3_def])
    
    # def _new_visit_mlil_var_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILVarSsa
    #     ) -> Optional[z3.ExprRef]:
    #     """
    #     TODO: Visit `MediumLevelILVarSsa` expression `bn_expr`.
    #     """
    #     Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_VAR_SSA)")
    #     # Expression defining the `src` variable (backward slice)
    #     z3_src = self._visit_var_ssa_definition(bn_expr.src, self._bn_func)
    #     return z3_src
    
    def _visit_mlil_var_ssa(
            self,
            bn_expr: bn.MediumLevelILVarSsa
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILVarSsa` expression `bn_expr`.
        """
        # Expression defining the `src` variable (backward slice)
        z3_src = self._visit_var_ssa_definition(bn_expr.src, bn_expr.function)
        return z3_src
    
    def _visit_bde_mlil_var_ssa(
            self,
            bn_expr: bn.MediumLevelILVarSsa
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILVarSsa` expression `bn_expr`.
        """
        z3_crr = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_src = self._reduce(z3.And, self._visit_bde_var_ssa_definition(bn_expr.src, bn_expr.function))
        return [z3_crr, z3_src]
    
    # def _new_visit_bde_mlil_var_ssa(
    #         self,
    #         bn_expr: bn.MediumLevelILVarSsa
    #     ) -> Tuple[Optional[z3.BoolRef], Set[bn.ILBranchDependence]]:
    #     """
    #     Visit branch dependencies of `MediumLevelILVarSsa` expression `bn_expr`.
    #     """
    #     z3_crr, bd_crr = self._new_get_branch_dependencies(bn_expr)
    #     z3_src, bd_src = self._new_visit_bde_var_ssa_definition(bn_expr.src, bn_expr.function)
    #     return (self._reduce(z3.And, [z3_crr, z3_src]), bd_crr.union(bd_src))
    
    def model(
            self,
            bn_expr: bn.MediumLevelILVarSsa
        ) -> None:
        """
        """
        z3_n = self._visit(bn_expr)
        # z3_n_bde = self._visit_bde(bn_expr)
        self._z3_solver.add(self._z3_var_csts[z3_n])
        if self._z3_solver.check() == z3.sat:
            print(self._z3_solver.model())
        # self._z3_solver.add(list(self._z3_var_csts.values()))
        # z3_n = self._z3_exprs["r2#3"]
        # self._z3_solver.add(self._z3_var_csts[z3_n])
        # # self._z3_solver.add(z3_n == 0)
        # if self._z3_solver.check():
        #     print(self._z3_solver.model())
        # z3_expr_brn = self._visit_brn(self._bn_expr)
        # for assertion in self._z3_solver.assertions():
        #     print(assertion.sexpr())
        return


# class NewMediumLevelILVarSsaModeler(MediumLevelILInstructionVisitor):
#     """
#     """

#     def __init__(self, bv: BinaryView, expr: MediumLevelILVarSsa, tag: str = "Modeler") -> None:
#         super().__init__(bv, tag)
#         self._bn_expr = expr
#         self._bn_func = expr.function
#         self._cnst = []
#         self._brch = []
#         return
    
#     def _visit_mlil_var_ssa(self, expr: MediumLevelILVarSsa) -> Tuple[ExprRef, ExprRef]:
#         # Visit variable definition (backward slice)
#         return self._visit_var_ssa_definition(expr.src, self._bn_func)
    
#     def model(self) -> None:
#         return self._visit(self._bn_expr)

class NewMediumLevelILInstructionVisitor:
    """
    Base class for visiting MLIL instructions.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "Visitor"
    ) -> None:
        """
        """
        self.bv = bv
        self.tag = tag
        self.bn_exprs = {}
        return
    
    def get_instr_info(
            self,
            bn_expr: bn.MediumLevelILInstruction
        ) -> str:
        """
        Returns a string with information about the `bn_expr` instruction.
        """
        return f"0x{bn_expr.instr.address:x} {str(bn_expr):s}"
    
    def visit_var_ssa_definition(
            self,
            bn_var: bn.SSAVariable,
            bn_func: bn.MediumLevelILFunction
    ) -> Set[bn.SSAVariable]:
        """
        """
        bn_expr = bn_func.get_ssa_var_definition(bn_var)
        if bn_expr is None:
            vs = set()
            for param_var in bn_func.source_function.parameter_vars:
                if param_var == bn_var.var:
                    bn_func_addr = bn_func.llil[0].address
                    for code_ref in self.bv.get_code_refs(bn_func_addr):
                        addr = code_ref.address
                        func = code_ref.function
                        call = func.get_low_level_il_at(addr).medium_level_il
                        vs.update(self.visit(call, func.mlil))
            return vs
        return self.visit(bn_expr, bn_func)
    
    def visit(
            self,
            bn_expr: bn.MediumLevelILInstruction,
            bn_func: bn.MediumLevelILFunction
    ) -> Set[bn.SSAVariable]:
        """
        """
        # Expression visited before
        if bn_expr in self.bn_exprs:
            return self.bn_exprs[bn_expr]
        # Call dedicated visit functions
        o_name = bn_expr.operation.name.lower()
        f_name = f"visit_{o_name:s}"
        if hasattr(self, f_name):
            self.bn_exprs[bn_expr] = getattr(self, f_name)(bn_expr, bn_func)
            return self.bn_exprs[bn_expr]
        # Warn on missing visit function
        Logger.warn(self.tag, f"Visit function `{f_name:s}` not implemented")
        return set()


class NewMediumLevelILVarSsaVisitor(NewMediumLevelILInstructionVisitor):
    """
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "Modeler"
        ) -> None:
        """
        """
        super().__init__(bv, tag)
        return
    
    def visit_mlil_const(
            self,
            bn_expr: bn.MediumLevelILConst,
            bn_func: bn.MediumLevelILFunction
        ) -> Set[bn.SSAVariable]:
        """
        Visit `MediumLevelILConst` expression `bn_expr`.
        """
        return set()
    
    def visit_mlil_var_phi(
            self,
            bn_expr: bn.MediumLevelILVarPhi,
            bn_func: bn.MediumLevelILFunction
        ) -> Set[bn.SSAVariable]:
        """
        Visit `MediumLevelILVarPhi` expression `bn_expr`.
        """
        Logger.debug(self.tag, self.get_instr_info(bn_expr) + " (MLIL_VAR_PHI)")
        vs = set([bn_expr.dest])
        for var in bn_expr.src:
            vs.update(self.visit_var_ssa_definition(var, bn_func))
        return vs
    
    def visit_mlil_set_var_ssa(
            self,
            bn_expr: bn.MediumLevelILSetVar,
            bn_func: bn.MediumLevelILFunction
        ) -> Set[bn.SSAVariable]:
        """
        Visit `MediumLevelILSetVar` expression `bn_expr`.
        """
        Logger.debug(self.tag, self.get_instr_info(bn_expr) + " (MLIL_SET_VAR_SSA)")
        vs = set([bn_expr.dest])
        vs.update(self.visit(bn_expr.src, bn_func))
        return vs
    
    def visit_mlil_var_ssa(
            self,
            bn_expr: bn.MediumLevelILVarSsa,
            bn_func: bn.MediumLevelILFunction
        ) -> Set[bn.SSAVariable]:
        """
        Visit `MediumLevelILVarSsa` expression `bn_expr`.
        """
        Logger.debug(self.tag, self.get_instr_info(bn_expr) + " (MLIL_VAR_SSA)")
        return self.visit_var_ssa_definition(bn_expr.src, bn_func)
    
    def slice_backwards(
            self,
            bn_expr: bn.MediumLevelILVarSsa
    ) -> Set[bn.SSAVariable]:
        """
        """
        return self.visit(bn_expr, bn_expr.function)
