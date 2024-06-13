import binaryninja as bn
import z3
from functools    import reduce
from typing       import Callable, List, Optional, Tuple
from ..common.log import Logger


class NewMediumLevelILInstructionVisitor:
    """
    Base class for visiting MLIL instructions.
    """

    def __init__(self, bv: bn.BinaryView, tag: str = "Visitor") \
        -> None:
        self._bv = bv
        self._tag = tag
        self._bn_exprs = {}
        self._z3_solver = z3.Solver()
        return
    
    def _visit(self, bn_expr: bn.MediumLevelILInstruction) \
        -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
        """
        Call dedicated visit function based on operation name of expression `expr`.
        """
        # Expression visited before
        if bn_expr in self._bn_exprs:
            return self._bn_exprs[bn_expr]
        # Call dedicated visit function
        o_name = bn_expr.operation.name.lower()
        f_name = f"_visit_{o_name:s}"
        if hasattr(self, f_name):
            self._bn_exprs[bn_expr] = getattr(self, f_name)(bn_expr)
            return self._bn_exprs[bn_expr]
        # Warn on missing visit function
        Logger.warn(self._tag, f"Visit function for operation `{o_name:s}` not implemented")
        return (None, None)


class MediumLevelILVarSsaVisitor(NewMediumLevelILInstructionVisitor):
    """
    """

    def __init__(self, bv: bn.BinaryView, bn_expr: bn.MediumLevelILVarSsa, tag: str = "Modeler") \
        -> None:
        super().__init__(bv, tag)
        self._bn_expr = bn_expr
        self._bn_func = bn_expr.function
        self._z3_exprs = {}
        return
    
    # def _and(self, z3_cnsts: List[Optional[z3.BoolRef]]) \
    #     -> Optional[z3.BoolRef]:
    #     """
    #     Create the conjunction of all constraints in list `z3_cnsts`.
    #     """
    #     z3_c = None
    #     for z3_cnst in z3_cnsts:
    #         if z3_cnst is None:
    #             continue
    #         if z3_c is None:
    #             z3_c = z3_cnst
    #             continue
    #         z3_c = z3.And(z3_c, z3_cnst)
    #     return z3_c
    
    def _reduce(self,
                operation: Callable[[z3.BoolRef, z3.BoolRef], z3.BoolRef],
                operands: List[Optional[z3.BoolRef]]) \
                    -> Optional[z3.BoolRef]:
        """
        Reduce all `operands` with operation `operation`. An `operand` may be `None`.
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
    
    def _create_z3_expression(self, bn_var: bn.SSAVariable) \
        -> Optional[z3.ExprRef]:
        """
        Create a Z3 expression for the variable `var`.
        """
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
    
    def _get_branch_constraints(self, bn_expr: bn.MediumLevelILInstruction) \
        -> Optional[z3.BoolRef]:
        """
        Get all branch constraints of expression `bn_expr`.
        """
        # Collect branch dependencies
        z3_brn_cnst = []
        for instr_index, branch in bn_expr.branch_dependence.items():
            bn_expr = self._bn_func[instr_index]
            z3_expr, z3_expr_brn = self._visit(bn_expr)
            if z3_expr is None: continue
            if branch.value == bn.ILBranchDependence.TrueBranchDependent:
                z3_brn_cnst.append(self._reduce(z3.And, [z3_expr == True, z3_expr_brn]))
            elif branch.value == bn.ILBranchDependence.FalseBranchDependent:
                z3_brn_cnst.append(self._reduce(z3.And, [z3_expr == False, z3_expr_brn]))
            elif z3_expr_brn is not None:
                z3_brn_cnst.append(z3_expr_brn)
        # No branch dependencies
        if not z3_brn_cnst: return None
        # And-reduce branch dependencies
        return reduce(
            lambda i, j: z3.And(i, j),
            z3_brn_cnst
        )
    
    def _visit_var_ssa_definition(self, bn_var: bn.SSAVariable, bn_fun: bn.MediumLevelILFunction) \
        -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
        """
        Visit the expression defining the variable `bn_var` (backward slice).
        """
        bn_def_expr = bn_fun.get_ssa_var_definition(bn_var)
        if bn_def_expr is None:
            return (self._create_z3_expression(bn_var), None)
        return self._visit(bn_def_expr)
    
    def _visit_mlil_call_ssa(self, bn_expr: bn.MediumLevelILCallSsa) \
        -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
        """
        Visit expressions of type `MediumLevelILCallSsa`.
        """
        # Log assigning expression (SSA)
        Logger.debug(self._tag, f"0x{bn_expr.instr.address:x} {str(bn_expr):s} (MLIL_CALL_SSA)")
        # Current expression's constraints
        if len(bn_expr.output) == 0:
            z3_dest = None
        elif len(bn_expr.output) == 1:
            z3_dest = self._create_z3_expression(bn_expr.output[0])
        else:
            # TODO: Support more than 1 output
            z3_dest = None
            Logger.warn(self._tag, f"0x{bn_expr.instr.address:x} More than 1 output not supported (MLIL_CALL_SSA)")
        z3_cal_brn = self._get_branch_constraints(bn_expr)
        return (z3_dest, z3_cal_brn)
    
    def _visit_mlil_cmp_sge(self, bn_expr: bn.MediumLevelILCmpSge) \
        -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
        """
        Visit expressions of type `MediumLevelILCmpSge`.
        """
        # Visit child expressions
        z3_lft, z3_lft_brn = self._visit(bn_expr.left)
        z3_rgt, z3_rgt_brn = self._visit(bn_expr.right)
        # Current expression's constraints
        # TODO: Check for None in other functions also
        if z3_lft is not None and z3_rgt is not None:
            z3_sge = z3_lft >= z3_rgt
        else:
            z3_sge = None
        z3_sge_brn = self._reduce(
            z3.And, [
                self._get_branch_constraints(bn_expr),
                z3_lft_brn,
                z3_rgt_brn
            ])
        return (z3_sge, z3_sge_brn)
    
    def _visit_mlil_cmp_ugt(self, bn_expr: bn.MediumLevelILCmpUgt) \
        -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
        """
        Visit expressions of type `MediumLevelILCmpUgt`.
        """
        # Visit child expressions
        z3_lft, z3_lft_brn = self._visit(bn_expr.left)
        z3_rgt, z3_rgt_brn = self._visit(bn_expr.right)
        # Current expression's constraints
        if z3_lft is not None and z3_rgt is not None:
            z3_ugt = z3.UGT(z3_lft, z3_rgt)
        else:
            z3_ugt = None
        z3_ugt_brn = self._reduce(
            z3.And, [
                self._get_branch_constraints(bn_expr),
                z3_lft_brn,
                z3_rgt_brn
            ])
        return (z3_ugt, z3_ugt_brn)
    
    def _visit_mlil_cmp_ule(self, bn_expr: bn.MediumLevelILCmpUle) \
        -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
        """
        Visit expressions of type `MediumLevelILCmpUle`.
        """
        # Visit child expressions
        z3_lft, z3_lft_brn = self._visit(bn_expr.left)
        z3_rgt, z3_rgt_brn = self._visit(bn_expr.right)
        # Current expression's constraints
        if z3_lft is not None and z3_rgt is not None:
            z3_ule = z3.ULE(z3_lft, z3_rgt)
        else:
            z3_ule = None
        z3_ule_brn = self._reduce(
            z3.And, [
                self._get_branch_constraints(bn_expr),
                z3_lft_brn,
                z3_rgt_brn
            ])
        return (z3_ule, z3_ule_brn)
    
    def _visit_mlil_const(self, bn_expr: bn.MediumLevelILConst) \
        -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
        """
        Visit expressions of type `MediumLevelILConst`.
        """
        # Current expression's constraints
        z3_cst = bn_expr.constant
        z3_cst_brn = self._get_branch_constraints(bn_expr)
        return (z3_cst, z3_cst_brn)
    
    def _visit_mlil_if(self, bn_expr: bn.MediumLevelILIf) \
        -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
        """
        Visit expressions of type `MediumLevelILIf`.
        """
        # Visit condition expression
        z3_con, z3_con_brn = self._visit(bn_expr.condition)
        # Current expression's constraints
        z3_ite = z3_con
        z3_ite_brn = self._reduce(
            z3.And, [
                self._get_branch_constraints(bn_expr),
                z3_con_brn
            ])
        return (z3_ite, z3_ite_brn)
    
    def _visit_mlil_var_phi(self, bn_expr: bn.MediumLevelILVarPhi) \
        -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
        """
        Visit expressions of type `MediumLevelILVarPhi`.
        """
        # Log assigning expression (SSA)
        Logger.debug(self._tag, f"0x{bn_expr.instr.address:x} {str(bn_expr):s} (MLIL_VAR_PHI)")
        # New Z3 expression for the desination
        z3_dest = self._create_z3_expression(bn_expr.dest)
        # Current expressions's branch constraints
        z3_crr_brn = self._get_branch_constraints(bn_expr)
        # Visit src variables
        z3_srcs = []
        for var in bn_expr.src:
            # Visit the expression defining the src variable (backward slice)
            z3_def, z3_def_brn = self._visit_var_ssa_definition(var, self._bn_func)
            z3_srcs.append((z3_def, z3_def_brn))
        # Add constraint to the solver
        z3_phi = None
        z3_phi_brn = None
        for z3_src, z3_src_brn in z3_srcs:
            # TODO: Probably the bug is here!
            z3_phi = self._reduce(z3.Or, [z3_phi, self._reduce(z3.And, [z3_dest == z3_src, z3_src_brn])])
            z3_phi_brn = self._reduce(z3.Or, [z3_phi_brn, self._reduce(z3.And, [z3_crr_brn, z3_src_brn])])
        self._z3_solver.add(z3.simplify(z3_phi))
        Logger.debug(self._tag, f"0x{bn_expr.instr.address:x} {str(z3_phi):s} (CONSTRAINT)")
        return (z3_dest, z3_phi_brn)

    def _visit_mlil_set_var_ssa(self, bn_expr: bn.MediumLevelILSetVar) \
        -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
        """
        Visit expressions of type `MediumLevelILSetVar`.
        """
        # Log assigning expression (SSA)
        Logger.debug(self._tag, f"0x{bn_expr.instr.address:x} {str(bn_expr):s} (MLIL_SET_VAR_SSA)")
        # New Z3 expression for the desination
        z3_dest = self._create_z3_expression(bn_expr.dest)
        # Visit src expression
        z3_src, z3_src_brn = self._visit(bn_expr.src)
        # Get current expression's branch constraints
        z3_set_brn = self._reduce(
            z3.And, [
                self._get_branch_constraints(bn_expr),
                z3_src_brn
            ])
        # Add constraint to the solver
        if z3_dest is not None and z3_src is not None:
            constraint = z3_dest == z3_src
            if z3_set_brn is not None:
                constraint = z3.And(constraint, z3_set_brn)
            # TODO: Add `z3.simplify(constraint)` here or somewhere else.
            self._z3_solver.add(z3.simplify(constraint))
            Logger.debug(self._tag, f"0x{bn_expr.instr.address:x} {str(constraint):s} (CONSTRAINT)")
        return (z3_dest, z3_set_brn)
    
    def _visit_mlil_var_ssa(self, bn_expr: bn.MediumLevelILVarSsa) \
        -> Tuple[Optional[z3.ExprRef], Optional[z3.BoolRef]]:
        """
        Visit expressions of type `MediumLevelILVarSsa`.
        """
        # Visit the expression defining the src variable (backward slice)
        z3_def, z3_def_brn = self._visit_var_ssa_definition(bn_expr.src, self._bn_func)
        # Get current expression's branch constraints
        z3_var_brn = self._reduce(
            z3.And, [
                self._get_branch_constraints(bn_expr),
                z3_def_brn
            ])
        return (z3_def, z3_var_brn)
    
    def model(self) -> None:
        """
        TODO:
        - To make things easier, maybe visit twice
            1. _visit_var_mlil_...
            2. _visit_brn_mlil_...
        """
        z3_expr = self._visit(self._bn_expr)
        # for assertion in self._z3_solver.assertions():
        #     print(assertion.sexpr())
        return


# class NewMediumLevelILVarSsaModeler(NewMediumLevelILInstructionVisitor):
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