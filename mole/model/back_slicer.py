import binaryninja  as bn
import z3
from   typing       import Callable, List, Optional, Set
from   ..common.log import Logger


class MediumLevelILInstructionVisitor:
    """
    Base class to visit `MediumLevelILInstruction` expressions.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "Visitor"
        ) -> None:
        self._bv = bv
        self._tag = tag
        self._bn_expr_vars = {}
        self._bn_expr_bdes = {}
        return
    
    def _get_instr_info(
            self,
            bn_expr: bn.MediumLevelILInstruction
        ) -> str:
        """
        Returns a string with information about the expression `bn_expr`.
        """
        return f"0x{bn_expr.instr.address:x} {str(bn_expr):s} {str(bn_expr.branch_dependence):s}"
    
    def _visit_var(
            self,
            bn_expr: bn.MediumLevelILInstruction
        ) -> Optional[z3.ExprRef]:
        """
        Call dedicated variable visit function based on the operation name of expression `bn_expr`.
        """
        # Expression visited before
        if bn_expr in self._bn_expr_vars:
            return self._bn_expr_vars[bn_expr]
        # TODO: Recursion
        self._bn_expr_vars[bn_expr] = None
        # Call dedicated visit functions
        o_name = bn_expr.operation.name.lower()
        f_name = f"_visit_var_{o_name:s}"
        if hasattr(self, f_name):
            self._bn_expr_vars[bn_expr] = getattr(self, f_name)(bn_expr)
            return self._bn_expr_vars[bn_expr]
        # Warn on missing visit function
        Logger.warn(self._tag, f"Visit function `{f_name:s}` not implemented")
        return None
    
    def _visit_bde(
            self,
            bn_expr: bn.MediumLevelILInstruction
        ) -> List[Optional[z3.BoolRef]]:
        """
        Call dedicated branch dependence visit function based on the operation name of expression
        `bn_expr`.
        """
        # Expression visited before
        if bn_expr in self._bn_expr_bdes:
            return self._bn_expr_bdes[bn_expr]
        # TODO: Recursion
        self._bn_expr_bdes[bn_expr] = []
        # Call dedicated visit functions
        o_name = bn_expr.operation.name.lower()
        f_name = f"_visit_bde_{o_name:s}"
        # TODO: Indefinite recursion
        if hasattr(self, f_name):
            self._bn_expr_bdes[bn_expr] = getattr(self, f_name)(bn_expr)
            return self._bn_expr_bdes[bn_expr]
        # Warn on missing visit function
        Logger.warn(self._tag, f"Visit function `{f_name:s}` not implemented")
        return []


class MediumLevelILVarSsaModeler(MediumLevelILInstructionVisitor):
    """
    Class to visit and model a `MediumLevelILVarSsa` expression.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "Modeler"
        ) -> None:
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

    def _get_branch_dependencies(
            self,
            bn_expr: bn.MediumLevelILInstruction
        ) -> List[Optional[z3.BoolRef]]:
        """
        Get all branch dependencies of expression `bn_expr`.
        """
        # Collect branch dependencies
        z3_bch_bdes = []
        for instr_index, branch in bn_expr.branch_dependence.items():
            bn_bch = bn_expr.function[instr_index]
            z3_bch = self._visit_var(bn_bch)
            if z3_bch is None: continue
            z3_bch_cst = self._z3_var_csts.get(z3_bch, None)
            z3_bch_bde = self._visit_bde(bn_bch)
            if branch.value == bn.ILBranchDependence.TrueBranchDependent:
                z3_bch_bdes.append(self._reduce(z3.And, [z3_bch == True, z3_bch_cst] + z3_bch_bde))
            elif branch.value == bn.ILBranchDependence.FalseBranchDependent:
                z3_bch_bdes.append(self._reduce(z3.And, [z3_bch == False, z3_bch_cst] + z3_bch_bde))
        # No branch dependencies
        if not z3_bch_bdes: return []
        # And-reduce branch dependencies
        return z3_bch_bdes

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
    
    # def find_var_aliases(
    #         self,
    #         bn_expr: bn.MediumLevelILVarAliased
    # ) -> List[bn.SSAVariable]:
    #     """
    #     TODO:
    #     bn_expr.function.get_var_definitions(bn_expr.src.var)
    #     """
    #     aliases = []
    #     for basic_block in bn_expr.function:
    #         for instr in basic_block:
    #             if instr.operation in (
    #                 bn.MediumLevelILOperation.MLIL_SET_VAR,
    #                 bn.MediumLevelILOperation.MLIL_SET_VAR_ALIASED,
    #                 bn.MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD, 
    #                 bn.MediumLevelILOperation.MLIL_SET_VAR_FIELD,
    #                 bn.MediumLevelILOperation.MLIL_SET_VAR_SPLIT,
    #                 bn.MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA,
    #                 bn.MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD
    #             ):
    #                 pass
    #             # if instr.operation == bn.MediumLevelILOperation.MLIL_VAR_ALIASED:
    #             #     aliased_var = instr.src
    #             # if instr.instr_index == 120:
    #             #     pass
    #             # if instr.operation in (
    #             #     bn.MediumLevelILOperation.MLIL_VAR_ALIASED,
    #             #     bn.MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD,
    #             #     bn.MediumLevelILOperation.MLIL_SET_VAR_ALIASED,
    #             #     bn.MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD
    #             # ):
    #             #     print(f"0x{instr.instr.address:x} {str(instr):s}")
    #             # if isinstance(instr, bn.MediumLevelILSetVarAliased):
    #             #     pass
    #             # if instr.instr_index == 119:
    #             #     pass
    #             # if instr.operation != bn.MediumLevelILOperation.MLIL_VAR_ALIASED:
    #             #     continue
    #             # if instr.src == bn_expr.src:
    #             #     aliases.append(instr.dest)
    #     return aliases
    
    def _visit_var_var_ssa_definition(
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
        return self._visit_var(bn_expr)
    
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
    
    def _visit_var_mlil_add(
            self,
            bn_expr: bn.MediumLevelILAdd
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILAdd` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_ADD)")
        # Visit the expression's child expressions
        z3_lft = self._visit_var(bn_expr.left)
        z3_rgt = self._visit_var(bn_expr.right)
        if z3_lft is None or z3_rgt is None:
            z3_add = None
        else:
            z3_add = z3_lft + z3_rgt
        return z3_add
    
    def _visit_bde_mlil_add(
            self,
            bn_expr: bn.MediumLevelILAdd
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILAdd` expression `bn_expr`.
        """
        z3_crr_bde = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_lft_bde = self._reduce(z3.And, self._visit_bde(bn_expr.left))
        z3_rgt_bde = self._reduce(z3.And, self._visit_bde(bn_expr.right))
        return [z3_crr_bde, z3_lft_bde, z3_rgt_bde]
    
    def _visit_var_mlil_address_of(
            self,
            bn_expr: bn.MediumLevelILAddressOf
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILAddressOf` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_ADDRESS_OF)")
        return None
    
    def _visit_bde_mlil_address_of(
            self,
            bn_expr: bn.MediumLevelILAddressOf
    ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILAddressOf` expression `bn_expr`.
        """
        return self._get_branch_dependencies(bn_expr)
    
    def _visit_var_mlil_call_ssa(
            self,
            bn_expr: bn.MediumLevelILCallSsa
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILCallSsa` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CALL_SSA)")
        # Branch dependencies
        z3_bdes = self._reduce(z3.Or, self._visit_bde(bn_expr))
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
        # Constrain the model
        if z3_dest is not None and z3_src is not None:
            self._z3_var_csts[z3_dest] = z3.simplify(self._reduce(z3.And, [z3_dest == z3_src, z3_src_cst, z3_bdes]))
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
    
    def _visit_var_mlil_cmp_e(
            self,
            bn_expr: bn.MediumLevelILCmpE
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILCmpE` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_E)")
        # Visit the expression's child expressions
        z3_lft = self._visit_var(bn_expr.left)
        z3_rgt = self._visit_var(bn_expr.right)
        if z3_lft is None or z3_rgt is None:
            z3_e = None
        else:
            z3_e = z3_lft == z3_rgt
        return z3_e
    
    def _visit_bde_mlil_cmp_e(
            self,
            bn_expr: bn.MediumLevelILCmpE
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILCmpE` expression `bn_expr`.
        """
        z3_crr_bde = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_lft_bde = self._reduce(z3.And, self._visit_bde(bn_expr.left))
        z3_rgt_bde = self._reduce(z3.And, self._visit_bde(bn_expr.right))
        return [z3_crr_bde, z3_lft_bde, z3_rgt_bde]
    
    def _visit_var_mlil_cmp_ne(
            self,
            bn_expr: bn.MediumLevelILCmpNe
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILCmpNe` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_NE)")
        # Visit the expression's child expressions
        z3_lft = self._visit_var(bn_expr.left)
        z3_rgt = self._visit_var(bn_expr.right)
        if z3_lft is None or z3_rgt is None:
            z3_ne = None
        else:
            z3_ne = z3_lft != z3_rgt
        return z3_ne
    
    def _visit_bde_mlil_cmp_ne(
            self,
            bn_expr: bn.MediumLevelILCmpNe
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILCmpNe` expression `bn_expr`.
        """
        z3_crr_bde = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_lft_bde = self._reduce(z3.And, self._visit_bde(bn_expr.left))
        z3_rgt_bde = self._reduce(z3.And, self._visit_bde(bn_expr.right))
        return [z3_crr_bde, z3_lft_bde, z3_rgt_bde]
    
    def _visit_var_mlil_cmp_sge(
            self,
            bn_expr: bn.MediumLevelILCmpSge
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILCmpSge` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_SGE)")
        # Visit the expression's child expressions
        z3_lft = self._visit_var(bn_expr.left)
        z3_rgt = self._visit_var(bn_expr.right)
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
    
    def _visit_var_mlil_cmp_slt(
            self,
            bn_expr: bn.MediumLevelILCmpSlt
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILCmpSlt` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_SLT)")
        # Visit the expression's child expressions
        z3_lft = self._visit_var(bn_expr.left)
        z3_rgt = self._visit_var(bn_expr.right)
        if z3_lft is None or z3_rgt is None:
            z3_slt = None
        else:
            z3_slt = z3_lft < z3_rgt
        return z3_slt
    
    def _visit_bde_mlil_cmp_slt(
            self,
            bn_expr: bn.MediumLevelILCmpSlt
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILCmpSlt` expression `bn_expr`.
        """
        z3_crr_bde = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_lft_bde = self._reduce(z3.And, self._visit_bde(bn_expr.left))
        z3_rgt_bde = self._reduce(z3.And, self._visit_bde(bn_expr.right))
        return [z3_crr_bde, z3_lft_bde, z3_rgt_bde]
    
    def _visit_var_mlil_cmp_ugt(
            self,
            bn_expr: bn.MediumLevelILCmpUgt
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILCmpUgt` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_UGT)")
        # Visit the expression's child expressions
        z3_lft = self._visit_var(bn_expr.left)
        z3_rgt = self._visit_var(bn_expr.right)
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
    
    def _visit_var_mlil_cmp_ule(
            self,
            bn_expr: bn.MediumLevelILCmpUle
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILCmpUle` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_ULE)")
        # Visit the expression's child expressions
        z3_lft = self._visit_var(bn_expr.left)
        z3_rgt = self._visit_var(bn_expr.right)
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
    
    def _visit_var_mlil_const(
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
    
    def _visit_var_mlil_if(
            self,
            bn_expr: bn.MediumLevelILIf
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILIf` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_IF)")
        # Visit the expression's `condition` expression
        z3_con = self._visit_var(bn_expr.condition)
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
    
    def _visit_var_mlil_lsl(
            self,
            bn_expr: bn.MediumLevelILLsl
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILLsl` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_LSL)")
        # Visit the expression's child expressions
        z3_lft = self._visit_var(bn_expr.left)
        z3_rgt = self._visit_var(bn_expr.right)
        if z3_lft is None or z3_rgt is None:
            z3_lsl = None
        else:
            z3_lsl = z3_lft << z3_rgt
        return z3_lsl
    
    def _visit_bde_mlil_lsl(
            self,
            bn_expr: bn.MediumLevelILLsl
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILLsl` expression `bn_expr`.
        """
        z3_crr_bde = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_lft_bde = self._reduce(z3.And, self._visit_bde(bn_expr.left))
        z3_rgt_bde = self._reduce(z3.And, self._visit_bde(bn_expr.right))
        return [z3_crr_bde, z3_lft_bde, z3_rgt_bde]
    
    def _visit_var_mlil_lsr(
            self,
            bn_expr: bn.MediumLevelILLsr
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILLsr` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_LSR)")
        # Visit the expression's child expressions
        z3_lft = self._visit_var(bn_expr.left)
        z3_rgt = self._visit_var(bn_expr.right)
        if z3_lft is None or z3_rgt is None:
            z3_lsr = None
        else:
            z3_lsr = z3.LShR(z3_lft, z3_rgt)
        return z3_lsr
    
    def _visit_bde_mlil_lsr(
            self,
            bn_expr: bn.MediumLevelILLsr
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILLsr` expression `bn_expr`.
        """
        z3_crr_bde = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_lft_bde = self._reduce(z3.And, self._visit_bde(bn_expr.left))
        z3_rgt_bde = self._reduce(z3.And, self._visit_bde(bn_expr.right))
        return [z3_crr_bde, z3_lft_bde, z3_rgt_bde]
    
    def _visit_var_mlil_var_aliased(
            self,
            bn_expr: bn.MediumLevelILVarAliased
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILVarPhi` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_VAR_ALIASED)")
        # Expression defining the `src` variable (backward slice)
        z3_src = self._visit_var_var_ssa_definition(bn_expr.src, bn_expr.function)
        return z3_src
    
    def _visit_bde_mlil_var_aliased(
            self,
            bn_expr: bn.MediumLevelILVarAliased
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILVarAliased` expression `bn_expr`.
        """
        z3_src = self._reduce(z3.And, self._visit_bde_var_ssa_definition(bn_expr.src, bn_expr.function))
        return [z3_src]

    def _visit_var_mlil_var_phi(
            self,
            bn_expr: bn.MediumLevelILVarPhi
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILVarPhi` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_VAR_PHI)")
        # Branch dependencies
        z3_bdes = self._visit_bde(bn_expr)
        # New Z3 expression for the desination
        z3_dest = self._create_z3_expression(bn_expr.dest)
        # Visit the expression's `src` variables
        z3_srcs = []
        for var, z3_bde in zip(bn_expr.src, z3_bdes):
            z3_src = self._visit_var_var_ssa_definition(var, bn_expr.function)
            z3_src_cst = self._z3_var_csts.get(z3_src, None)
            if z3_dest is not None and z3_src is not None:
                z3_srcs.append(self._reduce(z3.And, [z3_dest == z3_src, z3_src_cst, z3_bde]))
        # Constrain the model
        if z3_srcs:
            self._z3_var_csts[z3_dest] = z3.simplify(self._reduce(z3.Or, z3_srcs))
        # Return Z3 expression
        return z3_dest
    
    def _visit_bde_mlil_var_phi(
            self,
            bn_expr: bn.MediumLevelILVarPhi
    ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILVarPhi` expression `bn_expr`.
        """
        # Determine relevant basic blocks
        bn_func = bn_expr.function
        bb_var_phi = bn_expr.il_basic_block
        bb_var_phi_srcs = []
        for var in bn_expr.src:
            bn_var_def = bn_func.get_ssa_var_definition(var)
            bb_var_def = bn_var_def.il_basic_block
            bb_var_phi_srcs.append(bb_var_def)
        # Collect path constraints of all phi-sources
        z3_var_phi = []
        for i, var in enumerate(bn_expr.src):
            # Find paths from variable definition to variable usage
            bb_paths = []
            ed_paths = []
            bn_var_def = bn_func.get_ssa_var_definition(var)
            bb_var_def = bn_var_def.il_basic_block
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
                        bn_bch_expr = in_edge.source[-1]
                        z3_cond = self._visit_var(bn_bch_expr)
                        z3_cond_cst = self._z3_var_csts.get(z3_cond, None)
                        z3_path.append(self._reduce(z3.And, [z3_cond == True, z3_cond_cst]))
                    elif in_edge.type == bn.BranchType.FalseBranch:
                        bn_bch_expr = in_edge.source[-1]
                        z3_cond = self._visit_var(bn_bch_expr)
                        z3_cond_cst = self._z3_var_csts.get(z3_cond, None)
                        z3_path.append(self._reduce(z3.And, [z3_cond == False, z3_cond_cst]))
                z3_var_phi_src.append(self._reduce(z3.And, z3_path))
            z3_var_phi.append(self._reduce(z3.Or, z3_var_phi_src))
        return z3_var_phi

    def _visit_var_mlil_set_var_ssa(
            self,
            bn_expr: bn.MediumLevelILSetVar
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILSetVar` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_SET_VAR_SSA)")
        # Branch dependencies
        z3_bdes = self._reduce(z3.Or, self._visit_bde(bn_expr))
        # New Z3 expression for the desination
        z3_dest = self._create_z3_expression(bn_expr.dest)
        # Expression's `src` expression
        z3_src = self._visit_var(bn_expr.src)
        z3_src_cst = self._z3_var_csts.get(z3_src, None)
        # Constrain the model
        if z3_dest is not None and z3_src is not None:
            self._z3_var_csts[z3_dest] = z3.simplify(self._reduce(
                z3.And, [z3_dest == z3_src, z3_src_cst, z3_bdes]
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
    
    def _visit_var_mlil_sub(
            self,
            bn_expr: bn.MediumLevelILSub
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILSub` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_CMP_SUB)")
        # Visit the expression's child expressions
        z3_lft = self._visit_var(bn_expr.left)
        z3_rgt = self._visit_var(bn_expr.right)
        if z3_lft is None or z3_rgt is None:
            z3_add = None
        else:
            z3_add = z3_lft - z3_rgt
        return z3_add
    
    def _visit_bde_mlil_sub(
            self,
            bn_expr: bn.MediumLevelILSub
        ) -> List[Optional[z3.BoolRef]]:
        """
        Visit branch dependencies of `MediumLevelILSub` expression `bn_expr`.
        """
        z3_crr_bde = self._reduce(z3.And, self._get_branch_dependencies(bn_expr))
        z3_lft_bde = self._reduce(z3.And, self._visit_bde(bn_expr.left))
        z3_rgt_bde = self._reduce(z3.And, self._visit_bde(bn_expr.right))
        return [z3_crr_bde, z3_lft_bde, z3_rgt_bde]
    
    def _visit_var_mlil_var_ssa(
            self,
            bn_expr: bn.MediumLevelILVarSsa
        ) -> Optional[z3.ExprRef]:
        """
        Visit `MediumLevelILVarSsa` expression `bn_expr`.
        """
        Logger.debug(self._tag, self._get_instr_info(bn_expr) + " (MLIL_VAR_SSA)")
        # Expression defining the `src` variable (backward slice)
        z3_src = self._visit_var_var_ssa_definition(bn_expr.src, bn_expr.function)
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
    
    def model(
            self,
            bn_expr: bn.MediumLevelILVarSsa
        ) -> None:
        """
        """
        solver = z3.Solver()
        z3_var = self._visit_var(bn_expr)
        solver.add(self._z3_var_csts.get(z3_var, False))
        if solver.check() == z3.sat:
            print(solver.model())
        return


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


class NewMediumLevelILVarSsaModeler(NewMediumLevelILInstructionVisitor):
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
