from __future__ import annotations
from typing import List, Optional, Set, Tuple
import binaryninja as bn


class InstructionHelper:
    """
    This class provides helper functions with respect to instructions.
    """

    @staticmethod
    def replace_addr_tokens(
        inst: bn.MediumLevelILInstruction,
    ) -> List[bn.InstructionTextToken]:
        """
        This method replaces possible address tokens in the given instruction `inst` with the
        corresponding code symbol token.
        """
        formatted_tokens: List[bn.InstructionTextToken] = []
        try:
            for token in inst.tokens:
                match token.type:
                    case bn.InstructionTextTokenType.PossibleAddressToken:
                        symbol = inst.function.view.get_symbol_at(token.value)
                        if symbol:
                            formatted_tokens.append(
                                bn.InstructionTextToken(
                                    bn.InstructionTextTokenType.CodeSymbolToken,
                                    symbol.short_name,
                                    token.value,
                                )
                            )
                        else:
                            formatted_tokens.append(token)
                    case _:
                        formatted_tokens.append(token)
        except Exception:
            pass
        return formatted_tokens

    @staticmethod
    def mark_func_tokens(
        tokens: List[bn.InstructionTextToken],
        return_indices: Set[int],
        param_indices: Set[int],
    ) -> List[bn.InstructionTextToken]:
        """
        This method adds markers around the tokens corresponding to relevant function return values
        and parameters. Relevant return values and/or parameters can be specified by their indices.
        If `return_indices` or `param_indices` contains the value 0, all return values or parameters
        will be marked, respectively.
        """
        before_param_tokens: List[bn.InstructionTextToken] = []
        param_tokens: List[List[bn.InstructionTextToken]] = [[]]
        after_param_tokens: List[bn.InstructionTextToken] = []
        # Find parameter tokens
        in_param = False
        current_tokens = before_param_tokens
        for token in tokens:
            if token.text == "(":
                in_param = True
                current_tokens.append(token)
                current_tokens = after_param_tokens
            elif token.text == ")":
                in_param = False
                current_tokens.append(token)
            elif in_param:
                if token.text == ", ":
                    param_tokens.append([])
                else:
                    param_tokens[-1].append(token)
            else:
                current_tokens.append(token)
        # Mark parameters at indices `param_indices`
        for param_index in param_indices:
            # Ignore invalid parameter indices
            if param_index < 0 or param_index > len(param_tokens):
                continue
            # Mark all parameters
            if param_index == 0:
                left_param_token = param_tokens[0]
                right_param_token = param_tokens[-1]
            # Mark parameters at the specified indices
            else:
                left_param_token = param_tokens[param_index - 1]
                right_param_token = param_tokens[param_index - 1]
            # Insert left marker
            left_param_token.insert(
                0,
                bn.InstructionTextToken(bn.InstructionTextTokenType.CommentToken, "««"),
            )
            # Insert right marker
            if right_param_token and right_param_token[-1].text in (" ", " = "):
                right_param_token.insert(
                    len(right_param_token) - 1,
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.CommentToken, "»»"
                    ),
                )
            else:
                right_param_token.append(
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.CommentToken, "»»"
                    )
                )
        # Separate parameter tokens
        sep_param_tokens: List[List[bn.InstructionTextToken]] = []
        for i, param_token in enumerate(param_tokens):
            sep_param_tokens.append(param_token)
            if i < len(param_tokens) - 1:
                sep_param_tokens.append(
                    [
                        bn.InstructionTextToken(
                            bn.InstructionTextTokenType.TextToken, ", "
                        )
                    ]
                )
        # Find return tokens
        return_tokens: List[List[bn.InstructionTextToken]] = [[]]
        after_return_tokens: List[bn.InstructionTextToken] = before_param_tokens[-2:]
        for token in before_param_tokens[:-2]:
            if token.text == ", ":
                return_tokens.append([])
            else:
                return_tokens[-1].append(token)
        # Mark returns at indices `return_indices`
        for return_index in return_indices:
            # Ignore invalid return indices
            if return_index < 0 or return_index > len(return_tokens):
                continue
            # Mark all returns
            if return_index == 0:
                left_return_token = return_tokens[0]
                right_return_token = return_tokens[-1]
            # Mark returns at the specified indices
            else:
                left_return_token = return_tokens[return_index - 1]
                right_return_token = return_tokens[return_index - 1]
            # Insert left marker
            left_return_token.insert(
                0,
                bn.InstructionTextToken(bn.InstructionTextTokenType.CommentToken, "««"),
            )
            # Insert right marker
            if right_return_token and right_return_token[-1].text in (" ", " = "):
                right_return_token.insert(
                    len(right_return_token) - 1,
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.CommentToken, "»»"
                    ),
                )
            elif right_return_token and right_return_token[-1].text == "return ":
                token = right_return_token.pop()
                right_return_token.append(bn.InstructionTextToken(token.type, "return"))
                right_return_token.append(
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.CommentToken, "»»"
                    )
                )
                right_return_token.append(bn.InstructionTextToken(token.type, " "))
            else:
                right_return_token.append(
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.CommentToken, "»»"
                    )
                )
        # Separate return tokens
        sep_return_tokens: List[List[bn.InstructionTextToken]] = []
        for i, return_token in enumerate(return_tokens):
            sep_return_tokens.append(return_token)
            if i < len(return_tokens) - 1:
                sep_return_tokens.append(
                    [
                        bn.InstructionTextToken(
                            bn.InstructionTextTokenType.TextToken, ", "
                        )
                    ]
                )
        return (
            [token for return_token in sep_return_tokens for token in return_token]
            + after_return_tokens
            + [token for param_token in sep_param_tokens for token in param_token]
            + after_param_tokens
        )

    @staticmethod
    def get_inst_info(
        inst: bn.MediumLevelILInstruction, with_class_name: bool = True
    ) -> str:
        """
        This method returns a string with information about the instruction `inst`.
        """
        tokens = InstructionHelper.replace_addr_tokens(inst)
        token_text = "".join(token.text for token in tokens)
        info = f"0x{inst.instr.address:x} {token_text:s}"
        if with_class_name:
            info = f"{info:s} ({inst.__class__.__name__:s})"
        return info

    @staticmethod
    def get_func_signature(
        inst: bn.MediumLevelILCall
        | bn.MediumLevelILCallUntyped
        | bn.MediumLevelILCallSsa
        | bn.MediumLevelILCallUntypedSsa
        | bn.MediumLevelILTailcall
        | bn.MediumLevelILTailcallUntyped
        | bn.MediumLevelILTailcallSsa
        | bn.MediumLevelILTailcallUntypedSsa,
    ) -> Tuple[str, str]:
        """
        This method returns the name and signature of the target function being called by `inst`.
        """
        func_name = ""
        func_sign = ""
        if isinstance(
            inst,
            (
                bn.MediumLevelILCall,
                bn.MediumLevelILCallUntyped,
                bn.MediumLevelILCallSsa,
                bn.MediumLevelILCallUntypedSsa,
                bn.MediumLevelILTailcall,
                bn.MediumLevelILTailcallUntyped,
                bn.MediumLevelILTailcallSsa,
                bn.MediumLevelILTailcallUntypedSsa,
            ),
        ):
            bv = inst.function.view
            if isinstance(
                inst.dest, (bn.MediumLevelILConstPtr, bn.MediumLevelILImport)
            ):
                func = bv.get_function_at(inst.dest.constant)
                if func is not None:
                    func_name = func.symbol.short_name
                    func_sign = (
                        func.type.get_string_before_name()
                        + " "
                        + func_name
                        + func.type.get_string_after_name()
                    )
                else:
                    data_var = bv.get_data_var_at(inst.dest.constant)
                    symbol = bv.get_symbol_at(inst.dest.constant)
                    if data_var is not None and symbol is not None:
                        func_name = symbol.short_name
                        b_name = data_var.type.get_string_before_name().strip()
                        idx = b_name.rfind("(")
                        if idx != -1:
                            b_name = b_name[:idx].strip()
                        a_name = data_var.type.get_string_after_name().strip()
                        if a_name.startswith(")"):
                            a_name = a_name[1:]
                        func_sign = b_name + " " + func_name + a_name
        return func_name, func_sign

    @staticmethod
    def is_call_inst(
        inst: bn.HighLevelILInstruction
        | bn.MediumLevelILInstruction
        | bn.LowLevelILInstruction,
    ) -> bool:
        """
        This method checks whether the given instruction `inst` is a call instruction.
        """

        def _is_call_inst(
            inst: bn.HighLevelILInstruction
            | bn.MediumLevelILInstruction
            | bn.LowLevelILInstruction,
            *args,
            **kwargs,
        ) -> bool:
            if isinstance(
                inst,
                (
                    bn.HighLevelILCall,
                    bn.HighLevelILCallSsa,
                    bn.HighLevelILTailcall,
                    bn.MediumLevelILCall,
                    bn.MediumLevelILCallSsa,
                    bn.MediumLevelILCallUntyped,
                    bn.MediumLevelILCallUntypedSsa,
                    bn.MediumLevelILTailcall,
                    bn.MediumLevelILTailcallSsa,
                    bn.MediumLevelILTailcallUntyped,
                    bn.MediumLevelILTailcallUntypedSsa,
                    bn.LowLevelILCall,
                    bn.LowLevelILCallSsa,
                    bn.LowLevelILTailcall,
                    bn.LowLevelILTailcallSsa,
                ),
            ):
                return True
            return False

        return any(inst.traverse(_is_call_inst))

    @staticmethod
    def get_mlil_call_insts(
        inst: bn.HighLevelILInstruction
        | bn.MediumLevelILInstruction
        | bn.LowLevelILInstruction,
    ) -> List[
        bn.MediumLevelILCallSsa
        | bn.MediumLevelILCallUntypedSsa
        | bn.MediumLevelILTailcallSsa
        | bn.MediumLevelILTailcallUntypedSsa
    ]:
        """
        This method iterates through all sub-instructions of `inst` and returns all corresponding
        MLIL call instructions.
        """

        def find_mlil_call_inst(
            inst: bn.HighLevelILInstruction
            | bn.MediumLevelILInstruction
            | bn.LowLevelILInstruction
            | None,
            *args,
            **kwargs,
        ) -> (
            bn.MediumLevelILCall
            | bn.MediumLevelILCallSsa
            | bn.MediumLevelILCallUntyped
            | bn.MediumLevelILCallUntypedSsa
            | bn.MediumLevelILTailcall
            | bn.MediumLevelILTailcallSsa
            | bn.MediumLevelILTailcallUntyped
            | bn.MediumLevelILTailcallUntypedSsa
            | None
        ):
            # HLIL or LLIL
            if isinstance(
                inst,
                (
                    bn.HighLevelILCall,
                    bn.HighLevelILCallSsa,
                    bn.HighLevelILTailcall,
                    bn.LowLevelILCall,
                    bn.LowLevelILCallSsa,
                    bn.LowLevelILTailcall,
                    bn.LowLevelILTailcallSsa,
                ),
            ):
                try:
                    mlil_inst = inst.mlil
                except Exception:
                    mlil_inst = None
                return find_mlil_call_inst(mlil_inst)
            # MLIL
            if inst is not None and isinstance(
                inst.ssa_form,
                (
                    bn.MediumLevelILCall,
                    bn.MediumLevelILCallSsa,
                    bn.MediumLevelILCallUntyped,
                    bn.MediumLevelILCallUntypedSsa,
                    bn.MediumLevelILTailcall,
                    bn.MediumLevelILTailcallSsa,
                    bn.MediumLevelILTailcallUntyped,
                    bn.MediumLevelILTailcallUntypedSsa,
                ),
            ):
                return inst.ssa_form
            return None

        return [i for i in inst.traverse(find_mlil_call_inst) if i is not None]

    @staticmethod
    def is_value_equivalent(
        inst_a: bn.HighLevelILInstruction,
        inst_b: bn.HighLevelILInstruction,
    ) -> bool:
        """
        This method checks whether the two HLIL instructions `inst_a` and `inst_b` evaluate to
        the same value, e.g. equivalent pointers, array indices or arithmetic operands. The
        comparison is structural: constants and variables are compared directly, and pure
        operations (casts, integer arithmetic, array indexing, address-of) are compared
        recursively on their operands. An array variable is considered equivalent to its address
        (`arr == &arr`).

        The check is conservative: `True` means the values are equal, `False` means equality
        could not be established. Variables are compared by identity, so the result is only
        sound for SSA instructions or for instructions at the same program point.

        Example: `is_value_equivalent(arr#1[sx.q(i#0) + 1], arr#1[1 + sx.q(i#0)])` --> `True`
        """
        match (inst_a, inst_b):
            # `constant_a == constant_b`
            case (
                bn.HighLevelILConst(constant=constant_a)
                | bn.HighLevelILConstPtr(constant=constant_a),
                bn.HighLevelILConst(constant=constant_b)
                | bn.HighLevelILConstPtr(constant=constant_b),
            ):
                return constant_a == constant_b
            # `var_a == var_b`
            case (
                bn.HighLevelILVar(var=var_a) | bn.HighLevelILVarSsa(var=var_a),
                bn.HighLevelILVar(var=var_b) | bn.HighLevelILVarSsa(var=var_b),
            ):
                return var_a == var_b
            # `src_a[index_a] == src_b[index_b]`
            case (
                bn.HighLevelILArrayIndex(src=src_a, index=index_a)
                | bn.HighLevelILArrayIndexSsa(src=src_a, index=index_a),
                bn.HighLevelILArrayIndex(src=src_b, index=index_b)
                | bn.HighLevelILArrayIndexSsa(src=src_b, index=index_b),
            ):
                return InstructionHelper.is_value_equivalent(
                    src_a, src_b
                ) and InstructionHelper.is_value_equivalent(index_a, index_b)
            # `&src_a == &src_b`
            case (
                bn.HighLevelILAddressOf(src=src_a),
                bn.HighLevelILAddressOf(src=src_b),
            ):
                return InstructionHelper.is_value_equivalent(src_a, src_b)
            # `op(src_a) == op(src_b)`
            case (
                bn.HighLevelILSx(src=src_a)
                | bn.HighLevelILZx(src=src_a)
                | bn.HighLevelILLowPart(src=src_a)
                | bn.HighLevelILNeg(src=src_a)
                | bn.HighLevelILNot(src=src_a),
                bn.HighLevelILSx(src=src_b)
                | bn.HighLevelILZx(src=src_b)
                | bn.HighLevelILLowPart(src=src_b)
                | bn.HighLevelILNeg(src=src_b)
                | bn.HighLevelILNot(src=src_b),
            ) if inst_a.operation == inst_b.operation and inst_a.size == inst_b.size:
                return InstructionHelper.is_value_equivalent(src_a, src_b)
            # `(left_a op right_a) == (left_b op right_b)`
            case (
                bn.HighLevelILAdd(left=left_a, right=right_a)
                | bn.HighLevelILSub(left=left_a, right=right_a)
                | bn.HighLevelILMul(left=left_a, right=right_a)
                | bn.HighLevelILLsl(left=left_a, right=right_a)
                | bn.HighLevelILLsr(left=left_a, right=right_a)
                | bn.HighLevelILAsr(left=left_a, right=right_a)
                | bn.HighLevelILAnd(left=left_a, right=right_a)
                | bn.HighLevelILOr(left=left_a, right=right_a)
                | bn.HighLevelILXor(left=left_a, right=right_a),
                bn.HighLevelILAdd(left=left_b, right=right_b)
                | bn.HighLevelILSub(left=left_b, right=right_b)
                | bn.HighLevelILMul(left=left_b, right=right_b)
                | bn.HighLevelILLsl(left=left_b, right=right_b)
                | bn.HighLevelILLsr(left=left_b, right=right_b)
                | bn.HighLevelILAsr(left=left_b, right=right_b)
                | bn.HighLevelILAnd(left=left_b, right=right_b)
                | bn.HighLevelILOr(left=left_b, right=right_b)
                | bn.HighLevelILXor(left=left_b, right=right_b),
            ) if inst_a.operation == inst_b.operation and inst_a.size == inst_b.size:
                if InstructionHelper.is_value_equivalent(
                    left_a, left_b
                ) and InstructionHelper.is_value_equivalent(right_a, right_b):
                    return True
                # `(left_a op right_a) == (right_b op left_b)` (commutative operations)
                if isinstance(
                    inst_a,
                    (
                        bn.HighLevelILAdd,
                        bn.HighLevelILMul,
                        bn.HighLevelILAnd,
                        bn.HighLevelILOr,
                        bn.HighLevelILXor,
                    ),
                ):
                    return InstructionHelper.is_value_equivalent(
                        left_a, right_b
                    ) and InstructionHelper.is_value_equivalent(right_a, left_b)
                return False
            # `arr_a == &src_b` (array decaying to its address)
            case (
                bn.HighLevelILVar(var=var_a)
                | bn.HighLevelILVarSsa(var=bn.SSAVariable(var=var_a)),
                bn.HighLevelILAddressOf(src=src_b),
            ) if isinstance(var_a.type, bn.ArrayType):
                return InstructionHelper.is_value_equivalent(inst_a, src_b)
            # `&src_a == arr_b` (array decaying to its address)
            case (
                bn.HighLevelILAddressOf(src=src_a),
                bn.HighLevelILVar(var=var_b)
                | bn.HighLevelILVarSsa(var=bn.SSAVariable(var=var_b)),
            ) if isinstance(var_b.type, bn.ArrayType):
                return InstructionHelper.is_value_equivalent(src_a, inst_b)
        return False

    @staticmethod
    def _get_ptr_value_addr(
        ptr_inst: bn.HighLevelILInstruction,
    ) -> Optional[Tuple[Optional[bn.HighLevelILInstruction], int]]:
        """
        This method splits the address held by the HLIL pointer instruction `ptr_inst` into a
        symbolic base (`None` for absolute addresses) and a constant byte offset. Returns `None`
        if the address cannot be determined.

        `ptr_inst` must be an rvalue whose value is an address (e.g. `p`, `p + 8`, `&p->f`): the
        method does not access memory, it only evaluates the address the pointer holds. An
        address-of (`&`) is resolved via `_get_mem_access_addr` on its lvalue operand.

        Example: `_get_ptr_value_addr(&p->f)` --> `(p, 8)` (with `f` at offset 8)
        """
        match ptr_inst:
            case (
                bn.HighLevelILConstPtr(constant=addr)
                | bn.HighLevelILConst(constant=addr)
            ):
                return (None, addr)
            case (
                bn.HighLevelILAdd(
                    left=base_ptr_inst, right=bn.HighLevelILConst(constant=offset)
                )
                | bn.HighLevelILAdd(
                    left=bn.HighLevelILConst(constant=offset), right=base_ptr_inst
                )
            ):
                inner_addr = InstructionHelper._get_ptr_value_addr(base_ptr_inst)
            case bn.HighLevelILSub(
                left=base_ptr_inst, right=bn.HighLevelILConst(constant=offset)
            ):
                inner_addr = InstructionHelper._get_ptr_value_addr(base_ptr_inst)
                offset = -offset
            case bn.HighLevelILAddressOf(src=mem_inst):
                return InstructionHelper._get_mem_access_addr(mem_inst)
            case _:
                # Anything else is an opaque base
                return (ptr_inst, 0)
        if inner_addr is None:
            return None
        base, inner_offset = inner_addr
        return (base, inner_offset + offset)

    @staticmethod
    def _get_mem_access_addr(
        mem_inst: bn.HighLevelILInstruction,
    ) -> Optional[Tuple[Optional[bn.HighLevelILInstruction], int]]:
        """
        This method returns the address of the memory accessed by the HLIL lvalue instruction
        `mem_inst`, split into a symbolic base (`None` for absolute addresses) and a constant byte
        offset. Returns `None` if the address cannot be determined.

        `mem_inst` must be an lvalue, i.e. the memory location itself (e.g. `*p`, `p->f`, `s.f`,
        `arr[2]`): the method returns where that memory is, not the value stored in it. The
        address is derived from the lvalue's operand, i.e. via `_get_ptr_value_addr` for pointer
        operands (`*p`, `p->f`, `arr[2]`) or recursively for lvalue operands (`s.f`).

        Example: `_get_mem_access_addr(p->f)` --> `(p, 8)` (with `f` at offset 8)
        """
        match mem_inst:
            case bn.HighLevelILDerefSsa(src=ptr_inst):
                return InstructionHelper._get_ptr_value_addr(ptr_inst)
            case bn.HighLevelILDerefFieldSsa(src=ptr_inst, offset=offset):
                inner_addr = InstructionHelper._get_ptr_value_addr(ptr_inst)
            case bn.HighLevelILStructField(src=struct_mem_inst, offset=offset):
                inner_addr = InstructionHelper._get_mem_access_addr(struct_mem_inst)
            case bn.HighLevelILArrayIndexSsa(
                src=ptr_inst, index=bn.HighLevelILConst(constant=index)
            ):
                inner_addr = InstructionHelper._get_ptr_value_addr(ptr_inst)
                offset = index * mem_inst.size
            case bn.HighLevelILArrayIndexSsa():
                # Opaque base in case of a non-constant index
                return (mem_inst, 0)
            case bn.HighLevelILVar():
                # Aliased variable (e.g. local struct `s`) is not in SSA form and lives in memory
                return (mem_inst, 0)
            case _:
                return None
        if inner_addr is None:
            return None
        base, inner_offset = inner_addr
        return (base, inner_offset + offset)

    @staticmethod
    def is_mem_access_overlapping(
        mem_inst_a: bn.HighLevelILInstruction,
        mem_inst_b: bn.HighLevelILInstruction,
        size_a: int,
        size_b: int,
    ) -> bool:
        """
        This method checks whether the memory accessed by the two HLIL lvalue instructions
        `mem_inst_a` and `mem_inst_b` (e.g. `*p`, `p->f`, `s.f`, `arr[2]`) is guaranteed to
        overlap (in at least one byte). The check is symmetric. Returns `False` if this cannot be
        determined. `size_a` and `size_b` are the access widths in bytes (e.g. from the
        corresponding MLIL load/store).

        Example: `is_mem_access_overlapping(p->f, *(p + 8), 4, 4)` --> `True` (with `f` at offset 8)
        """
        # Resolve both accesses to `(base, offset)`
        addr_a = InstructionHelper._get_mem_access_addr(mem_inst_a)
        addr_b = InstructionHelper._get_mem_access_addr(mem_inst_b)
        if addr_a is None or addr_b is None:
            return False
        (base_a, offset_a), (base_b, offset_b) = addr_a, addr_b
        # Ensure same base (`None` denotes an absolute address)
        if base_a is None or base_b is None:
            if base_a is not base_b:
                return False
        elif not InstructionHelper.is_value_equivalent(base_a, base_b):
            return False
        # Ensure byte ranges `[offset, offset + size)` intersect
        return offset_a < offset_b + size_b and offset_b < offset_a + size_a
