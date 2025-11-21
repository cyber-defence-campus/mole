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
        bv: bn.BinaryView,
        inst: bn.MediumLevelILCall
        | bn.MediumLevelILCallSsa
        | bn.MediumLevelILTailcall
        | bn.MediumLevelILTailcallSsa,
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
                bn.MediumLevelILCallSsa,
                bn.MediumLevelILTailcall,
                bn.MediumLevelILTailcallSsa,
            ),
        ):
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
            | bn.LowLevelILInstruction,
        ) -> Optional[
            bn.MediumLevelILCallSsa
            | bn.MediumLevelILCallUntypedSsa
            | bn.MediumLevelILTailcallSsa
            | bn.MediumLevelILTailcallUntypedSsa
        ]:
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
            if isinstance(
                inst,
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
