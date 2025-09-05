from __future__ import annotations
from functools import lru_cache
from typing import List, Optional, Tuple
import binaryninja as bn


class InstructionHelper:
    """
    This class provides helper functions with respect to instructions.
    """

    @staticmethod
    @lru_cache(maxsize=64)
    def replace_addr_tokens(
        inst: bn.MediumLevelILInstruction,
    ) -> List[bn.InstructionTextToken]:
        """
        This method replaces possible address tokens in the given instruction `inst` with the
        corresponding code symbol token.
        """
        formatted_tokens: List[bn.InstructionTextToken] = []
        for token in inst.tokens:
            match token.type:
                case bn.InstructionTextTokenType.PossibleAddressToken:
                    func = inst.function.view.get_function_at(token.value)
                    if func:
                        formatted_tokens.append(
                            bn.InstructionTextToken(
                                bn.InstructionTextTokenType.CodeSymbolToken,
                                func.name,
                                func.start,
                            )
                        )
                    else:
                        formatted_tokens.append(token)
                case _:
                    formatted_tokens.append(token)
        return formatted_tokens

    def mark_param_token(
        tokens: List[bn.InstructionTextToken], param_indices: List[int]
    ) -> List[bn.InstructionTextToken]:
        """
        This method adds markers around the tokens corresponding to the function parameters at the
        given indices `param_indices`.
        """
        before_tokens: List[bn.InstructionTextToken] = []
        param_tokens: List[List[bn.InstructionTextToken]] = [[]]
        after_tokens: List[bn.InstructionTextToken] = []
        # Find parameter tokens
        in_param = False
        current_tokens = before_tokens
        for token in tokens:
            if token.text == "(":
                in_param = True
                current_tokens.append(token)
                current_tokens = after_tokens
            elif token.text == ")":
                in_param = False
                current_tokens.append(token)
            elif in_param:
                if token.text == ", ":
                    param_tokens.append([token])
                    param_tokens.append([])
                else:
                    param_tokens[-1].append(token)
            else:
                current_tokens.append(token)
        # Mark parameters at indices `param_indices`
        for param_index in param_indices:
            if param_index <= 0 or param_index > len(param_tokens):
                continue
            param_token = param_tokens[param_index - 1]
            if param_token:
                param_token.insert(
                    0,
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.CommentToken, "««"
                    ),
                )
                param_token.append(
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.CommentToken, "»»"
                    )
                )
        return (
            before_tokens
            + [token for param_token in param_tokens for token in param_token]
            + after_tokens
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
                    func_name = func.name
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
                        func_name = symbol.name
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
        bn.MediumLevelILCall
        | bn.MediumLevelILCallSsa
        | bn.MediumLevelILTailcall
        | bn.MediumLevelILTailcallSsa
    ]:
        """
        This method iterates through all sub-instructions of `inst` and returns all
        corresponding MLIL call instructions.
        """

        def find_mlil_call_inst(
            inst: bn.HighLevelILInstruction | bn.MediumLevelILInstruction,
        ) -> Optional[bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa]:
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
                    bn.MediumLevelILTailcall,
                    bn.MediumLevelILTailcallSsa,
                ),
            ):
                return inst
            return None

        return [i for i in inst.traverse(find_mlil_call_inst) if i is not None]
