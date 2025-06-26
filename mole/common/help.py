from __future__ import annotations
from functools import lru_cache
from typing import Dict, List, Optional, Set
import binaryninja as bn


class SymbolHelper:
    """
    This class provides helper functions with respect to symbols.
    """

    @staticmethod
    def get_symbol_by_section(
        bv: bn.BinaryView, symbol_name: str, section_name: str = ".plt"
    ) -> Optional[bn.CoreSymbol]:
        """
        This method returns the symbol with name `symbol_name` belonging to section `section_name`.
        """
        section = bv.get_section_by_name(section_name)
        if section is None:
            return None
        for symbol in bv.symbols.get(symbol_name, []):
            if section.start <= symbol.address < section.end:
                return symbol
        return None

    @staticmethod
    def get_code_refs(
        bv: bn.BinaryView, symbol_names: List[str]
    ) -> Dict[str, Set[bn.MediumLevelILInstruction]]:
        """
        This method determines code references for the provided `symbol_names`. The returned
        dictionary contains individual `symbol_names` as keys, and the corresponding code references
        as values. Code references correspond to `bn.MediumLevelILInstruction`s in SSA form.
        """
        mlil_ssa_code_refs = {}
        for symbol_name in symbol_names:
            for symbol in bv.symbols.get(symbol_name, []):
                # Check if the symbol is in the PE sections .idata
                idata = bv.sections.get(".idata")
                in_idata = idata.start <= symbol.address < idata.end if idata else False
                # Check if the symbol is in the PE sections .synthetic_builtins
                synthetic = bv.sections.get(".synthetic_builtins")
                in_synthetic = (
                    synthetic.start <= symbol.address < synthetic.end
                    if synthetic
                    else False
                )
                # Check if there is no code at the symbol address
                no_code = bv.get_function_at(symbol.address) is None
                # Ensure symbols contains code or is in the .idata or .synthetic_builtins sections
                if no_code and not in_idata and not in_synthetic:
                    continue
                # Store code references
                mlil_insts: Set[bn.MediumLevelILInstruction] = mlil_ssa_code_refs.get(
                    symbol_name, set()
                )
                for code_ref in bv.get_code_refs(symbol.address):
                    mlil_insts.add(code_ref.mlil.ssa_form)
                mlil_ssa_code_refs[symbol_name] = mlil_insts
        return mlil_ssa_code_refs


class VariableHelper:
    """
    This class provides helper functions with respect to variables.
    """

    @staticmethod
    def get_var_info(var: bn.Variable) -> str:
        """
        This method returns a string with information about the variable `var`.
        """
        return f"{var.name}"

    @staticmethod
    def get_ssavar_info(var: bn.SSAVariable) -> str:
        """
        This method returns a string with information about the SSA variable `var`.
        """
        return f"{var.name}#{var.version}"


class InstructionHelper:
    """
    This class provides helper functions with respect to instructions.
    """

    @staticmethod
    @lru_cache(maxsize=None)
    def format_inst(inst: bn.MediumLevelILInstruction) -> str:
        """
        This method replaces function addresses with their names.
        """
        formatted_tokens = []
        for token in inst.tokens:
            match token.type:
                case bn.InstructionTextTokenType.PossibleAddressToken:
                    func = inst.function.view.get_function_at(token.value)
                    if func:
                        formatted_tokens.append(func.name)
                    else:
                        formatted_tokens.append(token.text)
                case _:
                    formatted_tokens.append(token.text)
        return "".join(formatted_tokens)

    @staticmethod
    def get_inst_info(
        inst: bn.MediumLevelILInstruction, with_class_name: bool = True
    ) -> str:
        """
        This method returns a string with information about the instruction `inst`.
        """
        info = f"0x{inst.instr.address:x} {InstructionHelper.format_inst(inst):s}"
        if with_class_name:
            info = f"{info:s} ({inst.__class__.__name__:s})"
        return info


class FunctionHelper:
    """
    This class provides helper functions with respect to functions.
    """

    @staticmethod
    def get_func_info(
        func: bn.MediumLevelILFunction, with_class_name: bool = True
    ) -> str:
        """
        This method returns a string with information about the function `func`.
        """
        info = f"0x{func.source_function.start:x} {func.source_function.name:s}"
        if with_class_name:
            info = f"{info:s} ({func.__class__.__name__:s})"
        return info

    @staticmethod
    def get_il_code(
        func: bn.HighLevelILFunction | bn.MediumLevelILFunction | bn.LowLevelILFunction,
    ) -> str:
        """
        This method returns an IL code representation of the function `func`.
        """
        if not func:
            return ""
        code_lines = [
            f"0x{inst.address:x}: {str(inst):s}" for inst in func.instructions
        ]
        return "\n".join(code_lines)

    @staticmethod
    def get_pseudo_c_code(func: bn.Function) -> str:
        """
        This method returns the pseudo C code of the function `func`.
        """
        if not func or func.pseudo_c_if_available is None:
            return ""
        code_lines = []
        for code_line in func.pseudo_c_if_available.get_linear_lines(func.hlil.root):
            code_lines.append(f"0x{code_line.address:x}: {str(code_line):s}")
        return "\n".join(code_lines)
