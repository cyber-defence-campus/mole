from __future__ import annotations
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple
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
                in_synthetic_builtins = (
                    synthetic.start <= symbol.address < synthetic.end
                    if synthetic
                    else False
                )
                # Check if there is code at the symbol address
                in_code = bv.get_function_at(symbol.address) is not None
                # Ignore symbols that are neither in code, the .idata or .synthetic_builtins sections
                if not (in_code or in_idata or in_synthetic_builtins):
                    continue
                # Store code references
                mlil_insts: Set[bn.MediumLevelILInstruction] = mlil_ssa_code_refs.get(
                    symbol_name, set()
                )
                for code_ref in bv.get_code_refs(symbol.address):
                    # Store all instructions at the code reference address
                    funcs = bv.get_functions_containing(code_ref.address)
                    if funcs is None:
                        continue
                    for func in funcs:
                        if (
                            func is None
                            or func.mlil is None
                            or func.mlil.ssa_form is None
                        ):
                            continue
                        func = func.mlil.ssa_form
                        for inst in func.instructions:
                            if inst.address == code_ref.address:
                                mlil_insts.add(inst)
                if mlil_insts:
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
    def get_mlil_parm_insts(
        func: bn.MediumLevelILFunction,
    ) -> List[Optional[bn.MediumLevelILVarSsa]]:
        """
        This method returns a list of `MediumLevelILVarSsa` instructions that correspond to the
        parameters of function `func`. The order of the returned instructions corresponds to the one
        of the parameters in the function signature.
        """
        parm_vars = list(func.source_function.parameter_vars)
        parm_insts = len(parm_vars) * [None]

        func = func.ssa_form
        if func is None:
            return parm_insts

        # Find instructions corresponding to the function parameters
        def find_mlil_parm_inst(
            inst: bn.MediumLevelILInstruction,
        ) -> Tuple[int, Optional[bn.MediumLevelILVarSsa]]:
            if isinstance(inst, bn.MediumLevelILVarSsa):
                if inst.var.var in parm_vars:
                    return (parm_vars.index(inst.var.var), inst)
            return (-1, None)

        # Iterate instructions in the function
        for inst in func.instructions:
            for parm_idx, parm_inst in inst.traverse(find_mlil_parm_inst):
                if (
                    parm_idx >= 0
                    and parm_idx < len(parm_insts)
                    and parm_insts[parm_idx] is None
                    and parm_inst is not None
                ):
                    parm_insts[parm_idx] = parm_inst
            if None not in parm_insts:
                break
        return parm_insts

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
