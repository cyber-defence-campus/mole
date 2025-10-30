from __future__ import annotations
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
                rdata = bv.sections.get(".rdata")
                in_rdata = rdata.start <= symbol.address < rdata.end if rdata else False
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
                if not (in_code or in_rdata or in_idata or in_synthetic_builtins):
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
