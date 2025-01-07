from __future__ import annotations
from typing     import Dict, List, Optional, Set
import binaryninja as bn


class SymbolHelper:
    """
    This class provides helper functions with respect to symbols.
    """
    
    @staticmethod
    def get_symbol_by_section(
            bv: bn.BinaryView,
            symbol_name: str,
            section_name: str = ".plt"
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
            bv: bn.BinaryView,
            symbol_names: List[str],
            symbol_types: List[bn.SymbolType]
        ) -> Dict[str, Set[bn.MediumLevelILInstruction]]:
        """
        This method determines code references for the provided `symbol_names`. Only symbols having
        a type included in `symbol_types` are considered. The returned dictionary contains
        individual `symbol_names` as keys, and the corresponding code references as values. Code
        references correspond to `bn.MediumLevelILInstruction`s in SSA form.
        """
        mlil_ssa_code_refs = {}
        for symbol_name in symbol_names:
            for symbol in bv.symbols.get(symbol_name, []):
                if symbol.type not in symbol_types: continue
                for code_ref in bv.get_code_refs(symbol.address):
                    mlil_ssa_code_refs[symbol_name] = [code_ref.mlil.ssa_form]
        return mlil_ssa_code_refs


class InstructionHelper:
    """
    This class provides helper functions with respect to instructions.
    """

    @staticmethod
    def get_inst_info(
            inst: bn.MediumLevelILInstruction    
        ) -> str:
        """
        This method returns a string with information about the instruction `inst`.
        """
        return f"0x{inst.instr.address:x} {str(inst):s} ({inst.__class__.__name__:s})"