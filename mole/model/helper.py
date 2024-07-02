import binaryninja  as bn
from   typing       import Dict, List, Set


class SymbolHelper:
    """
    This class provides helper functions with respect to symbols.
    """

    @staticmethod
    def get_code_refs(
            bv: bn.BinaryView,
            symbol_names: List[str]
        ) -> Dict[str, Set[bn.MediumLevelILInstruction]]:
        """
        This method determines code references for the provided `symbol_names`. The returned
        dictionary contains individual `symbol_names` as keys, and the corresponding code references
        as values. Code references correspond to `bn.MediumLevelILInstruction`s in SSA form.
        """
        mlil_ssa_code_refs = {}
        for symbol_name in symbol_names:
            for symbol in bv.symbols.get(symbol_name, []):
                for code_ref in bv.get_code_refs(symbol.address):
                    llil_instr = code_ref.function.get_low_level_il_at(code_ref.address)
                    if llil_instr is None: continue
                    mlil_instr = llil_instr.mlil
                    if mlil_instr is None: continue
                    mlil_ssa_instr = mlil_instr.ssa_form
                    if mlil_ssa_instr is None: continue
                    mlil_ssa_instrs = mlil_ssa_code_refs.get(symbol_name, set())
                    mlil_ssa_instrs.add(mlil_ssa_instr)
                    mlil_ssa_code_refs[symbol_name] = mlil_ssa_instrs
        return mlil_ssa_code_refs