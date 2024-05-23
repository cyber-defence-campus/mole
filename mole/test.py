from binaryninja import BinaryView, MediumLevelILInstruction
from typing      import List
from .common.log import Logger


class Source:
    """
    """
    pass


class Sink:
    """
    """

    def __init__(self, bv: BinaryView, symbol_names: List[str]) -> None:
        self._bv = bv
        self._symbol_names = symbol_names
        self._mlil_insts = self._get_mlil_insts()
        return
    
    def _get_mlil_insts(self) -> List[MediumLevelILInstruction]:
        """
        Get MLIL instructions of all symbols' code references.
        """
        mlil_insts = [] 
        for symbol_name in self._symbol_names:
            for symbol in self._bv.symbols.get(symbol_name, []):
                for code_ref in self._bv.get_code_refs(symbol.address):
                    inst = code_ref.function.get_low_level_il_at(code_ref.address).medium_level_il
                    if inst is None: continue
                    mlil_insts.append(inst)
                    Logger.debug("Sink", f"0x{inst.address:x} ({symbol.name:s})")
        return mlil_insts


class ReverseTracker:
    """
    """
    pass