import binaryninja         as bn
from   typing              import List
from   ..common.log        import Logger
from   ..model.back_slicer import MediumLevelILVarSsaSlicer
from   ..model.helper      import SymbolHelper


class LibcMemcpy:
    """
    This class implements analysis testcases for `libc` function `memcpy`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            source_symbol_names: List[str] = [],
            tag: str = "Libc.Memcpy",
        ) -> None:
        """
        This method initializes instances of class `LibcMemcpy`.
        """
        self.bv = bv
        self.tag = tag
        self.synopsis = "void* memcpy(void* dest, const void* src, size_t n)"
        self.sources = SymbolHelper.get_code_refs(bv, source_symbol_names)
        self.sinks = SymbolHelper.get_code_refs(bv, ["memcpy", "__builtin_memcpy"])
        return
    
    def analyze_param_n(
            self
        ) -> None:
        """
        This method analyzes `memcpy` parameter `n`.
        """
        for symbol_name, sink_exprs in self.sinks.items():
            Logger.info(self.tag, f"Start analyzing '{symbol_name:s}' parameter 'n'...")
            for sink_expr in sink_exprs:
                # Skip invalid `memcpy` calls
                if sink_expr.operation != bn.MediumLevelILOperation.MLIL_CALL_SSA:
                    Logger.warn(self.tag, f"0x{sink_expr.address:x} (Ignore - not a call instruction)")
                    continue
                if len(sink_expr.params) != 3:
                    Logger.warn(self.tag, f"0x{sink_expr.address:x} (Ignore - invalid number of parameters)")
                    continue
                # Ignore `memcpy` calls with a constant `n` parameter
                n_param = sink_expr.params[2]
                if n_param.operation != bn.MediumLevelILOperation.MLIL_VAR_SSA:
                    Logger.debug(self.tag, f"0x{sink_expr.address:x} (Ignore - `n` parameter is constant)")
                    continue
                # Ignore `memcpy` calls where the `n` parameter can be determined with dataflow analysis
                possible_sizes = n_param.possible_values
                if possible_sizes.type != bn.RegisterValueType.UndeterminedValue:
                    Logger.debug(self.tag, f"0x{sink_expr.address:x} (Ignore - `n` parameter determined with dataflow analysis)")
                    continue
                # TODO: Try hitting given sources by static backward slicing
                Logger.info(self.tag, f"0x{sink_expr.address:x} Sink '{symbol_name:s}' (SLICE START)")
                slicer = MediumLevelILVarSsaSlicer(self.bv, self.sources, self.tag)
                vars = slicer.slice_backwards(n_param)
                Logger.info(self.tag, f"0x{sink_expr.address:x} Sink '{symbol_name:s}' (SLICE STOP)")
            Logger.info(self.tag, f"... stop analyzing '{symbol_name:s}' parameter 'n'.")
        return
    
    def analyze_all(
            self
        ) -> None:
        """
        This method runs all implemented `memcpy` analyses at once.
        """
        self.analyze_param_n()
        return