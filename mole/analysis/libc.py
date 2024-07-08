import binaryninja         as bn
from   typing              import List
from   ..common.helper     import InstructionHelper, SymbolHelper
from   ..common.log        import Logger
from   ..model.slice       import MediumLevelILBackwardSlicer


class LibcMemcpy:
    """
    This class implements analysis testcases for `libc` function `memcpy`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            source_symbol_names: List[str] = [],
            tag: str = "Libc.Memcpy",
            log: Logger = Logger()
        ) -> None:
        """
        This method initializes instances of class `LibcMemcpy`.
        """
        self.bv = bv
        self.tag = tag
        self.log = log
        self.synopsis = "void* memcpy(void* dest, const void* src, size_t n)"
        self.sources = SymbolHelper.get_code_refs(bv, source_symbol_names)
        self.sinks = SymbolHelper.get_code_refs(bv, ["memcpy", "__builtin_memcpy"])
        return
    
    def analyze_param_dest(
            self
        ) -> None:
        """
        This method analyzes the `memcpy` parameter `dest`.
        """
        for snk_name, snk_insts in self.sinks.items():
            for snk_inst in snk_insts:
                snk_info = InstructionHelper.get_inst_info(snk_inst)
                self.log.info(self.tag, f"Start analyzing '0x{snk_inst.address:x} {snk_name:s}' parameter 'dest'...")
                # Skip invalid `memcpy` calls
                if snk_inst.operation != bn.MediumLevelILOperation.MLIL_CALL_SSA:
                    self.log.warn(self.tag, f"{snk_info:s}: Ignore - not a call instruction")
                    continue
                if len(snk_inst.params) != 3:
                    self.log.warn(self.tag, f"{snk_info:s}: Ignore - invalid number of parameters")
                    continue
                # Backward slice the `dest` parameter
                dest_param = snk_inst.params[0]
                slicer = MediumLevelILBackwardSlicer(self.bv, self.tag, self.log)
                slicer.slice_backwards(dest_param)
                # Check whether the slice contains any source
                for src_name, src_insts in self.sources.items():
                    for src_inst in src_insts:
                        if slicer.includes(src_inst):
                            self.log.info(self.tag, f"Interesting path: 0x{src_inst.address:x} {src_name} --> 0x{snk_inst.address:x} {snk_name}!")
                self.log.info(self.tag, f"... stop analyzing '0x{snk_inst.address:x} {snk_name:s}' parameter 'dest'.")
        return
    
    def analyze_param_src(
            self
        ) -> None:
        """
        This method analyzes the `memcpy` parameter `src`.
        """
        for snk_name, snk_insts in self.sinks.items():
            for snk_inst in snk_insts:
                snk_info = InstructionHelper.get_inst_info(snk_inst)
                self.log.info(self.tag, f"Start analyzing '0x{snk_inst.address:x} {snk_name:s}' parameter 'src'...")
                # Skip invalid `memcpy` calls
                if snk_inst.operation != bn.MediumLevelILOperation.MLIL_CALL_SSA:
                    self.log.warn(self.tag, f"{snk_info:s}: Ignore - not a call instruction")
                    continue
                if len(snk_inst.params) != 3:
                    self.log.warn(self.tag, f"{snk_info:s}: Ignore - invalid number of parameters")
                    continue
                # Backward slice the `src` parameter
                src_param = snk_inst.params[1]
                slicer = MediumLevelILBackwardSlicer(self.bv, self.tag, self.log)
                slicer.slice_backwards(src_param)
                # Check whether the slice contains any source
                for src_name, src_insts in self.sources.items():
                    for src_inst in src_insts:
                        if slicer.includes(src_inst):
                            self.log.info(self.tag, f"Interesting path: 0x{src_inst.address:x} {src_name} --> 0x{snk_inst.address:x} {snk_name}!")
                self.log.info(self.tag, f"... stop analyzing '0x{snk_inst.address:x} {snk_name:s}' parameter 'src'.")
        return
    
    def analyze_param_n(
            self
        ) -> None:
        """
        This method analyzes `memcpy` parameter `n`.
        """
        for snk_name, snk_insts in self.sinks.items():
            for snk_inst in snk_insts:
                snk_info = InstructionHelper.get_inst_info(snk_inst)
                self.log.info(self.tag, f"Start analyzing '0x{snk_inst.address:x} {snk_name:s}' parameter 'n'...")
                # Skip invalid `memcpy` calls
                if snk_inst.operation != bn.MediumLevelILOperation.MLIL_CALL_SSA:
                    self.log.warn(self.tag, f"{snk_info:s}: Ignore - not a call instruction")
                    continue
                if len(snk_inst.params) != 3:
                    self.log.warn(self.tag, f"{snk_info:s}: Ignore - invalid number of parameters")
                    continue
                # Ignore `memcpy` calls with a constant `n` parameter
                n_param = snk_inst.params[2]
                if n_param.operation != bn.MediumLevelILOperation.MLIL_VAR_SSA:
                    self.log.debug(self.tag, f"{snk_info:s}: Ignore - `n` parameter is constant")
                    continue
                # Ignore `memcpy` calls where the `n` parameter can be determined with dataflow analysis
                possible_sizes = n_param.possible_values
                if possible_sizes.type != bn.RegisterValueType.UndeterminedValue:
                    self.log.debug(self.tag, f"{snk_info:s}: Ignore - `n` parameter determined with dataflow analysis")
                    continue
                # Backward slice the `n` parameter
                slicer = MediumLevelILBackwardSlicer(self.bv, self.tag, self.log)
                slicer.slice_backwards(n_param)
                # Check whether the slice contains any source
                for src_name, src_insts in self.sources.items():
                    for src_inst in src_insts:
                        if slicer.includes(src_inst):
                            self.log.info(self.tag, f"Interesting path: 0x{src_inst.address:x} {src_name} --> 0x{snk_inst.address:x} {snk_name}!")
                self.log.info(self.tag, f"... stop analyzing '0x{snk_inst.address:x} {snk_name:s}' parameter 'n'.")
        return
    
    def analyze_all(
            self
        ) -> None:
        """
        This method runs all implemented `memcpy` analyses at once.
        """
        self.analyze_param_dest()
        self.analyze_param_src()
        self.analyze_param_n()
        return