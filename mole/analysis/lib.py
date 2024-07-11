import binaryninja     as bn
import re
from   typing          import Callable, List
from   ..common.helper import SymbolHelper
from   ..common.log    import Logger
from   ..model.slice   import MediumLevelILBackwardSlicer


class function:
    """
    This class implements general analysis testcases.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.function",
            log: Logger = Logger(),
            par_cnt: Callable[[int], bool] = lambda x: x >= 0,
            par_dataflow: Callable[[int], bool] = lambda x: False,
            src_sym_names: List[str] = [],
            snk_sym_names: List[str] = []
        ) -> None:
        self._bv = bv
        self._tag = tag
        self._log = log
        self._par_cnt = par_cnt
        self._par_dataflow = par_dataflow
        self._sources = SymbolHelper.get_code_refs(self._bv, src_sym_names)
        self._sinks = SymbolHelper.get_code_refs(self._bv, snk_sym_names)
        return
        
    def analyze_params(
            self
        ) -> None:
        """
        This method analyzes the function's parameters.
        """
        for snk_name, snk_insts in self._sinks.items():
            for snk_inst in snk_insts:
                self._log.info(self._tag, f"Analyze function '0x{snk_inst.address:x} {snk_name:s}'")
                # Ignore invalid calls
                if snk_inst.operation != bn.MediumLevelILOperation.MLIL_CALL_SSA:
                    self._log.warn(self._tag, f"0x{snk_inst.address:x} Ignore call '0x{snk_inst.address:x} {snk_name:s}' due to invalid call instruction")
                    continue
                # Ignore calls with an invalid number of parameters
                if not self._par_cnt(len(snk_inst.params)):
                    self._log.warn(self._tag, f"0x{snk_inst.address:x} Ignore call '0x{snk_inst.address:x} {snk_name:s}' due to invalid number of arguments")
                    continue
                # Analyze parameters
                for parm_num, parm_var in enumerate(snk_inst.params):
                    self._log.debug(self._tag, f"Analyze argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                    # Perform dataflow analysis
                    if self._par_dataflow(parm_num):
                        # Ignore constant parameters
                        if parm_var.operation != bn.MediumLevelILOperation.MLIL_VAR_SSA:
                            self._log.debug(self._tag, f"0x{snk_inst.address:x} Ignore constant argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                            continue
                        # Ignore parameters that can be determined with dataflow analysis
                        possible_sizes = parm_var.possible_values
                        if possible_sizes.type != bn.RegisterValueType.UndeterminedValue:
                            self._log.debug(self._tag, f"0x{snk_inst.address:x} Ignore dataflow determined argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                            continue
                    # Backward slice the parameter
                    slicer = MediumLevelILBackwardSlicer(self._bv, self._tag, self._log)
                    slicer.slice_backwards(parm_var)
                    # Check whether the slice contains any source
                    for src_name, src_insts in self._sources.items():
                        for src_inst in src_insts:
                            if slicer.includes(src_inst):
                                t_src = f"0x{src_inst.address:x} {src_name}"
                                t_src = f"{t_src:s}()"
                                t_snk = f"0x{snk_inst.address:x} {snk_name}"
                                t_snk = f"{t_snk:s}(arg#{parm_num+1:d}:{str(parm_var):s})"
                                self._log.info(
                                    self._tag,
                                    f"Interesting path: {t_src:s} --> {t_snk:s}!"
                                )
        return
    
    def analyze_all(
            self
        ) -> None:
        """
        This method runs all implemented analyses at once.
        """
        self.analyze_params()
        return