from __future__       import annotations
from enum             import Enum
from typing           import Callable, List, Tuple
from ..analysis.slice import MediumLevelILBackwardSlicer
from ..common.helper  import SymbolHelper
from ..common.log     import Logger
import binaryninja as bn


class categories(Enum):
    """
    This class lists different function categories.
    """
    oth = "Others"
    # Sources
    env = "Environment Accesses"
    chr = "Character Inputs"
    lin = "Line Inputs"
    fmt = "Formatted Inputs"
    fad = "File and Directories"
    net = "Networks"
    # Sinks
    mem = "Memory Copy"
    scp = "String Copy"
    cat = "String Concatenation"
    sfc = "String Format Conversion"


class func:
    """
    This class represents a generic function.
    """

    def __init__(
            self,
            lib: str = "lib",
            name: str = "func",
            synopsis: str = "void func()",
            description: str = "Generic function",
            category: categories = categories.oth,
            symbols: List[str] = [],
            enabled: bool = False,
            log: Logger = Logger()
        ) -> None:
        self.lib = lib
        self.name = name
        self.synopsis = synopsis
        self.description = description
        self.category = category
        self.symbols = symbols
        self.enabled = enabled
        self._log = log
        return
    
    def __str__(self) -> str:
        return f"{self.lib:s}.{self.name:s}"

    
class src_func(func):
    """
    This class represents a generic source function.
    """

    def __init__(
            self,
            lib: str = "lib",
            name: str = "src_func",
            synopsis: str = "void src_func()",
            description: str = "Generic source function",
            category: categories = categories.oth,
            symbols: List[str] = [],
            enabled: bool = False,
            log: Logger = Logger(),
            par_cnt: Callable[[int], bool] = lambda x: x >= 0,
            par_dataflow: Callable[[int], bool] = lambda x: False,
            par_slice: Callable[[int], bool] = lambda x: False
        ) -> None:
        super().__init__(lib, name, synopsis, description, category, symbols, enabled, log)
        self._par_cnt = par_cnt
        self._par_dataflow = par_dataflow
        self._par_slice = par_slice
        self._target_insts = {}
        return
    
    def find_targets(
            self,
            bv: bn.BinaryView,
            canceled: Callable[[], bool]
        ) -> None:
        """
        This method finds a set of target instructions that a static backward slice should hit on.
        """
        code_refs = SymbolHelper.get_code_refs(bv, self.symbols)
        for symbol_name, insts in code_refs.items():
            if canceled(): break
            for inst in insts:
                if canceled(): break
                self._log.info(str(self), f"Analyze source function '0x{inst.address:x} {symbol_name:s}'")
                # Ignore everything but call instructions
                match inst:
                    case (bn.MediumLevelILCallSsa() |
                          bn.MediumLevelILTailcallSsa()):
                        s = self._target_insts.get((inst.address, symbol_name), set())
                        s.add(inst)
                        self._target_insts[(inst.address, symbol_name)] = s
                    case _:
                        continue
                # Ignore calls with an invalid number of parameters
                if not self._par_cnt(len(inst.params)):
                    self._log.warn(str(self), f"0x{inst.address:x} Ignore arguments of call '0x{inst.address:x} {symbol_name:s}' due to an unexpected amount")
                    continue
                # Analyze parameters
                for parm_num, parm_var in enumerate(inst.params):
                    if canceled(): break
                    self._log.debug(str(self), f"Analyze argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                    # Perform dataflow analysis
                    if self._par_dataflow(parm_num):
                        # Ignore constant parameters
                        if parm_var.operation != bn.MediumLevelILOperation.MLIL_VAR_SSA:
                            self._log.debug(str(self), f"0x{inst.address:x} Ignore constant argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                            continue
                        # Ignore parameters that can be determined with dataflow analysis
                        possible_sizes = parm_var.possible_values
                        if possible_sizes.type != bn.RegisterValueType.UndeterminedValue:
                            self._log.debug(str(self), f"0x{inst.address:x} Ignore dataflow determined argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                            continue
                    # Backward slice the parameter
                    if self._par_slice(parm_num):
                        slicer = MediumLevelILBackwardSlicer(bv, 0, str(self), self._log)
                        slicer.slice_backwards(parm_var)
                        # Add sliced instructions to target instructions
                        s = self._target_insts.get((inst.address, symbol_name), set())
                        s.update(slicer._sliced_insts)
                        self._target_insts[(inst.address, symbol_name)] = s
        return


class snk_func(func):
    """
    This class represents a generic sink function.
    """

    def __init__(
            self,
            lib: str = "lib",
            name: str = "snk_func",
            synopsis: str = "void snk_func()",
            description: str = "Generic sink function",
            category: categories = categories.oth,
            symbols: List[str] = [],
            enabled: bool = False,
            log: Logger = Logger(),
            par_cnt: Callable[[int], bool] = lambda x: x >= 0,
            par_dataflow: Callable[[int], bool] = lambda x: False,
            par_slice: Callable[[int], bool] = lambda x: True
        ) -> None:
        super().__init__(lib, name, synopsis, description, category, symbols, enabled, log)
        self._par_cnt = par_cnt
        self._par_dataflow = par_dataflow
        self._par_slice = par_slice
        return
    
    def find_paths(
            self,
            bv: bn.BinaryView,
            sources: List[src_func],
            max_func_depth: int,
            canceled: Callable[[], bool]
        ) -> List[Tuple[
                str, bn.MediumLevelILInstruction,
                str, bn.MediumLevelILInstruction,
                int, bn.SSAVariable
            ]]:
        """
        This method tries to find paths, starting from the current sink and ending in one of the
        given `sources`, using static backward slicing.
        """
        paths = []
        code_refs = SymbolHelper.get_code_refs(bv, self.symbols)
        for snk_name, snk_insts in code_refs.items():
            if canceled(): break
            for snk_inst in snk_insts:
                if canceled(): break
                self._log.info(str(self), f"Analyze sink function '0x{snk_inst.address:x} {snk_name:s}'")
                # Ignore everything but call instructions
                match snk_inst:
                    case (bn.MediumLevelILCallSsa() |
                          bn.MediumLevelILTailcallSsa()):
                        pass
                    case _:
                        continue
                # Ignore calls with an invalid number of parameters
                if not self._par_cnt(len(snk_inst.params)):
                    self._log.warn(str(self), f"0x{snk_inst.address:x} Ignore call '0x{snk_inst.address:x} {snk_name:s}' due to invalid number of arguments")
                    continue
                # Analyze parameters
                for parm_num, parm_var in enumerate(snk_inst.params):
                    if canceled(): break
                    self._log.debug(str(self), f"Analyze argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                    # Perform dataflow analysis
                    if self._par_dataflow(parm_num):
                        # Ignore constant parameters
                        if parm_var.operation != bn.MediumLevelILOperation.MLIL_VAR_SSA:
                            self._log.debug(str(self), f"0x{snk_inst.address:x} Ignore constant argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                            continue
                        # Ignore parameters that can be determined with dataflow analysis
                        possible_sizes = parm_var.possible_values
                        if possible_sizes.type != bn.RegisterValueType.UndeterminedValue:
                            self._log.debug(str(self), f"0x{snk_inst.address:x} Ignore dataflow determined argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                            continue
                    # Backward slice the parameter
                    if self._par_slice(parm_num):
                        slicer = MediumLevelILBackwardSlicer(bv, max_func_depth, self.name, self._log)
                        try:
                            slicer.slice_backwards(parm_var)
                        except Exception as e:
                            self._log.error(str(self), f"Exception: {str(e):s}")
                        # Check whether the slice contains any source
                        for source in sources:
                            if canceled(): break
                            for (sym_addr, sym_name), src_insts in source._target_insts.items():
                                if canceled(): break
                                for src_inst in src_insts:
                                    if canceled(): break
                                    if slicer.includes(src_inst):
                                        t_src = f"0x{sym_addr:x} {sym_name:s}()"
                                        t_snk = f"0x{snk_inst.address:x} {snk_name}"
                                        t_snk = f"{t_snk:s}(arg#{parm_num+1:d}:{str(parm_var):s})"
                                        self._log.info(
                                            str(self),
                                            f"Interesting path: {t_src:s} --> {t_snk:s}!"
                                        )
                                        paths.append((sym_name, src_inst, snk_name, snk_inst, parm_num, parm_var))
        return paths