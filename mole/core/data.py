from __future__    import annotations
from ..common.help import InstructionHelper, SymbolHelper
from ..common.log  import Logger
from .slice        import MediumLevelILBackwardSlicer
from dataclasses   import dataclass, field
from typing        import Callable, Dict, List, Set, Tuple
import binaryninja       as bn
import PySide6.QtWidgets as qtw


@dataclass
class Configuration:
    """
    This class is a representation of the data associated with the plugin's configuration.
    """
    sources: Dict[str, Library] = field(default_factory=dict)
    sinks: Dict[str, Library] = field(default_factory=dict)
    settings: Dict[str, WidgetSetting] = field(default_factory=dict)

    def __eq__(self, other: Configuration) -> bool:
        if not isinstance(other, Configuration):
            try:
                other = Configuration(**other)
            except:
                return False
        if len(self.sources) != len(other.sources): return False
        for lib_name, lib in self.sources.items():
            if not lib_name in other.sources: return False
            if lib != other.sources[lib_name]: return False
        if len(self.sinks) != len(other.sinks): return False
        for lib_name, lib in self.sinks.items():
            if not lib_name in other.sinks: return False
            if lib != other.sinks[lib_name]: return False
        if len(self.settings) != len(other.settings): return False
        for setting_name, setting in self.settings.items():
            if not setting_name in other.settings: return False
            if setting != other.settings[setting_name]: return False
        return True
    
    def to_dict(self) -> Dict:
        sources = {}
        for lib_name, lib in self.sources.items():
            sources[lib_name] = lib.to_dict()
        sinks = {}
        for lib_name, lib in self.sinks.items():
            sinks[lib_name] = lib.to_dict()
        settings = {}
        for setting_name, setting in self.settings.items():
            settings[setting_name] = setting.to_dict()
        return {
            "sources": sources,
            "sinks": sinks,
            "settings": settings
        }
    

@dataclass
class Library:
    """
    This class is a representation of the data associated with libraries.
    """
    name: str
    categories: Dict[str, Category] = field(default_factory=dict)

    def __eq__(self, other: Library) -> bool:
        if not isinstance(other, Library):
            try:
                other = Library(**other)
            except:
                return False
        if self.name != other.name: return False
        if len(self.categories) != len(other.categories): return False
        for cat_name, cat in self.categories.items():
            if not cat_name in other.categories: return False
            if cat != other.categories[cat_name]: return False
        return True
    
    def to_dict(self) -> Dict:
        categories = {}
        for cat_name, cat in self.categories.items():
            categories[cat_name] = cat.to_dict()
        return {
            "name": self.name,
            "categories": categories
        }


@dataclass
class Category:
    """
    This class is a representation of the data associated with categories.
    """
    name: str
    functions: Dict[str, Function] = field(default_factory=dict)

    def __eq__(self, other: Category) -> bool:
        if not isinstance(other, Category):
            try:
                other = Category(**other)
            except:
                return False
        if self.name != other.name: return False
        if len(self.functions) != len(other.functions): return False
        for fun_name, fun in self.functions.items():
            if not fun_name in other.functions: return False
            if fun != other.functions[fun_name]: return False
        return True

    def to_dict(self) -> Dict:
        functions = {}
        for fun_name, fun in self.functions.items():
            functions[fun_name] = fun.to_dict()
        return {
            "name": self.name,
            "functions": functions
        }
    

@dataclass
class Function:
    """
    This class is a representation of the data associated with functions.
    """
    name: str
    symbols: List[str]
    synopsis: str = ""
    enabled: bool = False
    par_cnt: str = ""
    par_cnt_fun: Callable[[int], bool] = None
    par_dataflow: str = ""
    par_dataflow_fun: Callable[[int], bool] = None
    par_slice: str = ""
    par_slice_fun: Callable[[int], bool] = None
    checkbox: qtw.QCheckBox = None

    def __eq__(self, other: Function) -> bool:
        if not isinstance(other, Function):
            try:
                other = Function(**other)
            except:
                return False
        return self.name == other.name
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "symbols": self.symbols,
            "synopsis": self.synopsis,
            "enabled": self.enabled,
            "par_cnt": self.par_cnt,
            "par_dataflow": self.par_dataflow,
            "par_slice": self.par_slice
        }
    

@dataclass
class SourceFunction(Function):
    """
    This class is a representation of the data associated with source functions.
    """
    target_insts: Dict[Tuple[int, str], Set[int, str]] = field(default_factory=dict)

    def __eq__(self, other: Function) -> bool:
        if not isinstance(other, SourceFunction):
            try:
                other = SourceFunction(**other)
            except:
                return False
        return super().__eq__(other)
    
    def find_targets(
            self,
            bv: bn.BinaryView,
            canceled: Callable[[], bool],
            tag: str = None,
            log: Logger = Logger()
        ) -> None:
        """
        This method finds a set of target instructions that a static backward slice should hit on.
        """
        code_refs = SymbolHelper.get_code_refs(
            bv,
            self.symbols,
            [
                bn.SymbolType.FunctionSymbol,
                bn.SymbolType.ImportedFunctionSymbol
            ]
        )
        for symbol_name, insts in code_refs.items():
            if canceled(): break
            for inst in insts:
                if canceled(): break
                log.info(tag, f"Analyze source function '0x{inst.address:x} {symbol_name:s}'")
                # Ignore everything but call instructions
                match inst:
                    case (bn.MediumLevelILCallSsa() |
                          bn.MediumLevelILTailcallSsa()):
                        s = self.target_insts.get((inst.address, symbol_name), set())
                        s.add(inst)
                        self.target_insts[(inst.address, symbol_name)] = s
                    case _:
                        continue
                # Ignore calls with an invalid number of parameters
                if not self.par_cnt_fun(len(inst.params)):
                    log.warn(tag, f"0x{inst.address:x} Ignore arguments of call '0x{inst.address:x} {symbol_name:s}' due to an unexpected amount")
                    continue
                # Analyze parameters
                for parm_num, parm_var in enumerate(inst.params):
                    if canceled(): break
                    log.debug(tag, f"Analyze argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                    # Perform dataflow analysis
                    if self.par_dataflow_fun(parm_num):
                        # Ignore constant parameters
                        if parm_var.operation != bn.MediumLevelILOperation.MLIL_VAR_SSA:
                            log.debug(tag, f"0x{inst.address:x} Ignore constant argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                            continue
                        # Ignore parameters that can be determined with dataflow analysis
                        possible_sizes = parm_var.possible_values
                        if possible_sizes.type != bn.RegisterValueType.UndeterminedValue:
                            log.debug(tag, f"0x{inst.address:x} Ignore dataflow determined argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                            continue
                    # Backward slice the parameter
                    if self.par_slice_fun(parm_num):
                        slicer = MediumLevelILBackwardSlicer(bv, 0, tag, log)
                        slicer.slice_backwards(parm_var)
                        # Add sliced instructions to target instructions
                        s = self.target_insts.get((inst.address, symbol_name), set())
                        s.update(slicer._sliced_insts)
                        self.target_insts[(inst.address, symbol_name)] = s
        return


@dataclass
class SinkFunction(Function):
    """
    This class is a representation of the data associated with sink functions.
    """

    def __eq__(self, other: Function) -> bool:
        if not isinstance(other, SinkFunction):
            try:
                other = SinkFunction(**other)
            except:
                return False
        return super().__eq__(other)

    def find_paths(
            self,
            bv: bn.BinaryView,
            sources: List[SourceFunction],
            max_func_depth: int,
            found_path: Callable[[Path], None],
            canceled: Callable[[], bool],
            tag: str = None,
            log: Logger = Logger()
        ) -> List[Path]:
        """
        This method tries to find paths, starting from the current sink and ending in one of the
        given `sources` using static backward slicing.
        """
        paths = []
        code_refs = SymbolHelper.get_code_refs(
            bv,
            self.symbols,
            [
                bn.SymbolType.FunctionSymbol,
                bn.SymbolType.ImportedFunctionSymbol
            ]
        )
        for snk_name, snk_insts in code_refs.items():
            if canceled(): break
            for snk_inst in snk_insts:
                if canceled(): break
                log.info(tag, f"Analyze sink function '0x{snk_inst.address:x} {snk_name:s}'")
                # Ignore everything but call instructions
                match snk_inst:
                    case (bn.MediumLevelILCallSsa() |
                          bn.MediumLevelILTailcallSsa()):
                        pass
                    case _:
                        continue
                # Ignore calls with an invalid number of parameters
                if not self.par_cnt_fun(len(snk_inst.params)):
                    log.warn(tag, f"0x{snk_inst.address:x} Ignore call '0x{snk_inst.address:x} {snk_name:s}' due to invalid number of arguments ({len(snk_inst.params):d})")
                    continue
                # Analyze parameters
                for par_idx, par_var in enumerate(snk_inst.params):
                    if canceled(): break
                    log.debug(tag, f"Analyze argument 'arg#{par_idx+1:d}:{str(par_var):s}'")
                    # Perform dataflow analysis
                    if self.par_dataflow_fun(par_idx):
                        # Ignore constant parameters
                        if par_var.operation != bn.MediumLevelILOperation.MLIL_VAR_SSA:
                            log.debug(tag, f"0x{snk_inst.address:x} Ignore constant argument 'arg#{par_idx+1:d}:{str(par_var):s}'")
                            continue
                        # Ignore parameters that can be determined with dataflow analysis
                        possible_sizes = par_var.possible_values
                        if possible_sizes.type != bn.RegisterValueType.UndeterminedValue:
                            log.debug(tag, f"0x{snk_inst.address:x} Ignore dataflow determined argument 'arg#{par_idx+1:d}:{str(par_var):s}'")
                            continue
                    # Backward slice the parameter
                    if self.par_slice_fun(par_idx):
                        slicer = MediumLevelILBackwardSlicer(bv, max_func_depth, self.name, log)
                        try:
                            slice = slicer.slice_backwards(par_var)
                        except Exception as e:
                            log.error(tag, f"Exception: {str(e):s}")
                            continue
                        # Check whether the slice contains any source
                        for source in sources:
                            if canceled(): break
                            for (src_sym_addr, src_sym_name), src_insts in source.target_insts.items():
                                if canceled(): break
                                for src_inst in src_insts:
                                    if canceled(): break
                                    if slicer.includes(src_inst):
                                        # Calculate slice's instructions and branch dependencies
                                        insts = [snk_inst]
                                        bdeps = {}
                                        path_found = False
                                        for inst in slice.keys():
                                            insts.append(inst)
                                            if inst == src_inst:
                                                log.info(tag, f"Found path from '0x{src_inst.address:x} {src_sym_name:s}' to '0x{snk_inst.address:x} {snk_name:s}'")
                                                path_found = True
                                                break
                                            for bch_idx, bch_dep in inst.branch_dependence.items():
                                                bdeps.setdefault(bch_idx, bch_dep)
                                        if not path_found:
                                            log.warn(tag, f"Path from '0x{src_inst.address:x} {src_sym_name:s}' to '0x{snk_inst.address:x} {snk_name:s}' not found")
                                            continue
                                        # Store path
                                        path = Path(
                                            src_sym_addr=src_sym_addr,
                                            src_sym_name=src_sym_name,
                                            snk_sym_addr=snk_inst.address,
                                            snk_sym_name=snk_name,
                                            snk_par_idx=par_idx,
                                            snk_par_var=par_var,
                                            insts=insts,
                                            bdeps=bdeps
                                        )
                                        paths.append(path)
                                        found_path(path)
                                        # Log path
                                        t_log = f"Interesting path: {str(path):s}"
                                        t_log = f"{t_log:s} [L:{len(insts):d},B:{len(bdeps):d}]!"
                                        log.info(tag, t_log)
                                        log.debug(tag, "--- Backward Slice ---")
                                        basic_block = None
                                        last_function = None
                                        fn_call_stack = []
                                        for inst in insts:
                                            if inst.il_basic_block != basic_block:
                                                basic_block = inst.il_basic_block
                                                if last_function != basic_block.function:
                                                    last_function = basic_block.function
                                                    fn_call_stack.insert(0, last_function)
                                                fun_name = basic_block.function.name
                                                bb_addr = basic_block[0].address
                                                log.info(tag, f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}")
                                            log.debug(tag, InstructionHelper.get_inst_info(inst))
                                        log.debug(tag, "----------------------")
                                        path.fn_call_stack = fn_call_stack
        return paths


@dataclass
class Path:
    """
    This class is a representation of the data associated with identified paths.
    """
    src_sym_addr: int
    src_sym_name: str
    snk_sym_addr: int
    snk_sym_name: str
    snk_par_idx: int
    snk_par_var: bn.MediumLevelILVarSsa
    insts: List[bn.MediumLevelILInstruction] = field(default_factory=list)
    bdeps: Dict[int, bn.ILBranchDependence] = field(default_factory=dict)
    fn_call_stack: List[bn.Function] = field(default_factory=list)

    def __eq__(self, other: Path) -> bool:
        if not isinstance(other, Path):
            try:
                other = Path(**other)
            except:
                return False
        return (
            self.src_sym_addr == other.src_sym_addr and
            self.src_sym_name == other.src_sym_name and
            self.snk_sym_addr == other.snk_sym_addr and
            self.snk_sym_name == other.snk_sym_name and
            self.snk_par_idx  == other.snk_par_idx  and
            self.snk_par_var  == other.snk_par_var  and
            self.insts        == other.insts        and
            self.bdeps        == other.bdeps
        )
    
    def __str__(self) -> str:
        src = f"0x{self.src_sym_addr:x} {self.src_sym_name:s}"
        # hops: number of functions in the call stack
        # callers: number of callers for the first function in the call stack (the source)
        stats = f"{len(self.fn_call_stack)}h"
        # we care more about the source caller than the source itself
        if len(self.fn_call_stack) > 1 and len(self.fn_call_stack[0].callers) > 0:
            src = f"{self.fn_call_stack[0].callers[0].name:s}({src:s})"
            stats += f",{len(self.fn_call_stack[0].callers):d}c"

        snk = f"0x{self.snk_sym_addr:x} {self.snk_sym_name:s}"
        snk = f"{snk:s}(arg#{self.snk_par_idx+1:d}:{str(self.snk_par_var):s})"
        
        return f"{src:s} --> {snk:s} [{stats}]"


@dataclass
class WidgetSetting:
    """
    This class is a representation of the data associated with a widget.
    """
    name: str
    value: int | str
    help: str
    widget: qtw.QWidget = None

    def __eq__(self, other: WidgetSetting) -> bool:
        if not isinstance(other, WidgetSetting):
            try:
                other = WidgetSetting(**other)
            except:
                return False
        return self.name == other.name
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "value": self.value,
            "help": self.help
        }


@dataclass
class SpinboxSetting(WidgetSetting):
    """
    This class is a representation of the data associated with a spinbox widget.
    """
    min_value: int = field(default_factory=int)
    max_value: int = field(default_factory=int)
    widget: qtw.QSpinBox = None

    def __eq__(self, other: SpinboxSetting) -> bool:
        if not isinstance(other, SpinboxSetting):
            try:
                other = SpinboxSetting(**other)
            except:
                return False
        return super().__eq__(other)
    
    def to_dict(self) -> Dict:
        d = super().to_dict()
        d.update({
            "min_value": self.min_value,
            "max_value": self.max_value
        })
        return d


@dataclass
class ComboboxSetting(WidgetSetting):
    """
    This class is a representation of the data associated with a combobox widget.
    """
    items: List[str] = field(default_factory=list)
    widget: qtw.QComboBox = None

    def __eq__(self, other: ComboboxSetting) -> bool:
        if not isinstance(other, ComboboxSetting):
            try:
                other = ComboboxSetting(**other)
            except:
                return False
        return super().__eq__(other)
    
    def to_dict(self) -> Dict:
        d = super().to_dict()
        d.update({
            "items": self.items
        })
        return d