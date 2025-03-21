from __future__          import annotations
from ..common.help       import InstructionHelper, SymbolHelper
from .slice              import MediumLevelILBackwardSlicer, MediumLevelILFunctionGraph
from dataclasses         import dataclass, field
from mole.common.log     import log
from typing              import Callable, Dict, List, Tuple
import binaryninja       as bn
import PySide6.QtWidgets as qtw


tag = "Mole.Data"


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
            except Exception as _:
                return False
        if len(self.sources) != len(other.sources): 
            return False
        for lib_name, lib in self.sources.items():
            if lib_name not in other.sources: 
                return False
            if lib != other.sources[lib_name]: 
                return False
        if len(self.sinks) != len(other.sinks): 
            return False
        for lib_name, lib in self.sinks.items():
            if lib_name not in other.sinks: 
                return False
            if lib != other.sinks[lib_name]: 
                return False
        if len(self.settings) != len(other.settings): 
            return False
        for setting_name, setting in self.settings.items():
            if setting_name not in other.settings: 
                return False
            if setting != other.settings[setting_name]: 
                return False
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
            except Exception as _:
                return False
        if self.name != other.name: 
            return False
        if len(self.categories) != len(other.categories): 
            return False
        for cat_name, cat in self.categories.items():
            if cat_name not in other.categories: 
                return False
            if cat != other.categories[cat_name]: 
                return False
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
            except Exception as _:
                return False
        if self.name != other.name: 
            return False
        if len(self.functions) != len(other.functions): 
            return False
        for fun_name, fun in self.functions.items():
            if fun_name not in other.functions: 
                return False
            if fun != other.functions[fun_name]: 
                return False
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
            except Exception as _:
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
    target_insts: Dict[Tuple[int, str], List[bn.MediumLevelILInstruction]] = field(default_factory=dict)

    def __eq__(self, other: Function) -> bool:
        if not isinstance(other, SourceFunction):
            try:
                other = SourceFunction(**other)
            except Exception as _:
                return False
        return super().__eq__(other)
    
    def find_targets(
            self,
            bv: bn.BinaryView,
            canceled: Callable[[], bool]
        ) -> None:
        """
        This method finds a set of target instructions that a static backward slice should hit on.
        """
        custom_tag = f"{tag:s}] [{self.name:s}"
        self.target_insts.clear()
        code_refs = SymbolHelper.get_code_refs(
            bv,
            self.symbols,
            [
                bn.SymbolType.FunctionSymbol,
                bn.SymbolType.ImportedFunctionSymbol
            ]
        )
        for src_name, src_insts in code_refs.items():
            if canceled(): 
                break
            for src_inst in src_insts:
                if canceled(): 
                    break
                log.info(
                    custom_tag,
                    f"Analyze source function '0x{src_inst.address:x} {src_name:s}'"
                )
                # Ignore everything but call instructions
                match src_inst:
                    case (bn.MediumLevelILCallSsa() |
                          bn.MediumLevelILTailcallSsa()):
                        self.target_insts.setdefault((src_inst.address, src_name), []).append(src_inst)
                    case _:
                        continue
                # Ignore calls with an invalid number of parameters
                if not self.par_cnt_fun(len(src_inst.params)):
                    log.warn(
                        custom_tag,
                        f"0x{src_inst.address:x} Ignore arguments of call '0x{src_inst.address:x} {src_name:s}' due to an unexpected amount"
                    )
                    continue
                # Analyze parameters
                for par_idx, par_var in enumerate(src_inst.params):
                    if canceled():
                        break
                    par_idx += 1
                    log.debug(
                        custom_tag,
                        f"Analyze argument 'arg#{par_idx:d}:{str(par_var):s}'"
                    )
                    # Perform dataflow analysis
                    if self.par_dataflow_fun(par_idx):
                        # Ignore constant parameters
                        if par_var.operation != bn.MediumLevelILOperation.MLIL_VAR_SSA:
                            log.debug(
                                custom_tag,
                                f"0x{src_inst.address:x} Ignore constant argument 'arg#{par_idx:d}:{str(par_var):s}'"
                            )
                            continue
                        # Ignore parameters that can be determined with dataflow analysis
                        possible_sizes = par_var.possible_values
                        if possible_sizes.type != bn.RegisterValueType.UndeterminedValue:
                            log.debug(
                                custom_tag,
                                f"0x{src_inst.address:x} Ignore dataflow determined argument 'arg#{par_idx:d}:{str(par_var):s}'"
                            )
                            continue
                    # Backward slice the parameter
                    if self.par_slice_fun(par_idx):
                        slicer = MediumLevelILBackwardSlicer(bv, 0)
                        slicer.slice_backwards(par_var)
                        # Add sliced instructions to the target instructions
                        addr_src_list = self.target_insts.setdefault((src_inst.address, src_name), [])
                        for inst in slicer.get_insts():
                            if inst not in addr_src_list:
                                addr_src_list.append(inst)
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
            except Exception as _:
                return False
        return super().__eq__(other)
    
    def find_paths(
            self,
            bv: bn.BinaryView,
            sources: List[SourceFunction],
            max_call_level: int,
            max_slice_depth: int,
            found_path: Callable[[Path], None],
            canceled: Callable[[], bool]
        ) -> List[Path]:
        """
        This method tries to find paths, starting from the current sink and ending in one of the
        given `sources` using static backward slicing.
        """
        paths = []
        custom_tag = f"{tag:s}] [{self.name:s}"
        code_refs = SymbolHelper.get_code_refs(
            bv,
            self.symbols,
            [
                bn.SymbolType.FunctionSymbol,
                bn.SymbolType.ImportedFunctionSymbol
            ]
        )
        for snk_name, snk_insts in code_refs.items():
            if canceled(): 
                break
            for snk_inst in snk_insts:
                if canceled(): 
                    break
                log.info(
                    custom_tag,
                    f"Analyze sink function '0x{snk_inst.address:x} {snk_name:s}'"
                )
                # Ignore everything but call instructions
                match snk_inst:
                    case (bn.MediumLevelILCallSsa() |
                          bn.MediumLevelILTailcallSsa()):
                        pass
                    case _:
                        continue
                # Ignore calls with an invalid number of parameters
                if not self.par_cnt_fun(len(snk_inst.params)):
                    log.warn(
                        custom_tag,
                        f"0x{snk_inst.address:x} Ignore call '0x{snk_inst.address:x} {snk_name:s}' due to invalid number of arguments"
                    )
                    continue
                # Analyze parameters
                for par_idx, par_var in enumerate(snk_inst.params):
                    if canceled():
                        break
                    par_idx += 1
                    log.debug(
                        custom_tag,
                        f"Analyze argument 'arg#{par_idx:d}:{str(par_var):s}'"
                    )
                    # Perform dataflow analysis
                    if self.par_dataflow_fun(par_idx):
                        # Ignore constant parameters
                        if par_var.operation != bn.MediumLevelILOperation.MLIL_VAR_SSA:
                            log.debug(
                                custom_tag,
                                f"0x{snk_inst.address:x} Ignore constant argument 'arg#{par_idx:d}:{str(par_var):s}'"
                            )
                            continue
                        # Ignore parameters that can be determined with dataflow analysis
                        possible_sizes = par_var.possible_values
                        if possible_sizes.type != bn.RegisterValueType.UndeterminedValue:
                            log.debug(
                                custom_tag,
                                f"0x{snk_inst.address:x} Ignore dataflow determined argument 'arg#{par_idx:d}:{str(par_var):s}'"
                            )
                            continue
                    # Backward slice the parameter
                    if self.par_slice_fun(par_idx):
                        slicer = MediumLevelILBackwardSlicer(bv, max_call_level)
                        slicer.slice_backwards(par_var)
                        for source in sources:
                            if canceled(): 
                                break
                            for (src_sym_addr, src_sym_name), src_insts in source.target_insts.items():
                                if canceled(): 
                                    break
                                for src_inst in src_insts:
                                    if canceled(): 
                                        break
                                    # Find paths
                                    for insts, call_graph in slicer.find_paths(par_var, src_inst, max_slice_depth):
                                        # Prepend sink instruction
                                        insts.insert(0, snk_inst)
                                        # Find split between sink and source originating instructions
                                        src_inst_idx = len(insts)
                                        for src_inst_idx in range(src_inst_idx-1, -1, -1):
                                            if insts[src_inst_idx] not in src_insts:
                                                break
                                        src_inst_idx += 1
                                        # Add additional attributes to call graph
                                        if snk_inst.function in call_graph:
                                            call_graph.nodes[snk_inst.function]["snk"] = f"snk: {snk_name:s} | {str(par_var):s}"
                                        if src_inst.function in call_graph:
                                            call_graph.nodes[src_inst.function]["src"] = f"src: {src_sym_name:s}"
                                        # Create path
                                        path = Path(
                                            src_sym_addr=src_sym_addr,
                                            src_sym_name=src_sym_name,
                                            snk_sym_addr=snk_inst.address,
                                            snk_sym_name=snk_name,
                                            snk_par_idx=par_idx,
                                            snk_par_var=par_var,
                                            src_inst_idx=src_inst_idx,
                                            insts=insts,
                                            call_graph=call_graph
                                        )
                                        # Found the same path before
                                        if path in paths:
                                            continue
                                        # Store path
                                        paths.append(path)
                                        if found_path:
                                            found_path(path)
                                        # Log path
                                        t_log = f"Interesting path: {str(path):s}"
                                        t_log = f"{t_log:s} [L:{len(insts):d},P:{len(path.phiis):d},B:{len(path.bdeps):d}]!"
                                        log.info(custom_tag, t_log)
                                        log.debug(custom_tag, "--- Backward Slice  ---")
                                        basic_block = None
                                        for idx, inst in enumerate(insts):
                                            if idx == src_inst_idx:
                                                log.debug(custom_tag, "--- Source Function ---")
                                            if inst.il_basic_block != basic_block:
                                                basic_block = inst.il_basic_block
                                                fun_name = basic_block.function.name
                                                bb_addr = basic_block[0].address
                                                log.debug(custom_tag, f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}")
                                            log.debug(custom_tag, InstructionHelper.get_inst_info(inst))
                                        log.debug(custom_tag, "-----------------------")
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
    src_inst_idx: int
    insts: List[bn.MediumLevelILInstruction] = field(default_factory=list)
    phiis: List[bn.MediumLevelILInstruction] = field(default_factory=list)
    bdeps: Dict[int, bn.ILBranchDependence] = field(default_factory=dict)
    call_graph: MediumLevelILFunctionGraph = field(default_factory=MediumLevelILFunctionGraph)

    def __init__(
            self,
            src_sym_addr: int,
            src_sym_name: str,
            snk_sym_addr: int,
            snk_sym_name: str,
            snk_par_idx: int,
            snk_par_var: bn.MediumLevelILVarSsa,
            src_inst_idx: int,
            insts: List[bn.MediumLevelILInstruction] = field(default_factory=list),
            call_graph: MediumLevelILFunctionGraph = field(default_factory=MediumLevelILFunctionGraph)
        ) -> None:
        self.src_sym_addr = src_sym_addr
        self.src_sym_name = src_sym_name
        self.snk_sym_addr = snk_sym_addr
        self.snk_sym_name = snk_sym_name
        self.snk_par_idx = snk_par_idx
        self.snk_par_var = snk_par_var
        self.src_inst_idx = src_inst_idx
        self.insts = insts
        self.call_graph = call_graph
        self._init_metrics()
        self._init_calls()
        return
    
    def _init_metrics(self) -> None:
        self.phiis = []
        self.bdeps = {}
        for inst in self.insts:
            if isinstance(inst, bn.MediumLevelILVarPhi):
                self.phiis.append(inst)
            for bch_idx, bch_dep in inst.branch_dependence.items():
                self.bdeps.setdefault(bch_idx, bch_dep)
        return
    
    def _init_calls(self) -> None:
        self.calls = []
        for inst in self.insts:
            func_name = inst.function.source_function.name
            if len(self.calls) == 0 or self.calls[-1][1] != func_name:
                call_level = self.call_graph.nodes.get(inst.function, {}).get("call_level", 0)
                self.calls.append((inst.address, func_name, call_level))
        return

    def __eq__(self, other: Path) -> bool:
        if not isinstance(other, Path):
            try:
                other = Path(**other)
            except Exception as _:
                return False
        return (
            self.src_sym_addr == other.src_sym_addr and
            self.src_sym_name == other.src_sym_name and
            self.snk_sym_addr == other.snk_sym_addr and
            self.snk_sym_name == other.snk_sym_name and
            self.snk_par_idx  == other.snk_par_idx  and
            self.snk_par_var  == other.snk_par_var  and
            self.insts[1:self.src_inst_idx-1] == other.insts[1:other.src_inst_idx-1]
        )
    
    def __str__(self) -> str:
        src = f"0x{self.src_sym_addr:x} {self.src_sym_name:s}"
        snk = f"0x{self.snk_sym_addr:x} {self.snk_sym_name:s}"
        snk = f"{snk:s}(arg#{self.snk_par_idx:d}:{str(self.snk_par_var):s})"
        return f"{src:s} --> {snk:s}"
    
    def to_dict(self) -> Dict:
        # Serialize instructions
        insts: List[Tuple[int, int]] = []
        for inst in self.insts:
            insts.append((hex(inst.function.source_function.start), inst.expr_index))
        return {
            "src_sym_addr": hex(self.src_sym_addr),
            "src_sym_name": self.src_sym_name,
            "snk_sym_addr": hex(self.snk_sym_addr),
            "snk_sym_name": self.snk_sym_name,
            "snk_par_idx" : self.snk_par_idx,
            "src_inst_idx": self.src_inst_idx,
            "insts"       : insts,
            "call_graph"  : self.call_graph.to_dict()
        }
    
    @classmethod
    def from_dict(cls: Path, bv: bn.BinaryView, d: Dict) -> Path | None:
        # Deserialize instructions
        insts: List[bn.MediumLevelILInstruction] = []
        for func_addr, expr_idx in d["insts"]:
            func = bv.get_function_at(int(func_addr, 0))
            inst = func.mlil.ssa_form.get_expr(expr_idx)
            insts.append(inst)
        # Deserialize sink parameter variable
        snk_par_idx = d["snk_par_idx"]
        snk_par_var = insts[0].params[snk_par_idx-1]
        path = cls(
            src_sym_addr = int(d["src_sym_addr"], 0),
            src_sym_name = d["src_sym_name"],
            snk_sym_addr = int(d["snk_sym_addr"], 0),
            snk_sym_name = d["snk_sym_name"],
            snk_par_idx  = snk_par_idx,
            snk_par_var  = snk_par_var,
            src_inst_idx = d["src_inst_idx"],
            insts        = insts,
            call_graph   = MediumLevelILFunctionGraph.from_dict(bv, d["call_graph"])
        )
        return path


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
            except Exception as _:
                return False
        return self.name == other.name
    
    def to_dict(self) -> dict:
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
            except Exception as _:
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
            except Exception as _:
                return False
        return super().__eq__(other)
    
    def to_dict(self) -> Dict:
        d = super().to_dict()
        d.update({
            "items": self.items
        })
        return d