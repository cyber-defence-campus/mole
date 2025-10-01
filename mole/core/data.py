from __future__ import annotations
from dataclasses import dataclass, field
from mole.common.helper.function import FunctionHelper
from mole.common.helper.instruction import InstructionHelper
from mole.common.helper.symbol import SymbolHelper
from mole.common.log import log
from mole.core.graph import MediumLevelILFunctionGraph, MediumLevelILInstructionGraph
from mole.core.slice import MediumLevelILBackwardSlicer
from mole.models.ai import AiVulnerabilityReport
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import binaryninja as bn
import hashlib
import networkx as nx
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
        return {"sources": sources, "sinks": sinks, "settings": settings}


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
                other = Library(name=self.name, **other)
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
        return {"categories": categories}


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
                other = Category(name=self.name, **other)
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
        return {"functions": functions}


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
                other = Function(name=self.name, **other)
            except Exception as _:
                return False
        return self.name == other.name

    def to_dict(self) -> Dict:
        return {
            "symbols": self.symbols,
            "synopsis": self.synopsis,
            "enabled": self.enabled,
            "par_cnt": self.par_cnt,
            "par_slice": self.par_slice,
        }


@dataclass(frozen=True)
class CallSiteKey:
    sym_addr: int
    sym_name: str
    call_inst: bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa


@dataclass(frozen=True)
class ParamKey:
    par_idx: int
    par_var: bn.MediumLevelILInstruction


@dataclass
class Graphs:
    inst_graph: MediumLevelILInstructionGraph
    call_graph: MediumLevelILFunctionGraph


@dataclass
class SourceFunction(Function):
    """
    This class is a representation of the data associated with source functions.
    """

    src_map: Dict[CallSiteKey, Dict[ParamKey, Graphs]] = field(default_factory=dict)

    def __eq__(self, other: Function) -> bool:
        if not isinstance(other, SourceFunction):
            try:
                other = SourceFunction(name=self.name, **other)
            except Exception as _:
                return False
        return super().__eq__(other)

    def find_targets(
        self,
        bv: bn.BinaryView,
        manual_fun: Optional[SourceFunction],
        manual_fun_inst: Optional[
            bn.MediumLevelILCall
            | bn.MediumLevelILCallSsa
            | bn.MediumLevelILTailcall
            | bn.MediumLevelILTailcallSsa
        ],
        manual_fun_all_code_xrefs: bool,
        cancelled: Callable[[], bool],
    ) -> None:
        """
        This method finds a set of target instructions that a static backward slice should hit on.
        """
        custom_tag = f"{tag:s}.Src.{self.name:s}"
        # Clear map
        self.src_map.clear()
        # Get code cross-references
        log.debug(custom_tag, "Finding code cross-references")
        code_refs = SymbolHelper.get_code_refs(bv, self.symbols)
        # Source manually configured via UI
        if isinstance(manual_fun, SourceFunction) and manual_fun_inst:
            # Source without code cross-references
            if not manual_fun_all_code_xrefs or not code_refs:
                code_refs = {}
                for symbol_name in self.symbols:
                    mlil_insts: Set[bn.MediumLevelILInstruction] = code_refs.get(
                        symbol_name, set()
                    )
                    mlil_insts.add(manual_fun_inst)
                    code_refs[symbol_name] = mlil_insts
        # Source configured via configuration files
        else:
            # Source without code cross-references
            if not code_refs:
                for symbol_name in self.symbols:
                    mlil_insts: Set[bn.MediumLevelILInstruction] = code_refs.get(
                        symbol_name, set()
                    )
                    for symbol in bv.symbols.get(symbol_name, []):
                        func = bv.get_function_at(symbol.address)
                        if func is None or func.mlil is None:
                            continue
                        # Build a synthetic call instruction
                        call_inst = FunctionHelper.get_mlil_synthetic_call_inst(
                            bv, func.mlil
                        )
                        if call_inst is None:
                            continue
                        mlil_insts.add(call_inst)
                    code_refs[symbol_name] = mlil_insts
        # Iterate code references
        for src_sym_name, src_insts in code_refs.items():
            if cancelled():
                break
            # Iterate source instructions
            for src_inst in src_insts:
                if cancelled():
                    break
                # Ignore everything but call instructions
                if not isinstance(
                    src_inst,
                    (
                        bn.MediumLevelILCall,
                        bn.MediumLevelILCallSsa,
                        bn.MediumLevelILTailcall,
                        bn.MediumLevelILTailcallSsa,
                    ),
                ):
                    continue
                src_sym_addr = src_inst.address
                log.info(
                    custom_tag,
                    f"Analyze source function '0x{src_sym_addr:x} {src_sym_name:s}'",
                )
                src_call_inst = src_inst
                # Ignore calls with an invalid number of parameters
                if self.par_cnt_fun and not self.par_cnt_fun(len(src_call_inst.params)):
                    log.warn(
                        custom_tag,
                        f"0x{src_sym_addr:x} Ignore call '0x{src_sym_addr:x} {src_sym_name:s}' due to an invalid number of arguments",
                    )
                    continue
                src_par_map = self.src_map.setdefault(
                    CallSiteKey(src_sym_addr, src_sym_name, src_call_inst), {}
                )
                # Iterate source instruction's parameters
                for src_par_idx, src_par_var in enumerate(
                    src_call_inst.params, start=1
                ):
                    if cancelled():
                        break
                    src_par_var = src_par_var.ssa_form
                    log.debug(
                        custom_tag,
                        f"Analyze argument 'arg#{src_par_idx:d}:{str(src_par_var):s}'",
                    )
                    # Perform dataflow analysis on the parameter
                    if self.par_dataflow_fun and self.par_dataflow_fun(src_par_idx):
                        # Ignore constant parameters
                        if (
                            src_par_var.operation
                            != bn.MediumLevelILOperation.MLIL_VAR_SSA
                        ):
                            log.debug(
                                custom_tag,
                                f"0x{src_sym_addr:x} Ignore constant argument 'arg#{src_par_idx:d}:{str(src_par_var):s}'",
                            )
                            continue
                        # Ignore parameters that can be determined with dataflow analysis
                        possible_sizes = src_par_var.possible_values
                        if (
                            possible_sizes.type
                            != bn.RegisterValueType.UndeterminedValue
                        ):
                            log.debug(
                                custom_tag,
                                f"0x{src_sym_addr:x} Ignore dataflow determined argument 'arg#{src_par_idx:d}:{str(src_par_var):s}'",
                            )
                            continue
                    # Initialize backward slicer
                    src_slicer = MediumLevelILBackwardSlicer(
                        bv, custom_tag, 0, 0, cancelled
                    )
                    # Initialize the function that decides which parameters to slice
                    if isinstance(manual_fun, SourceFunction) and manual_fun_inst:
                        par_slice_fun = (
                            manual_fun.par_slice_fun
                            if manual_fun.par_slice_fun
                            else lambda x: False
                        )
                    else:
                        par_slice_fun = (
                            self.par_slice_fun
                            if self.par_slice_fun
                            else lambda x: False
                        )
                    # Backward slice the parameter
                    if par_slice_fun(src_par_idx):
                        src_slicer.slice_backwards(src_par_var)
                    # Add edge to instruction graph
                    src_inst_graph = MediumLevelILInstructionGraph()
                    src_inst_graph.add_edge((None, src_call_inst), (None, src_par_var))
                    src_inst_graph = nx.compose(
                        src_inst_graph, src_slicer.get_inst_graph()
                    )
                    # Add node to call graph
                    src_call_graph = src_slicer.get_call_graph()
                    src_call_graph.add_node(src_call_inst.function)
                    src_call_graph = src_call_graph.copy()
                    # Store the resulting instruction and call graphs
                    if not cancelled():
                        src_par_map[ParamKey(src_par_idx, src_par_var)] = Graphs(
                            src_inst_graph, src_call_graph
                        )
        return


@dataclass
class SinkFunction(Function):
    """
    This class is a representation of the data associated with sink functions.
    """

    def __eq__(self, other: Function) -> bool:
        if not isinstance(other, SinkFunction):
            try:
                other = SinkFunction(name=self.name, **other)
            except Exception as _:
                return False
        return super().__eq__(other)

    def find_paths(
        self,
        bv: bn.BinaryView,
        sources: List[SourceFunction],
        manual_fun: Optional[SinkFunction],
        manual_fun_inst: Optional[
            bn.MediumLevelILCall
            | bn.MediumLevelILCallSsa
            | bn.MediumLevelILTailcall
            | bn.MediumLevelILTailcallSsa
        ],
        manual_fun_all_code_xrefs: bool,
        max_call_level: int,
        max_slice_depth: int,
        max_memory_slice_depth: int,
        found_path: Callable[[Path], None],
        cancelled: Callable[[], bool],
    ) -> List[Path]:
        """
        This method tries to find paths, starting from the current sink and ending in one of the
        given `sources` using static backward slicing.
        """
        paths: List[Path] = []
        custom_tag = f"{tag:s}.Snk.{self.name:s}"
        # Calculate SHA1 hash of binary
        sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
        # Get code cross-references
        log.debug(custom_tag, "Finding code cross-references")
        code_refs = SymbolHelper.get_code_refs(bv, self.symbols)
        # Sink manually configured via UI
        if isinstance(manual_fun, SinkFunction) and manual_fun_inst:
            # Sink without code cross-references
            if not manual_fun_all_code_xrefs or not code_refs:
                code_refs = {}
                for symbol_name in self.symbols:
                    mlil_insts: Set[bn.MediumLevelILInstruction] = code_refs.get(
                        symbol_name, set()
                    )
                    mlil_insts.add(manual_fun_inst)
                    code_refs[symbol_name] = mlil_insts
        # Sink configured via configuration files
        else:
            # Sink without code cross-references
            if not code_refs:
                for symbol_name in self.symbols:
                    mlil_insts: Set[bn.MediumLevelILInstruction] = code_refs.get(
                        symbol_name, set()
                    )
                    for symbol in bv.symbols.get(symbol_name, []):
                        caller_func = bv.get_function_at(symbol.address)
                        if caller_func is None or caller_func.mlil is None:
                            continue
                        # Build a synthetic call instruction
                        call_inst = FunctionHelper.get_mlil_synthetic_call_inst(
                            bv, caller_func.mlil
                        )
                        if call_inst is None:
                            continue
                        mlil_insts.add(call_inst)
                    code_refs[symbol_name] = mlil_insts
        # Iterate code references
        for snk_sym_name, snk_insts in code_refs.items():
            if cancelled():
                break
            # Iterate sink instructions
            for snk_inst in snk_insts:
                if cancelled():
                    break
                # Ignore everything but call instructions
                if not isinstance(
                    snk_inst,
                    (
                        bn.MediumLevelILCall,
                        bn.MediumLevelILCallSsa,
                        bn.MediumLevelILTailcall,
                        bn.MediumLevelILTailcallSsa,
                    ),
                ):
                    continue
                snk_sym_addr = snk_inst.address
                log.info(
                    custom_tag,
                    f"Analyze sink function '0x{snk_sym_addr:x} {snk_sym_name:s}'",
                )
                snk_call_inst = snk_inst
                # Ignore calls with an invalid number of parameters
                if self.par_cnt_fun and not self.par_cnt_fun(len(snk_call_inst.params)):
                    log.warn(
                        custom_tag,
                        f"0x{snk_sym_addr:x} Ignore call '0x{snk_sym_addr:x} {snk_sym_name:s}' due to an invalid number of arguments",
                    )
                    continue
                # Iterate sink instruction's parameters
                for snk_par_idx, snk_par_var in enumerate(
                    snk_call_inst.params, start=1
                ):
                    if cancelled():
                        break
                    log.debug(
                        custom_tag,
                        f"Analyze argument 'arg#{snk_par_idx:d}:{str(snk_par_var):s}'",
                    )
                    # Perform dataflow analysis on the parameter
                    if self.par_dataflow_fun and self.par_dataflow_fun(snk_par_idx):
                        # Ignore constant parameters
                        if (
                            snk_par_var.operation
                            != bn.MediumLevelILOperation.MLIL_VAR_SSA
                        ):
                            log.debug(
                                custom_tag,
                                f"0x{snk_sym_addr:x} Ignore constant argument 'arg#{snk_par_idx:d}:{str(snk_par_var):s}'",
                            )
                            continue
                        # Ignore parameters that can be determined with dataflow analysis
                        possible_sizes = snk_par_var.possible_values
                        if (
                            possible_sizes.type
                            != bn.RegisterValueType.UndeterminedValue
                        ):
                            log.debug(
                                custom_tag,
                                f"0x{snk_sym_addr:x} Ignore dataflow determined argument 'arg#{snk_par_idx:d}:{str(snk_par_var):s}'",
                            )
                            continue
                    # Peform backward slicing of the parameter
                    if isinstance(manual_fun, SinkFunction) and manual_fun_inst:
                        par_slice_fun = (
                            manual_fun.par_slice_fun
                            if manual_fun.par_slice_fun
                            else lambda x: False
                        )
                    else:
                        par_slice_fun = (
                            self.par_slice_fun
                            if self.par_slice_fun
                            else lambda x: False
                        )
                    if par_slice_fun(snk_par_idx):
                        # Initialize backward slicer
                        snk_slicer = MediumLevelILBackwardSlicer(
                            bv,
                            custom_tag,
                            max_call_level,
                            max_memory_slice_depth,
                            cancelled,
                        )
                        # Backward slice the parameter
                        snk_slicer.slice_backwards(snk_par_var)
                        # Add edge to instruction graph
                        snk_inst_graph = MediumLevelILInstructionGraph()
                        snk_inst_graph.add_edge(
                            (None, snk_call_inst), (None, snk_par_var)
                        )
                        snk_inst_graph = nx.compose(
                            snk_inst_graph, snk_slicer.get_inst_graph()
                        )
                        # Add node to call graph
                        snk_call_graph = snk_slicer.get_call_graph()
                        snk_call_graph.add_node(snk_call_inst.function)
                        snk_call_graph = snk_call_graph.copy()
                        # Iterate sources
                        for source in sources:
                            if cancelled():
                                break
                            # Iterate source instructions
                            for src_call_site, src_par_map in source.src_map.items():
                                src_sym_addr = src_call_site.sym_addr
                                src_sym_name = src_call_site.sym_name
                                src_call_inst = src_call_site.call_inst
                                if cancelled():
                                    break
                                # Iterate source instruction's parameters
                                for src_param, src_graphs in src_par_map.items():
                                    src_par_idx = src_param.par_idx
                                    src_par_var = src_param.par_var
                                    src_inst_graph = src_graphs.inst_graph
                                    src_call_graph = src_graphs.call_graph
                                    if cancelled():
                                        break
                                    # Source parameter was not sliced
                                    if isinstance(manual_fun, SourceFunction):
                                        par_slice_fun = (
                                            manual_fun.par_slice_fun
                                            if manual_fun.par_slice_fun
                                            else lambda x: False
                                        )
                                    else:
                                        par_slice_fun = (
                                            source.par_slice_fun
                                            if source.par_slice_fun
                                            else lambda x: False
                                        )
                                    if not par_slice_fun(src_par_idx):
                                        src_par_idx = None
                                        src_par_var = None
                                    # Iterate source instructions (order of backward slicing)
                                    for src_inst in src_inst_graph.nodes():
                                        # Ignore source instructions that were not sliced in the sink
                                        if not any(
                                            inst[1] == src_inst[1]
                                            for inst in snk_inst_graph
                                        ):
                                            continue
                                        # Adjust negative `max_slice_depth` values
                                        if (
                                            max_slice_depth is not None
                                            and max_slice_depth < 0
                                        ):
                                            max_slice_depth = None
                                        # Find all simple paths starting at the sink's call
                                        # instruction and ending in the current source instruction
                                        snk_paths: List[
                                            List[bn.MediumLevelILInstruction]
                                        ] = []
                                        _src_insts = [
                                            inst
                                            for inst in snk_inst_graph
                                            if inst[1] and inst[1] == src_inst[1]
                                        ]
                                        for _src_inst in _src_insts:
                                            try:
                                                snk_paths.extend(
                                                    list(
                                                        nx.all_simple_paths(
                                                            snk_inst_graph,
                                                            (None, snk_call_inst),
                                                            _src_inst,
                                                            max_slice_depth,
                                                        )
                                                    )
                                                )
                                            except (nx.NodeNotFound, nx.NetworkXNoPath):
                                                # Go to the next source instruction if no path found
                                                continue
                                        # Find shortest path starting at the source's call
                                        # instruction and ending in the current source instruction
                                        src_path: List[bn.MediumLevelILInstruction] = []
                                        try:
                                            src_path = nx.shortest_path(
                                                src_inst_graph,
                                                (None, src_call_inst),
                                                src_inst,
                                            )
                                        except (nx.NodeNotFound, nx.NetworkXNoPath):
                                            # Go to the next source instruction if no path found
                                            continue
                                        # Reverse the source path so it can be appended to the sink path
                                        src_path = list(reversed(src_path))
                                        # Iterate found paths
                                        for snk_path in snk_paths:
                                            # Combine source and sink paths
                                            combined_path = snk_path + src_path[1:]
                                            # Create a new path object
                                            path = Path(
                                                src_sym_addr=src_sym_addr,
                                                src_sym_name=src_sym_name,
                                                src_par_idx=src_par_idx,
                                                src_par_var=src_par_var,
                                                src_inst_idx=len(snk_path),
                                                snk_sym_addr=snk_sym_addr,
                                                snk_sym_name=snk_sym_name,
                                                snk_par_idx=snk_par_idx,
                                                snk_par_var=snk_par_var,
                                                insts=[i[1] for i in combined_path],
                                                sha1_hash=sha1_hash,
                                            )
                                            # Ignore the path if we found it before
                                            if path in paths:
                                                continue
                                            # Combine source and sink call graphs
                                            combined_call_graph: MediumLevelILFunctionGraph = nx.compose(
                                                src_call_graph, snk_call_graph
                                            )
                                            # Find return values and parameters being used in the path
                                            old_caller_func = None
                                            for (
                                                caller_inst,
                                                callee_inst,
                                            ) in combined_path:
                                                # Caller/callee instructions
                                                caller_inst = caller_inst  # type: Optional[bn.MediumLevelILInstruction]
                                                callee_inst = callee_inst  # type: Optional[bn.MediumLevelILInstruction]
                                                # Caller/callee functions
                                                caller_func = (
                                                    caller_inst.function
                                                    if caller_inst
                                                    else None
                                                )
                                                callee_func = callee_inst.function
                                                # Store sink parameter index if we have no caller
                                                if (
                                                    caller_inst is None
                                                    or caller_func is None
                                                ):
                                                    combined_call_graph.nodes[
                                                        callee_func
                                                    ]["in_path_param_indices"] = [
                                                        path.snk_par_idx
                                                    ]
                                                    continue
                                                # Ensure caller function changed
                                                if caller_func == old_caller_func:
                                                    continue
                                                old_caller_func = caller_func
                                                # Path goes downwards the call graph
                                                if combined_call_graph.has_edge(
                                                    caller_func, callee_func
                                                ) and combined_call_graph[caller_func][
                                                    callee_func
                                                ].get("downwards", False):
                                                    # Ensure return instruction
                                                    return_insts = FunctionHelper.get_mlil_return_insts(
                                                        callee_func
                                                    )
                                                    if callee_inst not in return_insts:
                                                        continue
                                                    # Store return index
                                                    return_idx = (
                                                        return_insts.index(callee_inst)
                                                        + 1
                                                    )
                                                    return_indices: List[int] = (
                                                        combined_call_graph.nodes[
                                                            callee_func
                                                        ].get(
                                                            "in_path_return_indices", []
                                                        )
                                                    )
                                                    if return_idx not in return_indices:
                                                        return_indices.append(
                                                            return_idx
                                                        )
                                                    combined_call_graph.nodes[
                                                        callee_func
                                                    ][
                                                        "in_path_return_indices"
                                                    ] = return_indices
                                                # Path goes upwards the call graph
                                                else:
                                                    # Ensure parameter instruction
                                                    param_insts = FunctionHelper.get_mlil_param_insts(
                                                        caller_func
                                                    )
                                                    if caller_inst not in param_insts:
                                                        continue
                                                    # Store parameter index
                                                    param_idx = (
                                                        param_insts.index(caller_inst)
                                                        + 1
                                                    )
                                                    param_indices: List[int] = (
                                                        combined_call_graph.nodes[
                                                            caller_func
                                                        ].get(
                                                            "in_path_param_indices", []
                                                        )
                                                    )
                                                    if param_idx not in param_indices:
                                                        param_indices.append(param_idx)
                                                    combined_call_graph.nodes[
                                                        caller_func
                                                    ][
                                                        "in_path_param_indices"
                                                    ] = param_indices
                                            # Fully initialize the path
                                            path.init(combined_call_graph)
                                            # Store the path
                                            paths.append(path)
                                            # Execute callback on a newly found path
                                            if found_path:
                                                found_path(path)
                                            # Log newly found path
                                            t_log = f"Interesting path: {str(path):s}"
                                            t_log = f"{t_log:s} [L:{len(path.insts):d},P:{len(path.phiis):d},B:{len(path.bdeps):d}]!"
                                            log.info(custom_tag, t_log)
                                            log.debug(
                                                custom_tag, "--- Backward Slice  ---"
                                            )
                                            basic_block = None
                                            for inst in path.insts:
                                                try:
                                                    inst_basic_block = (
                                                        inst.il_basic_block
                                                    )
                                                    if inst_basic_block != basic_block:
                                                        basic_block = inst_basic_block
                                                        fun_name = (
                                                            basic_block.function.name
                                                        )
                                                        bb_addr = basic_block[0].address
                                                        log.debug(
                                                            custom_tag,
                                                            f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}",
                                                        )
                                                except Exception:
                                                    pass
                                                log.debug(
                                                    custom_tag,
                                                    InstructionHelper.get_inst_info(
                                                        inst
                                                    ),
                                                )
                                            log.debug(
                                                custom_tag, "-----------------------"
                                            )
                                        # Ignore all other source instructions since a path was found
                                        break
        return paths


@dataclass
class Path:
    """
    This class is a representation of the data associated with identified paths.
    """

    src_sym_addr: int
    src_sym_name: str
    src_par_idx: Optional[int]
    src_par_var: Optional[bn.MediumLevelILInstruction]
    src_inst_idx: int
    snk_sym_addr: int
    snk_sym_name: str
    snk_par_idx: int
    snk_par_var: bn.MediumLevelILInstruction
    insts: List[bn.MediumLevelILInstruction]
    comment: str = ""
    sha1_hash: str = ""
    phiis: List[bn.MediumLevelILInstruction] = field(default_factory=list)
    bdeps: Dict[int, bn.ILBranchDependence] = field(default_factory=dict)
    calls: List[Tuple[int, bn.MediumLevelILFunction, int]] = field(default_factory=list)
    call_graph: MediumLevelILFunctionGraph = MediumLevelILFunctionGraph()
    ai_report: Optional[AiVulnerabilityReport] = None

    def __init__(
        self,
        src_sym_addr: int,
        src_sym_name: str,
        src_par_idx: Optional[int],
        src_par_var: Optional[bn.MediumLevelILInstruction],
        src_inst_idx: int,
        snk_sym_addr: int,
        snk_sym_name: str,
        snk_par_idx: int,
        snk_par_var: bn.MediumLevelILInstruction,
        insts: List[bn.MediumLevelILInstruction],
        comment: str = "",
        sha1_hash: str = "",
        ai_report: Optional[AiVulnerabilityReport] = None,
    ) -> None:
        self.src_sym_addr = src_sym_addr
        self.src_sym_name = src_sym_name
        self.src_par_idx = src_par_idx
        self.src_par_var = src_par_var
        self.src_inst_idx = src_inst_idx
        self.snk_sym_addr = snk_sym_addr
        self.snk_sym_name = snk_sym_name
        self.snk_par_idx = snk_par_idx
        self.snk_par_var = snk_par_var
        self.insts = insts
        self.comment = comment
        self.sha1_hash = sha1_hash
        self.phiis = []
        self.bdeps = {}
        self.calls = []
        self.call_graph = MediumLevelILFunctionGraph()
        self.ai_report = ai_report
        return

    def __eq__(self, other: Path) -> bool:
        if not isinstance(other, Path):
            try:
                other = Path(**other)
            except Exception as _:
                return False
        return (
            # Equal source
            self.src_sym_addr == other.src_sym_addr
            and self.src_sym_name == other.src_sym_name
            and (
                self.src_par_idx is None
                or other.src_par_idx is None
                or self.src_par_idx == other.src_par_idx
            )
            and (
                self.src_par_var is None
                or other.src_par_var is None
                or self.src_par_var == other.src_par_var
            )
            # Equal sink
            and self.snk_sym_addr == other.snk_sym_addr
            and self.snk_sym_name == other.snk_sym_name
            and self.snk_par_idx == other.snk_par_idx
            and self.snk_par_var == other.snk_par_var
            # Equal instructions (ignoring the ones originating from slicing the
            # source, only considering the source's call instruction)
            and self.src_inst_idx == other.src_inst_idx
            and self.insts[: self.src_inst_idx - 1]
            == other.insts[: self.src_inst_idx - 1]
            and self.insts[-1] == other.insts[-1]
            # Equal binary
            and self.sha1_hash == other.sha1_hash
        )

    def __str__(self) -> str:
        src = f"0x{self.src_sym_addr:x} {self.src_sym_name:s}"
        if self.src_par_idx and self.src_par_var:
            src = f"{src:s}(arg#{self.src_par_idx:d}:{str(self.src_par_var):s})"
        else:
            src = f"{src:s}"
        snk = f"0x{self.snk_sym_addr:x} {self.snk_sym_name:s}"
        snk = f"{snk:s}(arg#{self.snk_par_idx:d}:{str(self.snk_par_var):s})"
        return f"{snk:s} <-- {src:s}"

    def init(self, call_graph: MediumLevelILFunctionGraph) -> None:
        # Copy all nodes with added attribute `in_path=False`
        for node, attrs in call_graph.nodes(data=True):
            new_attrs = {**attrs, "in_path": False}
            self.call_graph.add_node(node, **new_attrs)
        # Change node attribute to `in_path=True` where functions are in the path
        old_func = None
        for inst in self.insts:
            # Phi-instructions
            if isinstance(inst, bn.MediumLevelILVarPhi):
                self.phiis.append(inst)
            # Branch dependencies
            for bch_idx, bch_dep in inst.branch_dependence.items():
                self.bdeps.setdefault(bch_idx, bch_dep)
            # Function information
            func = inst.function
            # Continue if the function does not change
            if func == old_func:
                continue
            # Function calls
            self.calls.append((inst.address, func, 0))
            # Function calls graph
            if func in self.call_graph:
                self.call_graph.nodes[func]["in_path"] = True
            # Store old function
            old_func = func
        # Copy all edges with added attribute `in_path` stating whether or not both nodes have
        # `in_path == True`
        for from_node, to_node, attrs in call_graph.edges(data=True):
            in_path = (
                self.call_graph.nodes[from_node]["in_path"]
                and self.call_graph.nodes[to_node]["in_path"]
            )
            new_attrs = {**attrs, "in_path": in_path}
            self.call_graph.add_edge(from_node, to_node, **new_attrs)
        # Add `src` node attribute
        src_func = self.insts[-1].function
        if src_func in self.call_graph:
            src_info = f"src: {self.src_sym_name:s}"
            if self.src_par_var:
                src_info = f"{src_info:s} | {str(self.src_par_var):s}"
            self.call_graph.nodes[src_func]["src"] = src_info
        # Add `snk` node attribute
        snk_func = self.insts[0].function
        if snk_func in self.call_graph:
            snk_info = f"snk: {self.snk_sym_name:s} | {str(self.snk_par_var):s}"
            self.call_graph.nodes[snk_func]["snk"] = snk_info
        # Calculate call levels
        if not self.call_graph.update_call_levels():
            log.warn(tag, "Failed to calculate call levels")
        # Update call levels
        for i, call in enumerate(self.calls):
            call_func = call[1]
            call_level = self.call_graph.nodes[call_func].get("level", 0)
            self.calls[i] = (call[0], call_func, call_level)
        return

    def update(self, bv: bn.BinaryView) -> Path:
        """
        This method updates the symbol names of the source and sink functions.
        """
        # Ensure path has instructions
        if not self.insts:
            return
        # Update source function's symbol name
        src_inst = self.insts[-1]
        src_sym_name, _ = InstructionHelper.get_func_signature(bv, src_inst)
        if src_sym_name:
            self.src_sym_name = src_sym_name
        # Update sink function's symbol name
        snk_inst = self.insts[0]
        snk_sym_name, _ = InstructionHelper.get_func_signature(bv, snk_inst)
        if snk_sym_name:
            self.snk_sym_name = snk_sym_name
        return self

    def to_dict(self) -> Dict:
        # Serialize instructions
        insts: List[Dict[str, str]] = []
        for inst in self.insts:
            inst_dict = {
                "fun_addr": hex(inst.function.source_function.start),
                "expr_idx": hex(inst.expr_index),
                "inst": InstructionHelper.get_inst_info(inst, True),
            }
            insts.append(inst_dict)
        return {
            "src_sym_addr": hex(self.src_sym_addr),
            "src_sym_name": self.src_sym_name,
            "src_par_idx": self.src_par_idx,
            "src_inst_idx": self.src_inst_idx,
            "snk_sym_addr": hex(self.snk_sym_addr),
            "snk_sym_name": self.snk_sym_name,
            "snk_par_idx": self.snk_par_idx,
            "insts": insts,
            "call_graph": self.call_graph.to_dict(),
            "comment": self.comment,
            "sha1_hash": self.sha1_hash,
            "ai_report": self.ai_report.to_dict() if self.ai_report else None,
        }

    @classmethod
    def from_dict(cls: Path, bv: bn.BinaryView, d: Dict) -> Optional[Path]:
        try:
            # Deserialize instructions
            insts: List[bn.MediumLevelILInstruction] = []
            for inst_dict in d["insts"]:
                inst_dict = inst_dict  # type: Dict[str, str]
                fun_addr = int(inst_dict["fun_addr"], 0)
                expr_idx = int(inst_dict["expr_idx"], 0)
                func = bv.get_function_at(fun_addr)
                inst = func.mlil.ssa_form.get_expr(expr_idx)
                inst_info = InstructionHelper.get_inst_info(inst, True)
                if inst_info != inst_dict["inst"]:
                    log.warn(tag, "Instruction mismatch:")
                    log.warn(tag, f"- Expected: {inst_dict['inst']:s}")
                    log.warn(tag, f"- Found   : {inst_info:s}")
                insts.append(inst)
            # Deserialize parameter variables
            src_par_idx = d["src_par_idx"]
            if src_par_idx is not None and src_par_idx > 0:
                inst: bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa = insts[-1]
                src_par_var = inst.params[src_par_idx - 1]
            else:
                src_par_var = None
            snk_par_idx = d["snk_par_idx"]
            if snk_par_idx is not None and snk_par_idx > 0:
                inst: bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa = insts[0]
                snk_par_var = inst.params[snk_par_idx - 1]
            else:
                snk_par_var = None
            # Deserialize path
            path: Path = cls(
                src_sym_addr=int(d["src_sym_addr"], 0),
                src_sym_name=d["src_sym_name"],
                src_par_idx=src_par_idx,
                src_par_var=src_par_var,
                src_inst_idx=d["src_inst_idx"],
                snk_sym_addr=int(d["snk_sym_addr"], 0),
                snk_sym_name=d["snk_sym_name"],
                snk_par_idx=snk_par_idx,
                snk_par_var=snk_par_var,
                insts=insts,
                comment=d["comment"],
                sha1_hash=d["sha1_hash"],
                ai_report=AiVulnerabilityReport(**d["ai_report"])
                if d["ai_report"]
                else None,
            )
            path.init(MediumLevelILFunctionGraph.from_dict(bv, d["call_graph"]))
            return path
        except Exception as e:
            src_sym_addr_str = str(d.get("src_sym_addr", "unknown"))
            src_sym_name_str = str(d.get("src_sym_name", "unknown"))
            snk_sym_addr_str = str(d.get("snk_sym_addr", "unknown"))
            snk_sym_name_str = str(d.get("snk_sym_name", "unknown"))
            log.error(tag, f"Failed to deserialize path: {str(e):s}")
            log.error(tag, f"- Source: {src_sym_addr_str:s} {src_sym_name_str:s}")
            log.error(tag, f"- Sink  : {snk_sym_addr_str:s} {snk_sym_name_str:s}")
        return None


@dataclass
class WidgetSetting:
    """
    This class is a representation of the data associated with a widget.
    """

    name: str
    value: Any
    help: str
    widget: qtw.QWidget = None

    def __eq__(self, other: WidgetSetting) -> bool:
        if not isinstance(other, WidgetSetting):
            try:
                other = WidgetSetting(name=self.name, **other)
            except Exception as _:
                return False
        return self.name == other.name

    def to_dict(self) -> dict:
        return {"value": self.value, "help": self.help}


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
                other = SpinboxSetting(name=self.name, **other)
            except Exception as _:
                return False
        return super().__eq__(other)

    def to_dict(self) -> Dict:
        d = super().to_dict()
        d.update({"min_value": self.min_value, "max_value": self.max_value})
        return d


@dataclass
class DoubleSpinboxSetting(WidgetSetting):
    """
    This class is a representation of the data associated with a spinbox widget.
    """

    min_value: float = field(default_factory=float)
    max_value: float = field(default_factory=float)
    widget: qtw.QDoubleSpinBox = None

    def __eq__(self, other: DoubleSpinboxSetting) -> bool:
        if not isinstance(other, DoubleSpinboxSetting):
            try:
                other = DoubleSpinboxSetting(name=self.name, **other)
            except Exception as _:
                return False
        return super().__eq__(other)

    def to_dict(self) -> Dict:
        d = super().to_dict()
        d.update({"min_value": self.min_value, "max_value": self.max_value})
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
                other = ComboboxSetting(name=self.name, **other)
            except Exception as _:
                return False
        return super().__eq__(other)

    def to_dict(self) -> Dict:
        d = super().to_dict()
        d.update({"items": self.items})
        return d


@dataclass
class TextSetting(WidgetSetting):
    """
    This class is a representation of the data associated with a text input widget.
    """

    widget: qtw.QLineEdit = None

    def __eq__(self, other: TextSetting) -> bool:
        if not isinstance(other, TextSetting):
            try:
                other = TextSetting(name=self.name, **other)
            except Exception as _:
                return False
        return super().__eq__(other)

    def to_dict(self) -> Dict:
        return super().to_dict()
