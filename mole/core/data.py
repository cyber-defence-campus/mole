from __future__ import annotations
from dataclasses import dataclass, field
from mole.common.help import InstructionHelper, SymbolHelper
from mole.common.log import log
from mole.core.slice import (
    MediumLevelILBackwardSlicer,
    MediumLevelILFunctionGraph,
    MediumLevelILInstructionGraph,
)
from mole.models.ai import AiVulnerabilityReport
from typing import Any, Callable, Dict, List, Optional, Tuple
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
        return {"name": self.name, "categories": categories}


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
        return {"name": self.name, "functions": functions}


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
            "par_slice": self.par_slice,
        }


@dataclass
class SourceFunction(Function):
    """
    This class is a representation of the data associated with source functions.
    """

    src_map: Dict[
        Tuple[
            int,  # src_sym_addr
            str,  # src_sym_name
            bn.MediumLevelILInstruction,  # src_call_inst
        ],
        Dict[
            Tuple[int, bn.MediumLevelILInstruction],  # src_par_idx, src_par_var
            MediumLevelILInstructionGraph,  # src_inst_graph
        ],
    ] = field(default_factory=dict)

    def __eq__(self, other: Function) -> bool:
        if not isinstance(other, SourceFunction):
            try:
                other = SourceFunction(**other)
            except Exception as _:
                return False
        return super().__eq__(other)

    def find_targets(self, bv: bn.BinaryView, canceled: Callable[[], bool]) -> None:
        """
        This method finds a set of target instructions that a static backward slice should hit on.
        """
        custom_tag = f"{tag:s}.Src.{self.name:s}"
        # Clear map
        self.src_map.clear()
        # Get code references of symbols
        code_refs = SymbolHelper.get_code_refs(bv, self.symbols)
        # Iterate code references
        for src_sym_name, src_insts in code_refs.items():
            if canceled():
                break
            # Iterate source instructions
            for src_inst in src_insts:
                if canceled():
                    break
                # Ignore everything but call instructions
                if not (
                    isinstance(src_inst, bn.MediumLevelILCallSsa)
                    or isinstance(src_inst, bn.MediumLevelILTailcallSsa)
                ):
                    continue
                src_sym_addr = src_inst.address
                log.info(
                    custom_tag,
                    f"Analyze source function '0x{src_sym_addr:x} {src_sym_name:s}'",
                )
                src_call_inst = src_inst
                # Ignore calls with an invalid number of parameters
                if not self.par_cnt_fun(len(src_call_inst.params)):
                    log.warn(
                        custom_tag,
                        f"0x{src_sym_addr:x} Ignore call '0x{src_sym_addr:x} {src_sym_name:s}' due to an invalid number of arguments",
                    )
                    continue
                src_par_map = self.src_map.setdefault(
                    (src_sym_addr, src_sym_name, src_call_inst), {}
                )
                # Iterate source instruction's parameters
                for src_par_idx, src_par_var in enumerate(src_call_inst.params):
                    if canceled():
                        break
                    src_par_idx += 1
                    log.debug(
                        custom_tag,
                        f"Analyze argument 'arg#{src_par_idx:d}:{str(src_par_var):s}'",
                    )
                    # Perform dataflow analysis on the parameter
                    if self.par_dataflow_fun(src_par_idx):
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
                    # Create backward slicer
                    src_slicer = MediumLevelILBackwardSlicer(
                        bv, custom_tag, 0, canceled
                    )
                    # Add edge between call and parameter instructions
                    src_slicer.inst_graph.add_node(
                        src_call_inst, 0, src_call_inst.function, origin="src"
                    )
                    src_slicer.inst_graph.add_node(
                        src_par_var, 0, src_par_var.function, origin="src"
                    )
                    src_slicer.inst_graph.add_edge(src_call_inst, src_par_var)
                    # Perform backward slicing of the parameter
                    if self.par_slice_fun(src_par_idx):
                        src_slicer.slice_backwards(src_par_var)
                    # Store the instruction graph
                    if not canceled():
                        src_par_map[(src_par_idx, src_par_var)] = src_slicer.inst_graph
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
        canceled: Callable[[], bool],
    ) -> List[Path]:
        """
        This method tries to find paths, starting from the current sink and ending in one of the
        given `sources` using static backward slicing.
        """
        paths: List[Path] = []
        custom_tag = f"{tag:s}.Snk.{self.name:s}"
        # Calculate SHA1 hash of binary
        sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
        # Get code references of symbols
        code_refs = SymbolHelper.get_code_refs(bv, self.symbols)
        # Iterate code references
        for snk_sym_name, snk_insts in code_refs.items():
            if canceled():
                break
            # Iterate sink instructions
            for snk_inst in snk_insts:
                if canceled():
                    break
                # Ignore everything but call instructions
                if not (
                    isinstance(snk_inst, bn.MediumLevelILCallSsa)
                    or isinstance(snk_inst, bn.MediumLevelILTailcallSsa)
                ):
                    continue
                snk_sym_addr = snk_inst.address
                log.info(
                    custom_tag,
                    f"Analyze sink function '0x{snk_sym_addr:x} {snk_sym_name:s}'",
                )
                snk_call_inst = snk_inst
                # Ignore calls with an invalid number of parameters
                if not self.par_cnt_fun(len(snk_call_inst.params)):
                    log.warn(
                        custom_tag,
                        f"0x{snk_sym_addr:x} Ignore call '0x{snk_sym_addr:x} {snk_sym_name:s}' due to an invalid number of arguments",
                    )
                    continue
                # Iterate sink instruction's parameters
                for snk_par_idx, snk_par_var in enumerate(snk_call_inst.params):
                    if canceled():
                        break
                    snk_par_idx += 1
                    log.debug(
                        custom_tag,
                        f"Analyze argument 'arg#{snk_par_idx:d}:{str(snk_par_var):s}'",
                    )
                    # Perform dataflow analysis on the parameter
                    if self.par_dataflow_fun(snk_par_idx):
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
                    if self.par_slice_fun(snk_par_idx):
                        # Create backward slicer
                        snk_slicer = MediumLevelILBackwardSlicer(
                            bv, custom_tag, max_call_level, canceled
                        )
                        snk_inst_graph = snk_slicer.inst_graph
                        snk_call_graph = snk_slicer.call_graph
                        # Add edge between call and parameter instructions
                        snk_inst_graph.add_node(
                            snk_call_inst, 0, snk_call_inst.function, origin="snk"
                        )
                        snk_inst_graph.add_node(
                            snk_par_var, 0, snk_par_var.function, origin="snk"
                        )
                        snk_inst_graph.add_edge(snk_call_inst, snk_par_var)
                        snk_call_graph.add_node(snk_call_inst.function, call_level=0)
                        # Backward slice the parameter instruction
                        snk_slicer.slice_backwards(snk_par_var)
                        # Iterate sources
                        for source in sources:
                            if canceled():
                                break
                            # Iterate source instructions
                            for (
                                src_sym_addr,
                                src_sym_name,
                                src_call_inst,
                            ), src_par_map in source.src_map.items():
                                if canceled():
                                    break
                                # Iterate source instruction's parameters
                                for (src_par_idx, src_par_var), (
                                    src_inst_graph
                                ) in src_par_map.items():
                                    if canceled():
                                        break
                                    # Source parameter was not sliced
                                    if not source.par_slice_fun(src_par_idx):
                                        src_par_idx = None
                                        src_par_var = None
                                    # Iterate source instructions (order of backward slicing)
                                    for src_inst in src_inst_graph.nodes():
                                        # Ignore source instructions that were not sliced in the sink
                                        if src_inst not in snk_inst_graph:
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
                                        try:
                                            snk_paths = nx.all_simple_paths(
                                                snk_inst_graph,
                                                snk_call_inst,
                                                src_inst,
                                                max_slice_depth,
                                            )
                                        except (nx.NodeNotFound, nx.NetworkXNoPath):
                                            # Go to the next source instruction if no path found
                                            continue
                                        # Find shortest path starting at the source's call
                                        # instruction and ending in the current source instruction
                                        src_path: List[bn.MediumLevelILInstruction] = []
                                        try:
                                            src_path = nx.shortest_path(
                                                src_inst_graph, src_call_inst, src_inst
                                            )
                                        except (nx.NodeNotFound, nx.NetworkXNoPath):
                                            # Go to the next source instruction if no path found
                                            continue
                                        # Reverse the source path so it can be appended to the sink path
                                        src_path = list(reversed(src_path))
                                        # Iterate found paths
                                        for snk_path in snk_paths:
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
                                                insts=snk_path + src_path[1:],
                                                sha1_hash=sha1_hash,
                                            )
                                            # Ignore the path if we found it before
                                            if path in paths:
                                                continue
                                            # Fully initialize the path
                                            path.init(snk_call_graph)
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
                                                if inst.il_basic_block != basic_block:
                                                    basic_block = inst.il_basic_block
                                                    fun_name = basic_block.function.name
                                                    bb_addr = basic_block[0].address
                                                    log.debug(
                                                        custom_tag,
                                                        f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}",
                                                    )
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
    calls: List[Tuple[int, str, int]] = field(default_factory=list)
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

    def init(self, call_graph: MediumLevelILFunctionGraph) -> None:
        # Copy all nodes with added attribute `in_path=False`
        for node, attrs in call_graph.nodes(data=True):
            new_attrs = {**attrs, "in_path": False}
            self.call_graph.add_node(node, **new_attrs)
        # Change node attribute to `in_path=True` where functions are in the path
        old_func_name = None
        for inst in self.insts:
            # Phi-instructions
            if isinstance(inst, bn.MediumLevelILVarPhi):
                self.phiis.append(inst)
            # Branch dependencies
            for bch_idx, bch_dep in inst.branch_dependence.items():
                self.bdeps.setdefault(bch_idx, bch_dep)
            # Function information
            func = inst.function
            func_name = func.source_function.name
            # Continue if the function does not change
            if func_name == old_func_name:
                continue
            # Function calls
            call_level = self.call_graph.nodes.get(func, {}).get("call_level", 0)
            self.calls.append((inst.address, func_name, call_level))
            # Function calls graph
            if func in self.call_graph:
                self.call_graph.nodes[func]["in_path"] = True
            # Store old function name
            old_func_name = func_name
        # Copy all edges with added attribute `in_path` stating whether or not both nodes have
        # `in_path == True`
        for node_from, node_to, attrs in call_graph.edges(data=True):
            in_path = (
                self.call_graph.nodes[node_from]["in_path"]
                and self.call_graph.nodes[node_to]["in_path"]
            )
            new_attrs = {**attrs, "in_path": in_path}
            self.call_graph.add_edge(node_from, node_to, **new_attrs)
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
            src = f"{src:s}()"
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
        # Deserialize instructions
        insts: List[bn.MediumLevelILInstruction] = []
        for func_addr, expr_idx in d["insts"]:
            func = bv.get_function_at(int(func_addr, 0))
            inst = func.mlil.ssa_form.get_expr(expr_idx)
            insts.append(inst)
        # Deserialize parameter variables
        src_par_idx = d["src_par_idx"]
        if src_par_idx:
            src_par_var = insts[-1].params[src_par_idx - 1]
        else:
            src_par_var = None
        snk_par_idx = d["snk_par_idx"]
        snk_par_var = insts[0].params[snk_par_idx - 1]
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
                other = WidgetSetting(**other)
            except Exception as _:
                return False
        return self.name == other.name

    def to_dict(self) -> dict:
        return {"name": self.name, "value": self.value, "help": self.help}


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
                other = DoubleSpinboxSetting(**other)
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
                other = ComboboxSetting(**other)
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
                other = TextSetting(**other)
            except Exception as _:
                return False
        return super().__eq__(other)

    def to_dict(self) -> Dict:
        return super().to_dict()
