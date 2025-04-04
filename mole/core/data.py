from __future__ import annotations
from mole.common.help import InstructionHelper, SymbolHelper
from mole.core.slice import (
    MediumLevelILBackwardSlicer,
    MediumLevelILFunctionGraph,
    MediumLevelILInstructionGraph,
)
from dataclasses import dataclass, field
from mole.common.log import log
from typing import Callable, Dict, List, Optional, Tuple
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
        code_refs = SymbolHelper.get_code_refs(
            bv,
            self.symbols,
            [bn.SymbolType.FunctionSymbol, bn.SymbolType.ImportedFunctionSymbol],
        )
        # Iterate code references
        for src_sym_name, src_insts in code_refs.items():
            if canceled():
                break
            # Iterate source instructions
            for src_inst in src_insts:
                if canceled():
                    break
                src_sym_addr = src_inst.address
                log.info(
                    custom_tag,
                    f"Analyze source function '0x{src_sym_addr:x} {src_sym_name:s}'",
                )
                # Ignore everything but call instructions
                if not (
                    isinstance(src_inst, bn.MediumLevelILCallSsa)
                    or isinstance(src_inst, bn.MediumLevelILTailcallSsa)
                ):
                    continue
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
                    src_slicer = MediumLevelILBackwardSlicer(bv, custom_tag, 0)
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
                    # Reverse all edges of the instruction graph
                    src_inst_graph = src_slicer.inst_graph.reverse()
                    # Store the instruction graph
                    src_par_map[(src_par_idx, src_par_var)] = src_inst_graph
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
        code_refs = SymbolHelper.get_code_refs(
            bv,
            self.symbols,
            [bn.SymbolType.FunctionSymbol, bn.SymbolType.ImportedFunctionSymbol],
        )
        # Iterate code references
        for snk_sym_name, snk_insts in code_refs.items():
            if canceled():
                break
            # Iterate sink instructions
            for snk_inst in snk_insts:
                if canceled():
                    break
                snk_sym_addr = snk_inst.address
                log.info(
                    custom_tag,
                    f"Analyze sink function '0x{snk_sym_addr:x} {snk_sym_name:s}'",
                )
                # Ignore everything but call instructions
                if not (
                    isinstance(snk_inst, bn.MediumLevelILCallSsa)
                    or isinstance(snk_inst, bn.MediumLevelILTailcallSsa)
                ):
                    continue
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
                            bv, custom_tag, max_call_level
                        )
                        # Add edge between call and parameter instructions
                        snk_slicer.inst_graph.add_node(
                            snk_call_inst, 0, snk_call_inst.function, origin="snk"
                        )
                        snk_slicer.inst_graph.add_node(
                            snk_par_var, 0, snk_par_var.function, origin="snk"
                        )
                        snk_slicer.inst_graph.add_edge(snk_call_inst, snk_par_var)
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
                                    # Merge instruction graphs
                                    inst_graph: MediumLevelILInstructionGraph = (
                                        nx.compose(
                                            src_inst_graph, snk_slicer.inst_graph
                                        )
                                    )
                                    # Find all simple paths in the merged instruction graph
                                    simple_paths: List[
                                        List[bn.MediumLevelILInstruction]
                                    ] = []
                                    try:
                                        if (
                                            max_slice_depth is not None
                                            and max_slice_depth < 0
                                        ):
                                            max_slice_depth = None
                                        simple_paths = nx.all_simple_paths(
                                            inst_graph,
                                            snk_call_inst,
                                            src_call_inst,
                                            max_slice_depth,
                                        )
                                    except (nx.NodeNotFound, nx.NetworkXNoPath):
                                        pass
                                    # Iterate found paths
                                    for simple_path in simple_paths:
                                        # Find first instruction originating from slicing the source
                                        src_inst_idx = len(simple_path)
                                        for inst in reversed(simple_path):
                                            origin = inst_graph.nodes[inst]["origin"]
                                            if origin == "snk":
                                                break
                                            src_inst_idx -= 1
                                        # Copy the call graph
                                        call_graph = snk_slicer.call_graph.copy()
                                        # Add attribute `in_path = False` to all nodes
                                        for node in call_graph.nodes():
                                            call_graph.nodes[node]["in_path"] = False
                                        # Change attribute to `in_path = True` where functions are part of the path
                                        for inst in simple_path:
                                            func = inst.function
                                            if func in call_graph:
                                                call_graph.nodes[func]["in_path"] = True
                                        # Add attribute `in_path` to edges where both nodes have `in_path = True`
                                        for from_node, to_node in call_graph.edges():
                                            call_graph[from_node][to_node][
                                                "in_path"
                                            ] = (
                                                call_graph.nodes[from_node]["in_path"]
                                                and call_graph.nodes[to_node]["in_path"]
                                            )
                                        # Create path
                                        path = Path(
                                            src_sym_addr=src_sym_addr,
                                            src_sym_name=src_sym_name,
                                            src_par_idx=src_par_idx,
                                            src_par_var=src_par_var,
                                            src_inst_idx=src_inst_idx,
                                            snk_sym_addr=snk_sym_addr,
                                            snk_sym_name=snk_sym_name,
                                            snk_par_idx=snk_par_idx,
                                            snk_par_var=snk_par_var,
                                            insts=simple_path,
                                            call_graph=call_graph,
                                            comment="",
                                            sha1_hash=sha1_hash,
                                        )
                                        # Check if an equal path was found before
                                        try:
                                            # Try to find an equal path in the list already found paths
                                            idx = paths.index(path)
                                            # Equal path found before
                                            old_path = paths[idx]
                                            # Delete old path if new path is shorter
                                            if len(path.insts) < len(old_path.insts):
                                                del paths[idx]
                                            # Keep old path if new path is longer
                                            else:
                                                continue
                                        except ValueError:
                                            # Equal path not found before
                                            pass
                                        # Add `in_path` node/edge attributes to call graph
                                        for node in path.call_graph.nodes():
                                            path.call_graph.nodes[node]["in_path"] = (
                                                False
                                            )
                                        for inst in path.insts:
                                            func = inst.function
                                            if func in path.call_graph:
                                                path.call_graph.nodes[func][
                                                    "in_path"
                                                ] = True
                                        for (
                                            from_node,
                                            to_node,
                                        ) in path.call_graph.edges():
                                            path.call_graph[from_node][to_node][
                                                "in_path"
                                            ] = (
                                                path.call_graph.nodes[from_node][
                                                    "in_path"
                                                ]
                                                and path.call_graph.nodes[to_node][
                                                    "in_path"
                                                ]
                                            )
                                        # Add `src` node attribute to call graph
                                        if src_call_inst.function in path.call_graph:
                                            path.call_graph.nodes[
                                                src_call_inst.function
                                            ][
                                                "src"
                                            ] = f"src: {src_sym_name:s} | {str(src_par_var):s}"
                                        # Add `snk` node attribute to call graph
                                        if snk_call_inst.function in path.call_graph:
                                            path.call_graph.nodes[
                                                snk_call_inst.function
                                            ][
                                                "snk"
                                            ] = f"snk: {snk_sym_name:s} | {str(snk_par_var):s}"
                                        # Store the path
                                        paths.append(path)
                                        # Execute callback on a newly found path
                                        if found_path:
                                            found_path(path)
                                        # Log newly found path
                                        t_log = f"Interesting path: {str(path):s}"
                                        t_log = f"{t_log:s} [L:{len(path.insts):d},P:{len(path.phiis):d},B:{len(path.bdeps):d}]!"
                                        log.info(custom_tag, t_log)
                                        log.debug(custom_tag, "--- Backward Slice  ---")
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
                                                InstructionHelper.get_inst_info(inst),
                                            )
                                        log.debug(custom_tag, "-----------------------")
        return paths


@dataclass
class Path:
    """
    This class is a representation of the data associated with identified paths.
    """

    src_sym_addr: int
    src_sym_name: str
    src_par_idx: int
    src_par_var: bn.MediumLevelILInstruction
    src_inst_idx: int
    snk_sym_addr: int
    snk_sym_name: str
    snk_par_idx: int
    snk_par_var: bn.MediumLevelILInstruction
    insts: List[bn.MediumLevelILInstruction] = field(default_factory=list)
    phiis: List[bn.MediumLevelILInstruction] = field(default_factory=list)
    bdeps: Dict[int, bn.ILBranchDependence] = field(default_factory=dict)
    call_graph: MediumLevelILFunctionGraph = field(
        default_factory=MediumLevelILFunctionGraph
    )
    comment: str = ""
    sha1_hash: str = ""

    def __init__(
        self,
        src_sym_addr: int,
        src_sym_name: str,
        src_par_idx: int,
        src_par_var: bn.MediumLevelILInstruction,
        src_inst_idx: int,
        snk_sym_addr: int,
        snk_sym_name: str,
        snk_par_idx: int,
        snk_par_var: bn.MediumLevelILInstruction,
        insts: List[bn.MediumLevelILInstruction] = field(default_factory=list),
        call_graph: MediumLevelILFunctionGraph = field(
            default_factory=MediumLevelILFunctionGraph
        ),
        comment: str = "",
        sha1_hash: str = "",
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
        self.call_graph = call_graph
        self.comment = comment
        self.sha1_hash = sha1_hash
        self._init()
        return

    def _init(self) -> None:
        self.calls = []
        self.phiis = []
        self.bdeps = {}
        for inst in self.insts:
            # Function calls
            func_name = inst.function.source_function.name
            if len(self.calls) == 0 or self.calls[-1][1] != func_name:
                call_level = self.call_graph.nodes.get(inst.function, {}).get(
                    "call_level", 0
                )
                self.calls.append((inst.address, func_name, call_level))
            # Phi-instructions
            if isinstance(inst, bn.MediumLevelILVarPhi):
                self.phiis.append(inst)
            # Branch dependencies
            for bch_idx, bch_dep in inst.branch_dependence.items():
                self.bdeps.setdefault(bch_idx, bch_dep)
        return

    def __eq__(self, other: Path) -> bool:
        if not isinstance(other, Path):
            try:
                other = Path(**other)
            except Exception as _:
                return False
        return (
            self.src_sym_addr == other.src_sym_addr
            and self.src_sym_name == other.src_sym_name
            and self.src_par_idx == other.src_par_idx
            and self.src_par_var == other.src_par_var
            and self.src_inst_idx == other.src_inst_idx
            and self.snk_sym_addr == other.snk_sym_addr
            and self.snk_sym_name == other.snk_sym_name
            and self.snk_par_idx == other.snk_par_idx
            and self.snk_par_var == other.snk_par_var
            # Ignore all instructions originating from slicing the source, but the source call itself
            and self.insts[: self.src_inst_idx - 1]
            == other.insts[: self.src_inst_idx - 1]
            and self.insts[-1] == other.insts[-1]
            and self.sha1_hash == other.sha1_hash
        )

    def __str__(self) -> str:
        src = f"0x{self.src_sym_addr:x} {self.src_sym_name:s}"
        src = f"{src:s}(arg#{self.src_par_idx:d}:{str(self.src_par_var):s})"
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
        src_par_var = insts[-1].params[src_par_idx - 1]
        snk_par_idx = d["snk_par_idx"]
        snk_par_var = insts[0].params[snk_par_idx - 1]
        path = cls(
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
            call_graph=MediumLevelILFunctionGraph.from_dict(bv, d["call_graph"]),
            comment=d["comment"],
            sha1_hash=d["sha1_hash"],
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
