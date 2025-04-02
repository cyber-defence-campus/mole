from __future__ import annotations
from mole.common.help import SymbolHelper
from mole.core.slice import (
    MediumLevelILBackwardSlicer,
    MediumLevelILFunctionGraph,
    MediumLevelILInstructionGraph,
)
from dataclasses import dataclass, field
from mole.common.log import log
from typing import Callable, Dict, List, Tuple
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
            int,
            str,
            bn.MediumLevelILInstruction,  # src_sym_addr, src_sym_name, src_call_inst
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
        self.src_map.clear()
        code_refs = SymbolHelper.get_code_refs(
            bv,
            self.symbols,
            [bn.SymbolType.FunctionSymbol, bn.SymbolType.ImportedFunctionSymbol],
        )
        for src_sym_name, src_insts in code_refs.items():
            if canceled():
                break
            for src_inst in src_insts:
                if canceled():
                    break
                src_sym_addr = src_inst.address
                log.info(
                    custom_tag,
                    f"Analyze source function '0x{src_sym_addr:x} {src_sym_name:s}'",
                )
                # Ignore everything but call instructions
                if not isinstance(src_inst, bn.MediumLevelILCallSsa) and not isinstance(
                    src_inst, bn.MediumLevelILTailcallSsa
                ):
                    continue
                src_call_inst = src_inst
                # Ignore calls with an invalid number of parameters
                if not self.par_cnt_fun(len(src_call_inst.params)):
                    log.warn(
                        custom_tag,
                        f"0x{src_sym_addr:x} Ignore arguments of call '0x{src_sym_addr:x} {src_sym_name:s}' due to an unexpected amount",
                    )
                    continue
                src_par_map = self.src_map.setdefault(
                    (src_sym_addr, src_sym_name, src_call_inst), {}
                )
                # Analyze parameters
                for src_par_idx, src_par_var in enumerate(src_call_inst.params):
                    if canceled():
                        break
                    src_par_idx += 1
                    log.debug(
                        custom_tag,
                        f"Analyze argument 'arg#{src_par_idx:d}:{str(src_par_var):s}'",
                    )
                    # Perform dataflow analysis
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
                    # Backward slice the parameter
                    src_par_map[(src_par_idx, src_par_var)] = None
                    if self.par_slice_fun(src_par_idx):
                        slicer = MediumLevelILBackwardSlicer(bv, custom_tag, 0)
                        # TODO: Rename `_inst_graph` to `inst_graph`
                        slicer._inst_graph.add_node(
                            src_call_inst, 0, src_call_inst.function
                        )
                        slicer._inst_graph.add_node(
                            src_par_var, 0, src_par_var.function
                        )
                        slicer._inst_graph.add_edge(src_call_inst, src_par_var)
                        slicer.slice_backwards(src_par_var)
                        src_par_map[(src_par_idx, src_par_var)] = slicer._inst_graph
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
        paths = []
        custom_tag = f"{tag:s}.Snk.{self.name:s}"
        sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
        code_refs = SymbolHelper.get_code_refs(
            bv,
            self.symbols,
            [bn.SymbolType.FunctionSymbol, bn.SymbolType.ImportedFunctionSymbol],
        )
        for snk_sym_name, snk_insts in code_refs.items():
            if canceled():
                break
            for snk_inst in snk_insts:
                if canceled():
                    break
                snk_sym_addr = snk_inst.address
                log.info(
                    custom_tag,
                    f"Analyze sink function '0x{snk_sym_addr:x} {snk_sym_name:s}'",
                )
                # Ignore everything but call instructions
                if not isinstance(snk_inst, bn.MediumLevelILCallSsa) and not isinstance(
                    snk_inst, bn.MediumLevelILTailcallSsa
                ):
                    continue
                snk_call_inst = snk_inst
                # Ignore calls with an invalid number of parameters
                if not self.par_cnt_fun(len(snk_call_inst.params)):
                    log.warn(
                        custom_tag,
                        f"0x{snk_sym_addr:x} Ignore call '0x{snk_sym_addr:x} {snk_sym_name:s}' due to invalid number of arguments",
                    )
                    continue
                # Analyze parameters
                for snk_par_idx, snk_par_var in enumerate(snk_call_inst.params):
                    if canceled():
                        break
                    snk_par_idx += 1
                    log.debug(
                        custom_tag,
                        f"Analyze argument 'arg#{snk_par_idx:d}:{str(snk_par_var):s}'",
                    )
                    # Perform dataflow analysis
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
                    # Backward slice the sink parameter
                    if self.par_slice_fun(snk_par_idx):
                        snk_slicer = MediumLevelILBackwardSlicer(
                            bv, custom_tag, max_call_level
                        )
                        # TODO: Test
                        snk_slicer._inst_graph.add_node(
                            snk_call_inst, 0, snk_call_inst.function
                        )
                        snk_slicer._inst_graph.add_node(
                            snk_par_var, 0, snk_par_var.function
                        )
                        snk_slicer._inst_graph.add_edge(snk_call_inst, snk_par_var)
                        snk_slicer.slice_backwards(snk_par_var)
                        # Iterate source functions
                        for source in sources:
                            if canceled():
                                break
                            for (
                                src_sym_addr,
                                src_sym_name,
                                src_call_inst,
                            ), src_par_map in source.src_map.items():
                                if canceled():
                                    break
                                for (
                                    src_par_idx,
                                    src_par_var,
                                ), src_inst_graph in src_par_map.items():
                                    if canceled():
                                        break
                                    # Empty source instruction graph
                                    if not src_inst_graph:
                                        continue
                                    # Instruction graph from slicing the source (reversed)
                                    src_inst_graph = MediumLevelILInstructionGraph(
                                        [(v, u) for u, v in src_inst_graph.edges]
                                    )
                                    # Instruction graph from slicing the sink
                                    snk_inst_graph = snk_slicer._inst_graph
                                    # Merged instruction graph
                                    merged_inst_graph: MediumLevelILInstructionGraph = (
                                        nx.compose(src_inst_graph, snk_inst_graph)
                                    )
                                    # Find all simple paths in the merged instruction graph
                                    try:
                                        if (
                                            max_slice_depth is not None
                                            and max_slice_depth < 0
                                        ):
                                            max_slice_depth = None
                                        simple_paths = nx.all_simple_paths(
                                            merged_inst_graph,
                                            snk_call_inst,
                                            src_call_inst,
                                            max_slice_depth,
                                        )
                                    except (nx.NodeNotFound, nx.NetworkXNoPath):
                                        simple_paths = []
                                    # TODO: Continue here
                                    if not sha1_hash or not simple_paths:
                                        log.debug(custom_tag, "TODO")

                                    # for src_inst in src_slicer.get_insts():
                                    #     for (
                                    #         _snk_insts,
                                    #         call_graph,
                                    #     ) in snk_slicer.find_all_paths(
                                    #         snk_call_inst, src_inst, max_slice_depth
                                    #     ):
                                    #         # Split between source and sink originating instructions
                                    #         _old_snk_inst = None
                                    #         while len(_snk_insts) > 1:
                                    #             _snk_inst = _snk_insts.pop()
                                    #             if (
                                    #                 _snk_inst
                                    #                 not in src_slicer.get_insts()
                                    #             ):
                                    #                 _snk_insts.append(_snk_inst)
                                    #                 break
                                    #             _old_snk_inst = _snk_inst
                                    #         _src_insts, _ = (
                                    #             src_slicer.find_shortest_path(
                                    #                 src_call_inst, _old_snk_inst, False
                                    #             )
                                    #         )
                                    #         # Create path
                                    #         path = Path(
                                    #             src_sym_addr=src_sym_addr,
                                    #             snk_sym_addr=snk_sym_addr,
                                    #             src_sym_name=src_sym_name,
                                    #             snk_sym_name=snk_sym_name,
                                    #             src_par_idx=src_par_idx,
                                    #             snk_par_idx=snk_par_idx,
                                    #             src_par_var=src_par_var,
                                    #             snk_par_var=snk_par_var,
                                    #             src_insts=_src_insts,
                                    #             snk_insts=_snk_insts,
                                    #             snk_call_graph=call_graph,
                                    #             comment="",
                                    #             sha1_hash=sha1_hash,
                                    #         )
                                    #         # Found the same path before
                                    #         if path in paths:
                                    #             continue
                                    #         # Store path
                                    #         paths.append(path)
                                    #         if found_path:
                                    #             found_path(path)
                                    #         # Log path
                                    #         t_log = f"Interesting path: {str(path):s}"
                                    #         t_log = f"{t_log:s} [L:{len(path.snk_insts):d},P:{len(path.snk_phiis):d},B:{len(path.snk_bdeps):d}]!"
                                    #         log.info(custom_tag, t_log)
                                    #         log.debug(
                                    #             custom_tag,
                                    #             "--- Backward Slice: From Sink  ---",
                                    #         )
                                    #         basic_block = None
                                    #         for inst in path.snk_insts:
                                    #             if inst.il_basic_block != basic_block:
                                    #                 basic_block = inst.il_basic_block
                                    #                 fun_name = basic_block.function.name
                                    #                 bb_addr = basic_block[0].address
                                    #                 log.debug(
                                    #                     custom_tag,
                                    #                     f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}",
                                    #                 )
                                    #             log.debug(
                                    #                 custom_tag,
                                    #                 InstructionHelper.get_inst_info(
                                    #                     inst
                                    #                 ),
                                    #             )
                                    #         log.debug(
                                    #             custom_tag,
                                    #             "--- Forward Slice:  To Source  ---",
                                    #         )
                                    #         basic_block = None
                                    #         for inst in reversed(path.src_insts):
                                    #             if inst.il_basic_block != basic_block:
                                    #                 basic_block = inst.il_basic_block
                                    #                 fun_name = basic_block.function.name
                                    #                 bb_addr = basic_block[0].address
                                    #                 log.debug(
                                    #                     custom_tag,
                                    #                     f"- FUN: '{fun_name:s}', BB; 0x{bb_addr:x}",
                                    #                 )
                                    #             log.debug(
                                    #                 custom_tag,
                                    #                 InstructionHelper.get_inst_info(
                                    #                     inst
                                    #                 ),
                                    #             )
                                    #         log.debug(
                                    #             custom_tag, "-----------------------"
                                    #         )

                                    # for src_inst in src_slicer.get_insts():
                                    #     for insts, call_graph in snk_slicer.find_all_paths(
                                    #         snk_par_var,
                                    #         src_inst,
                                    #         max_slice_depth
                                    #     ):
                                    #         # TODO: Split between source and sink originating instructions
                                    #         _snk_inst = None
                                    #         _snk_insts = [snk_call_inst] + insts
                                    #         while _snk_insts:
                                    #             # Find first instruction that does not originate from slicing the source
                                    #             _snk_inst = _snk_insts.pop()
                                    #             if _snk_inst not in src_slicer.get_insts():
                                    #                 _snk_insts.append(_snk_inst)
                                    #                 break
                                    #         _src_insts, _ = src_slicer.find_shortest_path(
                                    #             src_call_inst, _snk_inst, False
                                    #         )

                                    #         # Create path
                                    #         path = Path(
                                    #             src_sym_addr=src_sym_addr,
                                    #             snk_sym_addr=snk_sym_addr,
                                    #             src_sym_name=src_sym_name,
                                    #             snk_sym_name=snk_sym_name,
                                    #             src_par_idx=src_par_idx,
                                    #             snk_par_idx=snk_par_idx,
                                    #             src_par_var=src_par_var,
                                    #             snk_par_var=snk_par_var,
                                    #             src_insts=_src_insts,
                                    #             snk_insts=_snk_insts,
                                    #             snk_call_graph=call_graph,
                                    #             comment="",
                                    #             sha1_hash=sha1_hash,
                                    #         )
                                    #         # Found the same path before
                                    #         if path in paths:
                                    #             continue
                                    #         # Store path
                                    #         paths.append(path)
                                    #         if found_path:
                                    #             found_path(path)
                                    #         # Log path
                                    #         t_log = f"Interesting path: {str(path):s}"
                                    #         t_log = f"{t_log:s} [L:{len(path.snk_insts):d},P:{len(path.snk_phiis):d},B:{len(path.snk_bdeps):d}]!"
                                    #         log.info(custom_tag, t_log)
                                    #         log.debug(custom_tag, "--- Backward Slice: From Sink  ---")
                                    #         basic_block = None
                                    #         for inst in path.snk_insts:
                                    #             if inst.il_basic_block != basic_block:
                                    #                 basic_block = inst.il_basic_block
                                    #                 fun_name = basic_block.function.name
                                    #                 bb_addr = basic_block[0].address
                                    #                 log.debug(
                                    #                     custom_tag,
                                    #                     f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}",
                                    #                 )
                                    #             log.debug(
                                    #                 custom_tag,
                                    #                 InstructionHelper.get_inst_info(inst),
                                    #             )
                                    #         log.debug(custom_tag, "--- Forward Slice:  To Source  ---")
                                    #         basic_block = None
                                    #         for inst in reversed(path.src_insts):
                                    #             if inst.il_basic_block != basic_block:
                                    #                 basic_block = inst.il_basic_block
                                    #                 fun_name = basic_block.function.name
                                    #                 bb_addr = basic_block[0].address
                                    #                 log.debug(
                                    #                     custom_tag,
                                    #                     f"- FUN: '{fun_name:s}', BB; 0x{bb_addr:x}"
                                    #                 )
                                    #             log.debug(
                                    #                 custom_tag,
                                    #                 InstructionHelper.get_inst_info(inst)
                                    #             )
                                    #         log.debug(custom_tag, "-----------------------")

                                    # for src_inst in src_insts:
                                    #     # Find paths from sink parameter to source-originating instruction
                                    #     for insts, call_graph in snk_slicer.find_all_paths(
                                    #         snk_par_var,
                                    #         src_inst,
                                    #         max_slice_depth
                                    #     ):
                                    #         # TODO: Split between source and sink-originating instructions
                                    #         _src_inst = None
                                    #         _snk_insts = [snk_inst] + insts
                                    #         while _snk_insts:
                                    #             # Find first instruction that does not originate from slicing the source
                                    #             _snk_inst = _snk_insts.pop()
                                    #             if _snk_inst not in src_insts:
                                    #                 _snk_insts.append(_snk_inst)
                                    #                 break
                                    #             _src_inst = _snk_inst
                                    #         # TODO: find_path(src_inst, _src_inst, max_slice_depth)
                                    #         try:
                                    #             idx = src_insts.index(_src_inst)
                                    #             _src_insts = src_insts[:idx]
                                    #         except ValueError:
                                    #             _src_insts = []

                                    #         # _snk_insts = [snk_inst] + insts
                                    #         # _src_insts = []

                                    #         # idx = len(_snk_insts)
                                    #         # for idx in range(idx-1, -1, -1):
                                    #         #     if _snk_insts[idx] not in src_insts:
                                    #         #         break
                                    #         # _src_insts = src_insts[idx+1:]

                                    #         # # TODO:
                                    #         # for snk_inst in reversed(insts):
                                    #         #     if snk_inst not in src_insts:
                                    #         #         pass
                                    #         # # Find split between sink and source originating instructions
                                    #         # src_inst_idx = len(snk_insts)
                                    #         # for src_inst_idx in range(
                                    #         #     src_inst_idx - 1, -1, -1
                                    #         # ):
                                    #         #     inst = snk_insts[src_inst_idx]
                                    #         #     try:
                                    #         #         idx = src_insts.index(inst)
                                    #         #     except ValueError:
                                    #         #         # `ìnst` originates from slicing the sink
                                    #         #         snk_insts.extend(src_insts[:])
                                    #         #         break

                                    #         #     # No longer a source-originating instruction
                                    #         #     if idx < 0:
                                    #         #         snk_insts.extend(src_insts[idx:])
                                    #         #         break
                                    #         # src_inst_idx += 1

                                    #         # Add additional attributes to call graph
                                    #         if snk_inst.function in call_graph:
                                    #             call_graph.nodes[snk_inst.function][
                                    #                 "snk"
                                    #             ] = f"snk: {snk_sym_name:s} | {str(snk_par_var):s}"
                                    #         if src_inst.function in call_graph:
                                    #             call_graph.nodes[src_inst.function][
                                    #                 "src"
                                    #             ] = f"src: {src_sym_name:s} | {str(src_par_var):s}"
                                    #         # Create path
                                    #         path = Path(
                                    #             src_sym_addr=src_sym_addr,
                                    #             snk_sym_addr=snk_inst_addr,
                                    #             src_sym_name=src_sym_name,
                                    #             snk_sym_name=snk_sym_name,
                                    #             src_par_idx=src_par_idx,
                                    #             snk_par_idx=snk_par_idx,
                                    #             src_par_var=src_par_var,
                                    #             snk_par_var=snk_par_var,
                                    #             src_insts=_src_insts,
                                    #             snk_insts=_snk_insts,
                                    #             snk_call_graph=call_graph,
                                    #             comment="",
                                    #             sha1_hash=sha1_hash,
                                    #         )
                                    #         # Found the same path before
                                    #         if path in paths:
                                    #             continue
                                    #         # Store path
                                    #         paths.append(path)
                                    #         if found_path:
                                    #             found_path(path)
                                    #         # Log path
                                    #         t_log = f"Interesting path: {str(path):s}"
                                    #         t_log = f"{t_log:s} [L:{len(path.snk_insts):d},P:{len(path.snk_phiis):d},B:{len(path.snk_bdeps):d}]!"
                                    #         log.info(custom_tag, t_log)
                                    #         log.debug(custom_tag, "--- Backward Slice: From Sink  ---")
                                    #         basic_block = None
                                    #         for inst in path.snk_insts:
                                    #             if inst.il_basic_block != basic_block:
                                    #                 basic_block = inst.il_basic_block
                                    #                 fun_name = basic_block.function.name
                                    #                 bb_addr = basic_block[0].address
                                    #                 log.debug(
                                    #                     custom_tag,
                                    #                     f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}",
                                    #                 )
                                    #             log.debug(
                                    #                 custom_tag,
                                    #                 InstructionHelper.get_inst_info(inst),
                                    #             )
                                    #         log.debug(custom_tag, "--- Forward Slice:  To Source  ---")
                                    #         basic_block = None
                                    #         for inst in reversed(path.src_insts):
                                    #             if inst.il_basic_block != basic_block:
                                    #                 basic_block = inst.il_basic_block
                                    #                 fun_name = basic_block.function.name
                                    #                 bb_addr = basic_block[0].address
                                    #                 log.debug(
                                    #                     custom_tag,
                                    #                     f"- FUN: '{fun_name:s}', BB; 0x{bb_addr:x}"
                                    #                 )
                                    #             log.debug(
                                    #                 custom_tag,
                                    #                 InstructionHelper.get_inst_info(inst)
                                    #             )
                                    #         log.debug(custom_tag, "-----------------------")
        return paths


@dataclass
class Path:
    """
    This class is a representation of the data associated with identified paths.
    """

    src_sym_addr: int
    snk_sym_addr: int
    src_sym_name: str
    snk_sym_name: str
    src_par_idx: int
    snk_par_idx: int
    src_par_var: bn.MediumLevelILInstruction
    snk_par_var: bn.MediumLevelILInstruction
    src_insts: List[bn.MediumLevelILInstruction] = field(default_factory=list)
    snk_insts: List[bn.MediumLevelILInstruction] = field(default_factory=list)
    snk_phiis: List[bn.MediumLevelILInstruction] = field(default_factory=list)
    snk_bdeps: Dict[int, bn.ILBranchDependence] = field(default_factory=dict)
    snk_call_graph: MediumLevelILFunctionGraph = field(
        default_factory=MediumLevelILFunctionGraph
    )
    comment: str = ""
    sha1_hash: str = ""

    def __init__(
        self,
        src_sym_addr: int,
        snk_sym_addr: int,
        src_sym_name: str,
        snk_sym_name: str,
        src_par_idx: int,
        snk_par_idx: int,
        src_par_var: bn.MediumLevelILInstruction,
        snk_par_var: bn.MediumLevelILInstruction,
        src_insts: List[bn.MediumLevelILInstruction] = field(default_factory=list),
        snk_insts: List[bn.MediumLevelILInstruction] = field(default_factory=list),
        snk_call_graph: MediumLevelILFunctionGraph = field(
            default_factory=MediumLevelILFunctionGraph
        ),
        comment: str = "",
        sha1_hash: str = "",
    ) -> None:
        self.src_sym_addr = src_sym_addr
        self.snk_sym_addr = snk_sym_addr
        self.src_sym_name = src_sym_name
        self.snk_sym_name = snk_sym_name
        self.src_par_idx = src_par_idx
        self.snk_par_idx = snk_par_idx
        self.src_par_var = src_par_var
        self.snk_par_var = snk_par_var
        self.src_insts = src_insts
        self.snk_insts = snk_insts
        self.snk_call_graph = snk_call_graph
        self.comment = comment
        self.sha1_hash = sha1_hash
        self._init_metrics()
        self._init_calls()
        return

    def _init_metrics(self) -> None:
        self.snk_phiis = []
        self.snk_bdeps = {}
        for inst in self.snk_insts:
            if isinstance(inst, bn.MediumLevelILVarPhi):
                self.snk_phiis.append(inst)
            for bch_idx, bch_dep in inst.branch_dependence.items():
                self.snk_bdeps.setdefault(bch_idx, bch_dep)
        return

    def _init_calls(self) -> None:
        self.calls = []
        for inst in self.snk_insts:
            func_name = inst.function.source_function.name
            if len(self.calls) == 0 or self.calls[-1][1] != func_name:
                call_level = self.snk_call_graph.nodes.get(inst.function, {}).get(
                    "call_level", 0
                )
                self.calls.append((inst.address, func_name, call_level))
        return

    def __eq__(self, other: Path) -> bool:
        if not isinstance(other, Path):
            try:
                other = Path(**other)
            except Exception as _:
                return False
        return (
            self.src_sym_addr == other.src_sym_addr
            and self.snk_sym_addr == other.snk_sym_addr
            and self.src_sym_name == other.src_sym_name
            and self.snk_sym_name == other.snk_sym_name
            and self.snk_par_idx == other.snk_par_idx
            and self.snk_par_var == other.snk_par_var
            and self.snk_insts == other.snk_insts
            and self.sha1_hash == other.sha1_hash
        )

    def __str__(self) -> str:
        src = f"0x{self.src_sym_addr:x} {self.src_sym_name:s}"
        src = f"{src:s}(arg#{self.src_par_idx:d}:{str(self.src_par_var):s})"
        snk = f"0x{self.snk_sym_addr:x} {self.snk_sym_name:s}"
        snk = f"{snk:s}(arg#{self.snk_par_idx:d}:{str(self.snk_par_var):s})"
        return f"{src:s} --> {snk:s}"

    def to_dict(self) -> Dict:
        # Serialize source-originating instructions
        src_insts: List[Tuple[int, int]] = []
        for inst in self.src_insts:
            src_insts.append(
                (hex(inst.function.source_function.start), inst.expr_index)
            )
        # Serialiye sink-originating instructions
        snk_insts: List[Tuple[int, int]] = []
        for inst in self.snk_insts:
            snk_insts.append(
                (hex(inst.function.source_function.start), inst.expr_index)
            )
        return {
            "src_sym_addr": hex(self.src_sym_addr),
            "snk_sym_addr": hex(self.snk_sym_addr),
            "src_sym_name": self.src_sym_name,
            "snk_sym_name": self.snk_sym_name,
            "src_par_idx": self.src_par_idx,
            "snk_par_idx": self.snk_par_idx,
            "src_insts": src_insts,
            "snk_insts": snk_insts,
            "comment": self.comment,
            "sha1_hash": self.sha1_hash,
            "snk_call_graph": self.snk_call_graph.to_dict(),
        }

    @classmethod
    def from_dict(cls: Path, bv: bn.BinaryView, d: Dict) -> Path | None:
        # Deserialize source-originating instructions
        src_insts: List[bn.MediumLevelILInstruction] = []
        for func_addr, expr_idx in d["src_insts"]:
            func = bv.get_function_at(int(func_addr, 0))
            inst = func.mlil.ssa_form.get_expr(expr_idx)
            src_insts.append(inst)
        # Deserialize sink-originating instructions
        snk_insts: List[bn.MediumLevelILInstruction] = []
        for func_addr, expr_idx in d["snk_insts"]:
            func = bv.get_function_at(int(func_addr, 0))
            inst = func.mlil.ssa_form.get_expr(expr_idx)
            snk_insts.append(inst)
        # Deserialize source parameter variable
        src_par_idx = d["src_par_idx"]
        src_par_var = src_insts[0].params[src_par_idx - 1]
        src_par_idx = 0
        src_par_var = None
        # Deserialize sink parameter variable
        snk_par_idx = d["snk_par_idx"]
        snk_par_var = snk_insts[0].params[snk_par_idx - 1]
        path = cls(
            src_sym_addr=int(d["src_sym_addr"], 0),
            snk_sym_addr=int(d["snk_sym_addr"], 0),
            src_sym_name=d["src_sym_name"],
            snk_sym_name=d["snk_sym_name"],
            src_par_idx=src_par_idx,
            snk_par_idx=snk_par_idx,
            src_par_var=src_par_var,
            snk_par_var=snk_par_var,
            src_insts=src_insts,
            snk_insts=snk_insts,
            snk_call_graph=MediumLevelILFunctionGraph.from_dict(
                bv, d["snk_call_graph"]
            ),
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
