from __future__ import annotations
from concurrent import futures
from mole.core.graph import MediumLevelILFunctionGraph, MediumLevelILInstructionGraph
from mole.core.slice import MediumLevelILBackwardSlicer
from mole.common.helper.function import FunctionHelper
from mole.common.helper.instruction import InstructionHelper
from mole.common.helper.symbol import SymbolHelper
from mole.common.log import Logger
from mole.common.task import BackgroundService
from mole.grouping import get_grouper, PathGrouper
from mole.models.config import (
    CallSiteKey,
    CheckboxSetting,
    ComboboxSetting,
    ConfigModel,
    Graphs,
    ParamKey,
    SinkFunction,
    SourceFunction,
    SpinboxSetting,
)
from mole.models.path import Path
from typing import Callable, cast, Dict, List, Set, Tuple
import binaryninja as bn
import hashlib
import networkx as nx
import os


tag = "Path"


class PathService(BackgroundService):
    """
    This class implements a service for Mole's path.
    """

    def __init__(
        self, bv: bn.BinaryView, log: Logger, config_model: ConfigModel
    ) -> None:
        """
        This method initializes the path service.
        """
        super().__init__()
        self.bv = bv
        self.log = log
        self.config_model = config_model
        self._paths: List[Path] = []
        return

    def get_path_grouper(self) -> PathGrouper | None:
        """
        This method returns a path grouper based on the current configuration.
        """
        path_grouping = ""
        setting = self.config_model.get_setting("path_grouping")
        if isinstance(setting, ComboboxSetting):
            path_grouping = str(setting.value)
        return get_grouper(path_grouping)

    def get_paths(self) -> List[Path]:
        """
        This method waits for the path finding to complete and returns the identified paths.
        """
        paths = cast(List[Path], self.results(thread_name="find"))
        return paths if paths is not None else []

    def _slice_src_function(
        self,
        src_fun: SourceFunction,
        manual_fun: SourceFunction | None,
        manual_fun_inst: bn.MediumLevelILCall
        | bn.MediumLevelILCallSsa
        | bn.MediumLevelILTailcall
        | bn.MediumLevelILTailcallSsa
        | None,
        manual_fun_all_code_xrefs: bool,
    ) -> None:
        """
        This method performs backward slicing on the given source function `src_fun`. It stores the
        resulting instruction and call graphs in the source function's `graph_map`.
        """
        # Custom tag for logging
        custom_tag = f"{tag:s}] [Src:{src_fun.name:s}"
        # Clear function's graph map
        src_fun.graph_map.clear()
        # Get code cross-references
        code_refs = SymbolHelper.get_code_refs(self.bv, src_fun.symbols)
        # Source manually configured via UI
        if manual_fun is not None and manual_fun_inst is not None:
            # Source without code cross-references
            if not manual_fun_all_code_xrefs or not code_refs:
                code_refs = {}
                for symbol_name in src_fun.symbols:
                    mlil_insts: Set[bn.MediumLevelILInstruction] = code_refs.get(
                        symbol_name, set()
                    )
                    mlil_insts.add(manual_fun_inst)
                    code_refs[symbol_name] = mlil_insts
        # Source configured via configuration files
        else:
            # Source without code cross-references
            if not code_refs:
                for symbol_name in src_fun.symbols:
                    mlil_insts: Set[bn.MediumLevelILInstruction] = code_refs.get(
                        symbol_name, set()
                    )
                    for symbol in self.bv.get_symbols_by_name(symbol_name):
                        func = self.bv.get_function_at(symbol.address)
                        if func is None or func.mlil is None:
                            continue
                        # Build a synthetic call instruction
                        call_inst = FunctionHelper.get_mlil_synthetic_call_inst(
                            func.mlil
                        )
                        if call_inst is None:
                            continue
                        mlil_insts.add(call_inst)
                    code_refs[symbol_name] = mlil_insts
        # Iterate code references
        for src_sym_name, src_insts in code_refs.items():
            if self.cancelled(thread_name="find"):
                break
            # Iterate source instructions
            for src_inst in src_insts:
                if self.cancelled(thread_name="find"):
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
                self.log.info(
                    custom_tag,
                    f"Analyze source function '0x{src_sym_addr:x} {src_sym_name:s}'",
                )
                src_call_inst = src_inst
                # Ignore calls with an invalid number of parameters
                if not src_fun.par_cnt_fun(len(src_call_inst.params)):
                    self.log.warn(
                        custom_tag,
                        f"0x{src_sym_addr:x} Ignore call '0x{src_sym_addr:x} {src_sym_name:s}' due to an invalid number of arguments",
                    )
                    continue
                par_map = src_fun.graph_map.setdefault(
                    CallSiteKey(src_sym_addr, src_sym_name, src_call_inst), {}
                )
                # Iterate source instruction's parameters
                for src_par_idx, src_par_var in enumerate(
                    src_call_inst.params, start=1
                ):
                    if self.cancelled(thread_name="find"):
                        break
                    src_par_var = src_par_var.ssa_form
                    self.log.debug(
                        custom_tag,
                        f"Analyze argument 'arg#{src_par_idx:d}:{str(src_par_var):s}'",
                    )
                    # Perform dataflow analysis on the parameter
                    if src_fun.par_dataflow_fun(src_par_idx):
                        # Ignore constant parameters
                        if (
                            src_par_var.operation
                            != bn.MediumLevelILOperation.MLIL_VAR_SSA
                        ):
                            self.log.debug(
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
                            self.log.debug(
                                custom_tag,
                                f"0x{src_sym_addr:x} Ignore dataflow determined argument 'arg#{src_par_idx:d}:{str(src_par_var):s}'",
                            )
                            continue
                    # Initialize backward slicer
                    src_slicer = MediumLevelILBackwardSlicer(
                        self.bv,
                        self.log,
                        custom_tag,
                        0,
                        0,
                        lambda: self.cancelled(thread_name="find"),
                    )
                    # Initialize the function that decides which parameters to slice
                    if isinstance(manual_fun, SourceFunction) and manual_fun_inst:
                        par_slice_fun = manual_fun.par_slice_fun
                    else:
                        par_slice_fun = src_fun.par_slice_fun
                    # Backward slice the parameter
                    if par_slice_fun(src_par_idx):
                        src_slicer.slice_backwards(src_par_var)
                    # Add edge to instruction graph
                    src_inst_graph = MediumLevelILInstructionGraph()
                    src_inst_graph.add_edge((None, src_call_inst), (None, src_par_var))
                    src_inst_graph = cast(
                        MediumLevelILInstructionGraph,
                        nx.compose(src_inst_graph, src_slicer.get_inst_graph()),
                    )
                    # Add node to call graph
                    src_call_graph = src_slicer.get_call_graph()
                    src_call_graph.add_node(src_call_inst.function)
                    src_call_graph = src_call_graph.copy()
                    # Store the resulting instruction and call graphs
                    if not self.cancelled(thread_name="find"):
                        par_map[ParamKey(src_par_idx, src_par_var)] = Graphs(
                            src_inst_graph, src_call_graph
                        )
        return

    def _slice_snk_function(
        self,
        snk_fun: SinkFunction,
        sources: List[SourceFunction],
        manual_fun: SinkFunction | None,
        manual_fun_inst: bn.MediumLevelILCall
        | bn.MediumLevelILCallSsa
        | bn.MediumLevelILTailcall
        | bn.MediumLevelILTailcallSsa
        | None,
        manual_fun_all_code_xrefs: bool,
        max_call_level: int,
        max_slice_depth: int | None,
        max_memory_slice_depth: int,
        found_path: Callable[[Path], None],
    ) -> List[Path]:
        """
        This method performs backward slicing on the given sink function `snk_fun`. It then checks
        if any instructions of the sources were reached and if so creates a path. For each newly
        found path, it executes the `found_path` callback.
        """
        paths: List[Path] = []
        # Custom tag for logging
        custom_tag = f"{tag:s}] [Snk:{snk_fun.name:s}"
        # Calculate SHA1 hash of binary
        if self.bv.file.raw is not None:
            sha1_hash = hashlib.sha1(
                self.bv.file.raw.read(0, self.bv.file.raw.end)
            ).hexdigest()
        else:
            sha1_hash = ""
        # Get code cross-references
        code_refs = SymbolHelper.get_code_refs(self.bv, snk_fun.symbols)
        # Sink manually configured via UI
        if manual_fun is not None and manual_fun_inst is not None:
            # Sink without code cross-references
            if not manual_fun_all_code_xrefs or not code_refs:
                code_refs = {}
                for symbol_name in snk_fun.symbols:
                    mlil_insts: Set[bn.MediumLevelILInstruction] = code_refs.get(
                        symbol_name, set()
                    )
                    mlil_insts.add(manual_fun_inst)
                    code_refs[symbol_name] = mlil_insts
        # Sink configured via configuration files
        else:
            # Sink without code cross-references
            if not code_refs:
                for symbol_name in snk_fun.symbols:
                    mlil_insts: Set[bn.MediumLevelILInstruction] = code_refs.get(
                        symbol_name, set()
                    )
                    for symbol in self.bv.get_symbols_by_name(symbol_name):
                        caller_func = self.bv.get_function_at(symbol.address)
                        if caller_func is None or caller_func.mlil is None:
                            continue
                        # Build a synthetic call instruction
                        call_inst = FunctionHelper.get_mlil_synthetic_call_inst(
                            caller_func.mlil
                        )
                        if call_inst is None:
                            continue
                        mlil_insts.add(call_inst)
                    code_refs[symbol_name] = mlil_insts
        # Iterate code references
        for snk_sym_name, snk_insts in code_refs.items():
            if self.cancelled(thread_name="find"):
                break
            # Iterate sink instructions
            for snk_inst in snk_insts:
                if self.cancelled(thread_name="find"):
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
                self.log.info(
                    custom_tag,
                    f"Analyze sink function '0x{snk_sym_addr:x} {snk_sym_name:s}'",
                )
                snk_call_inst = snk_inst
                # Ignore calls with an invalid number of parameters
                if not snk_fun.par_cnt_fun(len(snk_call_inst.params)):
                    self.log.warn(
                        custom_tag,
                        f"0x{snk_sym_addr:x} Ignore call '0x{snk_sym_addr:x} {snk_sym_name:s}' due to an invalid number of arguments",
                    )
                    continue
                # Iterate sink instruction's parameters
                for snk_par_idx, snk_par_var in enumerate(
                    snk_call_inst.params, start=1
                ):
                    if self.cancelled(thread_name="find"):
                        break
                    self.log.debug(
                        custom_tag,
                        f"Analyze argument 'arg#{snk_par_idx:d}:{str(snk_par_var):s}'",
                    )
                    # Perform dataflow analysis on the parameter
                    if snk_fun.par_dataflow_fun(snk_par_idx):
                        # Ignore constant parameters
                        if (
                            snk_par_var.operation
                            != bn.MediumLevelILOperation.MLIL_VAR_SSA
                        ):
                            self.log.debug(
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
                            self.log.debug(
                                custom_tag,
                                f"0x{snk_sym_addr:x} Ignore dataflow determined argument 'arg#{snk_par_idx:d}:{str(snk_par_var):s}'",
                            )
                            continue
                    # Peform backward slicing of the parameter
                    if isinstance(manual_fun, SinkFunction) and manual_fun_inst:
                        par_slice_fun = manual_fun.par_slice_fun
                    else:
                        par_slice_fun = snk_fun.par_slice_fun
                    if par_slice_fun(snk_par_idx):
                        # Initialize backward slicer
                        snk_slicer = MediumLevelILBackwardSlicer(
                            self.bv,
                            self.log,
                            custom_tag,
                            max_call_level,
                            max_memory_slice_depth,
                            lambda: self.cancelled(thread_name="find"),
                        )
                        # Backward slice the parameter
                        snk_slicer.slice_backwards(snk_par_var)
                        # Add edge to instruction graph
                        snk_inst_graph = MediumLevelILInstructionGraph()
                        snk_inst_graph.add_edge(
                            (None, snk_call_inst), (None, snk_par_var)
                        )
                        snk_inst_graph = cast(
                            MediumLevelILInstructionGraph,
                            nx.compose(snk_inst_graph, snk_slicer.get_inst_graph()),
                        )
                        # Add node to call graph
                        snk_call_graph = snk_slicer.get_call_graph()
                        snk_call_graph.add_node(snk_call_inst.function)
                        snk_call_graph = snk_call_graph.copy()
                        # Iterate sources
                        for source in sources:
                            if self.cancelled(thread_name="find"):
                                break
                            # Iterate source instructions
                            for src_call_site, src_par_map in source.graph_map.items():
                                src_sym_addr = src_call_site.sym_addr
                                src_sym_name = src_call_site.sym_name
                                src_call_inst = src_call_site.call_inst
                                if self.cancelled(thread_name="find"):
                                    break
                                # Iterate source instruction's parameters
                                for src_param, src_graphs in src_par_map.items():
                                    src_par_idx = src_param.par_idx
                                    src_par_var = src_param.par_var
                                    src_inst_graph = src_graphs.inst_graph
                                    src_call_graph = src_graphs.call_graph
                                    if self.cancelled(thread_name="find"):
                                        break
                                    # Source parameter was not sliced
                                    if isinstance(manual_fun, SourceFunction):
                                        par_slice_fun = manual_fun.par_slice_fun
                                    else:
                                        par_slice_fun = source.par_slice_fun
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
                                            List[
                                                Tuple[
                                                    bn.MediumLevelILInstruction | None,
                                                    bn.MediumLevelILInstruction | None,
                                                ]
                                            ]
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
                                        src_path: List[
                                            Tuple[
                                                bn.MediumLevelILInstruction | None,
                                                bn.MediumLevelILInstruction | None,
                                            ]
                                        ] = []
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
                                            # Identify source parameter index and variable
                                            if len(combined_path) >= 2:
                                                src_inst = combined_path[-1]
                                                prv_inst = combined_path[-2]
                                                edge_attrs = (
                                                    snk_inst_graph.get_edge_data(
                                                        prv_inst, src_inst
                                                    )
                                                )
                                                if edge_attrs is not None:
                                                    call_params: Set[int] = (
                                                        edge_attrs.get(
                                                            "call_params", set()
                                                        )
                                                    )
                                                    if len(call_params) == 1:
                                                        src_par_idx = call_params.pop()
                                                        src_par_var = (
                                                            src_call_inst.params[
                                                                src_par_idx - 1
                                                            ]
                                                        )
                                                    else:
                                                        src_par_idx = None
                                                        src_par_var = None
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
                                                insts=[
                                                    i[1]
                                                    for i in combined_path
                                                    if i[1] is not None
                                                ],
                                                sha1_hash=sha1_hash,
                                            )
                                            # Ignore the path if we found it before
                                            if path in paths:
                                                continue
                                            # Combine source and sink call graphs
                                            combined_call_graph = cast(
                                                MediumLevelILFunctionGraph,
                                                nx.compose(
                                                    src_call_graph, snk_call_graph
                                                ),
                                            )
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
                                            self.log.info(custom_tag, t_log)
                                            self.log.debug(
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
                                                            basic_block.function.symbol.short_name
                                                            if basic_block.function
                                                            is not None
                                                            else "unknown"
                                                        )
                                                        bb_addr = basic_block[0].address
                                                        self.log.debug(
                                                            custom_tag,
                                                            f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}",
                                                        )
                                                except Exception:
                                                    pass
                                                self.log.debug(
                                                    custom_tag,
                                                    InstructionHelper.get_inst_info(
                                                        inst
                                                    ),
                                                )
                                            self.log.debug(
                                                custom_tag, "-----------------------"
                                            )
                                        # Ignore all other source instructions since a path was found
                                        break
        return paths

    def _find_paths(
        self,
        max_workers: int | None,
        fix_func_type: bool,
        max_call_level: int,
        max_slice_depth: int,
        max_memory_slice_depth: int,
        src_funs: List[SourceFunction],
        snk_funs: List[SinkFunction],
        manual_fun: SourceFunction | SinkFunction | None,
        manual_fun_inst: bn.MediumLevelILCall
        | bn.MediumLevelILCallSsa
        | bn.MediumLevelILTailcall
        | bn.MediumLevelILTailcallSsa
        | None,
        manual_fun_all_code_xrefs: bool,
        path_callback: Callable[[Path], None] = lambda _: None,
        finished_callback: Callable[[], None] = lambda: None,
    ) -> List[Path]:
        """
        This method searches for paths using static backward slicing.
        """
        self.log.info(tag, "Starting backward slicing")
        if not src_funs or not snk_funs:
            self.log.warn(tag, "No source or sink functions configured")
        else:
            # Fix source/sink function types
            if fix_func_type:
                # Source function synopses
                src_fun_synopses: Dict[str, Tuple[str, Callable[[int], bool]]] = {}
                for src_fun in src_funs:
                    for symbol in src_fun.symbols:
                        src_fun_synopses[symbol] = (
                            src_fun.synopsis,
                            src_fun.par_cnt_fun,
                        )
                # Sink function synopses
                snk_fun_synopses: Dict[str, Tuple[str, Callable[[int], bool]]] = {}
                for snk_fun in snk_funs:
                    for symbol in snk_fun.symbols:
                        snk_fun_synopses[symbol] = (
                            snk_fun.synopsis,
                            snk_fun.par_cnt_fun,
                        )
                # Fix function types
                fixed = False
                for func in self.bv.functions:
                    synopsis, par_cnt_fun = src_fun_synopses.get(
                        func.name, (None, None)
                    )
                    if (
                        synopsis is not None
                        and par_cnt_fun is not None
                        and not par_cnt_fun(len(func.parameter_vars))
                    ):
                        try:
                            type, _ = self.bv.parse_type_string(synopsis)
                            func.set_user_type(type)
                            fixed = True
                            self.log.info(
                                tag, f"Fixed type of source function {func.name:s}"
                            )
                        except Exception as e:
                            self.log.warn(
                                tag,
                                f"Failed to fix type of source function {func.name:s}: {str(e):s}",
                            )
                    synopsis, par_cnt_fun = snk_fun_synopses.get(
                        func.name, (None, None)
                    )
                    if (
                        synopsis is not None
                        and par_cnt_fun is not None
                        and not par_cnt_fun(len(func.parameter_vars))
                    ):
                        try:
                            type, _ = self.bv.parse_type_string(synopsis)
                            func.set_user_type(type)
                            fixed = True
                            self.log.info(
                                tag, f"Fixed type of source function {func.name:s}"
                            )
                        except Exception as e:
                            self.log.warn(
                                tag,
                                f"Failed to fix type of sink function {func.name:s}: {str(e):s}",
                            )
                if fixed:
                    self.bv.update_analysis_and_wait()
            # Backward slice source functions
            with futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit tasks
                tasks: List[futures.Future] = []
                for src_fun in src_funs:
                    if self.cancelled(thread_name="find"):
                        break
                    tasks.append(
                        executor.submit(
                            self._slice_src_function,
                            src_fun,
                            manual_fun
                            if isinstance(manual_fun, SourceFunction)
                            else None,
                            manual_fun_inst,
                            manual_fun_all_code_xrefs,
                        )
                    )
                # Wait for tasks to complete
                filename = os.path.basename(self.bv.file.filename)
                self.set_progress(
                    "find", f"[{filename:s}] Sliced sources: 0/{len(tasks):d}"
                )
                for cnt, _ in enumerate(futures.as_completed(tasks), start=1):
                    self.set_progress(
                        "find", f"[{filename:s}] Sliced sources: {cnt:d}/{len(tasks):d}"
                    )
            # Backward slice sink functions
            with futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit tasks
                tasks: List[futures.Future] = []
                for snk_fun in snk_funs:
                    if self.cancelled(thread_name="find"):
                        break
                    tasks.append(
                        executor.submit(
                            self._slice_snk_function,
                            snk_fun,
                            src_funs,
                            manual_fun
                            if isinstance(manual_fun, SinkFunction)
                            else None,
                            manual_fun_inst,
                            manual_fun_all_code_xrefs,
                            max_call_level,
                            max_slice_depth,
                            max_memory_slice_depth,
                            path_callback,
                        ),
                    )
                # Wait for tasks to complete and collect paths
                filename = os.path.basename(self.bv.file.filename)
                self.set_progress(
                    "find", f"[{filename:s}] Sliced sinks: 0/{len(tasks):d}"
                )
                for cnt, task in enumerate(futures.as_completed(tasks), start=1):
                    self.set_progress(
                        "find", f"[{filename:s}] Sliced sinks: {cnt:d}/{len(tasks):d}"
                    )
                    # Collect paths from task results
                    if task.done() and not task.exception():
                        paths = cast(List[Path], task.result())
                        self._paths.extend(paths)
        self.log.info(tag, "Backward slicing completed")
        finished_callback()
        return self._paths

    def find_paths(
        self,
        initial_progress_text: str = "",
        can_cancel: bool = False,
        max_workers: int | None = None,
        fix_func_type: bool | None = None,
        max_call_level: int | None = None,
        max_slice_depth: int | None = None,
        max_memory_slice_depth: int | None = None,
        enable_all_funs: bool = False,
        manual_fun: SourceFunction | SinkFunction | None = None,
        manual_fun_inst: bn.MediumLevelILCall
        | bn.MediumLevelILCallUntyped
        | bn.MediumLevelILCallSsa
        | bn.MediumLevelILCallUntypedSsa
        | bn.MediumLevelILTailcall
        | bn.MediumLevelILTailcallUntyped
        | bn.MediumLevelILTailcallSsa
        | bn.MediumLevelILTailcallUntypedSsa
        | None = None,
        manual_fun_all_code_xrefs: bool = False,
        path_callback: Callable[[Path], None] = lambda _: None,
        finished_callback: Callable[[], None] = lambda: None,
    ) -> None:
        """
        This method searches for paths in a background thread.
        """
        # Cancel path finding thread if already running
        if self.is_alive("find"):
            self.cancel("find")
            return
        # Ensure no other thread is running
        if self.is_alive():
            self.log.warn(tag, "Another thread of the path service is still runnning")
            return
        # Determine settings
        self.log.debug(tag, "Settings")
        if max_workers is None:
            setting = self.config_model.get_setting("max_workers")
            if isinstance(setting, SpinboxSetting):
                max_workers = int(setting.value)
        if max_workers is not None and max_workers <= 0:
            max_workers = None
        self.log.debug(tag, f"- max_workers           : '{max_workers}'")
        if fix_func_type is None:
            fix_func_type = False
            setting = self.config_model.get_setting("fix_func_type")
            if isinstance(setting, CheckboxSetting):
                fix_func_type = bool(setting.value)
        fix_func_type = cast(bool, fix_func_type)
        self.log.debug(tag, f"- fix_func_type         : '{str(fix_func_type):s}'")
        if max_call_level is None:
            max_call_level = 10
            setting = self.config_model.get_setting("max_call_level")
            if isinstance(setting, SpinboxSetting):
                max_call_level = int(setting.value)
        max_call_level = cast(int, max_call_level)
        self.log.debug(tag, f"- max_call_level        : '{max_call_level}'")
        if max_slice_depth is None:
            max_slice_depth = 1000
            setting = self.config_model.get_setting("max_slice_depth")
            if isinstance(setting, SpinboxSetting):
                max_slice_depth = int(setting.value)
        max_slice_depth = cast(int, max_slice_depth)
        self.log.debug(tag, f"- max_slice_depth       : '{max_slice_depth}'")
        if max_memory_slice_depth is None:
            max_memory_slice_depth = 10
            setting = self.config_model.get_setting("max_memory_slice_depth")
            if isinstance(setting, SpinboxSetting):
                max_memory_slice_depth = int(setting.value)
        max_memory_slice_depth = cast(int, max_memory_slice_depth)
        self.log.debug(tag, f"- max_memory_slice_depth: '{max_memory_slice_depth}'")
        # Source functions
        src_funs = cast(
            List[SourceFunction],
            self.config_model.get_functions(
                fun_type="Sources",
                fun_enabled=(None if enable_all_funs else True),
            ),
        )
        # Manually configured source function
        if isinstance(manual_fun, SourceFunction):
            # Use only manually configured source function
            if not manual_fun_all_code_xrefs:
                src_funs = [manual_fun]
            # Use all configured source functions with the manually selected symbol
            else:
                src_funs = [
                    src_fun
                    for src_fun in src_funs
                    if any(symbol in src_fun.symbols for symbol in manual_fun.symbols)
                ]
                if not src_funs:
                    src_funs = [manual_fun]
        self.log.debug(tag, f"- number of sources     : '{len(src_funs):d}'")
        # Sink functions
        snk_funs = cast(
            List[SinkFunction],
            self.config_model.get_functions(
                fun_type="Sinks", fun_enabled=(None if enable_all_funs else True)
            ),
        )
        # Manually configured sink function
        if isinstance(manual_fun, SinkFunction):
            # Use only manually configured sink function
            if not manual_fun_all_code_xrefs:
                snk_funs = [manual_fun]
            # Use all configured sink functions with the manually selected symbol
            else:
                snk_funs = [
                    snk_fun
                    for snk_fun in snk_funs
                    if any(symbol in snk_fun.symbols for symbol in manual_fun.symbols)
                ]
                if not snk_funs:
                    snk_funs = [manual_fun]
        self.log.debug(tag, f"- number of sinks       : '{len(snk_funs):d}'")
        # Clear previous paths and caches
        self._paths.clear()
        FunctionHelper.cache_clear()
        # Start background task
        self.start(
            thread_name="find",
            initial_progress_text=initial_progress_text,
            can_cancel=can_cancel,
            run=self._find_paths,
            max_workers=max_workers,
            fix_func_type=fix_func_type,
            max_call_level=max_call_level,
            max_slice_depth=max_slice_depth,
            max_memory_slice_depth=max_memory_slice_depth,
            src_funs=src_funs,
            snk_funs=snk_funs,
            manual_fun=manual_fun,
            manual_fun_inst=manual_fun_inst,
            manual_fun_all_code_xrefs=manual_fun_all_code_xrefs,
            path_callback=path_callback,
            finished_callback=finished_callback,
        )
        return
