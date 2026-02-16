from __future__ import annotations
from concurrent import futures
from mole.core.data import (
    CheckboxSetting,
    ComboboxSetting,
    Path,
    SinkFunction,
    SourceFunction,
    SpinboxSetting,
)
from mole.common.helper.function import FunctionHelper
from mole.common.log import Logger
from mole.common.task import BackgroundService
from mole.grouping import get_grouper, PathGrouper
from mole.models.config import ConfigModel
from typing import Callable, cast, Dict, List, Tuple
import binaryninja as bn


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
        path_callback: Callable[[Path], None] | None = None,
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
                            src_fun.find_targets,
                            self.bv,
                            manual_fun
                            if isinstance(manual_fun, SourceFunction)
                            else None,
                            manual_fun_inst,
                            manual_fun_all_code_xrefs,
                            lambda: self.cancelled(thread_name="find"),
                            self.log,
                        )
                    )
                # Wait for tasks to complete
                self.progress = f"Mole processes {len(tasks):d} source functions"
                for cnt, _ in enumerate(futures.as_completed(tasks), start=1):
                    self.progress = f"Mole processed source {cnt:d}/{len(tasks):d}"
            # Backward slice sink functions
            with futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit tasks
                tasks: List[futures.Future] = []
                for snk_fun in snk_funs:
                    if self.cancelled(thread_name="find"):
                        break
                    tasks.append(
                        executor.submit(
                            snk_fun.find_paths,
                            self.bv,
                            src_funs,
                            manual_fun
                            if isinstance(manual_fun, SinkFunction)
                            else None,
                            manual_fun_inst,
                            manual_fun_all_code_xrefs,
                            max_call_level,
                            max_slice_depth,
                            max_memory_slice_depth,
                            path_callback
                            if path_callback is not None
                            else lambda _: None,
                            lambda: self.cancelled(thread_name="find"),
                            self.log,
                        )
                    )
                # Wait for tasks to complete and collect paths
                self.progress = f"Mole processes {len(tasks):d} sink functions"
                for cnt, task in enumerate(futures.as_completed(tasks), start=1):
                    self.progress = f"Mole processed sink {cnt:d}/{len(tasks):d}"
                    # Collect paths from task results
                    if task.done() and not task.exception():
                        paths = cast(List[Path], task.result())
                        self._paths.extend(paths)
        self.log.info(tag, "Backward slicing completed")
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
        path_callback: Callable[[Path], None] | None = None,
    ) -> None:
        """
        This method searches for paths in a background thread.
        """
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
        )
        return
