from __future__ import annotations
from concurrent import futures
from mole.common.log import log
from mole.common.task import BackgroundTask
from mole.core.data import Path, SourceFunction, SinkFunction
from mole.models.config import ConfigModel
from typing import Callable, List, Optional
import binaryninja as bn


tag = "Mole.Path"


class PathService(BackgroundTask):
    """
    This class implements a background task that tries to find interesting code paths using static
    backward slicing.
    """

    def __init__(
        self,
        bv: bn.BinaryView,
        config_model: ConfigModel,
        max_workers: Optional[int] = None,
        max_call_level: Optional[int] = None,
        max_slice_depth: Optional[int] = None,
        max_memory_slice_depth: Optional[int] = None,
        enable_all_funs: bool = False,
        manual_fun: Optional[SourceFunction | SinkFunction] = None,
        manual_fun_inst: Optional[
            bn.MediumLevelILCall
            | bn.MediumLevelILCallSsa
            | bn.MediumLevelILTailcall
            | bn.MediumLevelILTailcallSsa
        ] = None,
        manual_fun_all_code_xrefs: bool = False,
        path_callback: Optional[Callable[[Path], None]] = None,
        initial_progress_text: str = "",
        can_cancel: bool = False,
    ) -> None:
        """
        This method initializes the path service.
        """
        super().__init__(initial_progress_text, can_cancel)
        self._bv = bv
        self._config_model = config_model
        self._max_workers = max_workers
        self._max_call_level = max_call_level
        self._max_slice_depth = max_slice_depth
        self._max_memory_slice_depth = max_memory_slice_depth
        self._enable_all_funs = enable_all_funs
        self._manual_fun = manual_fun
        self._manual_fun_inst = manual_fun_inst
        self._manual_fun_all_code_xrefs = manual_fun_all_code_xrefs
        self._path_callback = path_callback
        return

    @property
    def _paths(self) -> List[Path]:
        paths: List[Path] = self._results
        return paths

    @_paths.setter
    def _paths(self, paths: List[Path]) -> None:
        self._results = paths
        return

    def run(self) -> None:
        """
        This method runs the background task, i.e. tries to identify interesting code paths using
        static backward slicing.
        """
        log.info(tag, "Starting backward slicing")
        self._paths = []
        # Settings
        log.debug(tag, "Settings")
        max_workers = self._max_workers
        if max_workers is None:
            setting = self._config_model.get_setting("max_workers")
            if setting:
                max_workers = setting.value
        if max_workers is not None and max_workers <= 0:
            max_workers = None
        log.debug(tag, f"- max_workers: '{max_workers}'")
        max_call_level = self._max_call_level
        if max_call_level is None:
            setting = self._config_model.get_setting("max_call_level")
            if setting:
                max_call_level = setting.value
        log.debug(tag, f"- max_call_level: '{max_call_level}'")
        max_slice_depth = self._max_slice_depth
        if max_slice_depth is None:
            setting = self._config_model.get_setting("max_slice_depth")
            if setting:
                max_slice_depth = setting.value
        log.debug(tag, f"- max_slice_depth: '{max_slice_depth}'")
        max_memory_slice_depth = self._max_memory_slice_depth
        if max_memory_slice_depth is None:
            setting = self._config_model.get_setting("max_memory_slice_depth")
            if setting:
                max_memory_slice_depth = setting.value
        log.debug(tag, f"- max_memory_slice_depth: '{max_memory_slice_depth}'")
        # Source functions
        src_funs: List[SourceFunction] = self._config_model.get_functions(
            fun_type="Sources",
            fun_enabled=(None if self._enable_all_funs else True),
        )
        # Manually configured source function
        if isinstance(self._manual_fun, SourceFunction):
            # Use only manually configured source function
            if not self._manual_fun_all_code_xrefs:
                src_funs = [self._manual_fun]
            # Use all configured source functions with the manually selected symbol
            else:
                src_funs = [
                    src_fun
                    for src_fun in src_funs
                    if any(
                        symbol in src_fun.symbols for symbol in self._manual_fun.symbols
                    )
                ]
                if not src_funs:
                    src_funs = [self._manual_fun]
        log.debug(tag, f"- number of sources: '{len(src_funs):d}'")
        # Sink functions
        snk_funs: List[SinkFunction] = self._config_model.get_functions(
            fun_type="Sinks", fun_enabled=(None if self._enable_all_funs else True)
        )
        # Manually configured sink function
        if isinstance(self._manual_fun, SinkFunction):
            # Use only manually configured sink function
            if not self._manual_fun_all_code_xrefs:
                snk_funs = [self._manual_fun]
            # Use all configured sink functions with the manually selected symbol
            else:
                snk_funs = [
                    snk_fun
                    for snk_fun in snk_funs
                    if any(
                        symbol in snk_fun.symbols for symbol in self._manual_fun.symbols
                    )
                ]
                if not snk_funs:
                    snk_funs = [self._manual_fun]
        log.debug(tag, f"- number of sinks: '{len(snk_funs):d}'")
        # Backward slicing
        if not src_funs or not snk_funs:
            log.warn(tag, "No source or sink functions configured")
        else:
            # Backward slice source functions
            with futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit tasks
                tasks: List[futures.Future] = []
                for src_fun in src_funs:
                    if self.cancelled:
                        break
                    tasks.append(
                        executor.submit(
                            src_fun.find_targets,
                            self._bv,
                            self._manual_fun,
                            self._manual_fun_inst,
                            self._manual_fun_all_code_xrefs,
                            lambda: self.cancelled,
                        )
                    )
                # Wait for tasks to complete
                self.progress = f"Mole processes {len(tasks):d} source functions"
                for cnt, _ in enumerate(futures.as_completed(tasks)):
                    self.progress = f"Mole processed source {cnt + 1:d}/{len(tasks):d}"
            # Backward slice sink functions
            with futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit tasks
                tasks: List[futures.Future] = []
                for snk_fun in snk_funs:
                    if self.cancelled:
                        break
                    tasks.append(
                        executor.submit(
                            snk_fun.find_paths,
                            self._bv,
                            src_funs,
                            self._manual_fun,
                            self._manual_fun_inst,
                            self._manual_fun_all_code_xrefs,
                            max_call_level,
                            max_slice_depth,
                            max_memory_slice_depth,
                            self._path_callback,
                            lambda: self.cancelled,
                        )
                    )
                # Wait for tasks to complete and collect paths
                self.progress = f"Mole processes {len(tasks):d} sink functions"
                for cnt, task in enumerate(futures.as_completed(tasks)):
                    self.progress = f"Mole processed sink {cnt + 1:d}/{len(tasks):d}"
                    # Collect paths from task results
                    if task.done() and not task.exception():
                        paths = task.result()
                        if paths:
                            self._paths.extend(paths)
        log.info(tag, "Backward slicing completed")
        return

    def paths(self) -> List[Path]:
        """
        This method waits for the backward slicing to complete and returns all identified paths.
        """
        paths: List[Path] = self.results()
        return paths
