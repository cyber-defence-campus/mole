
from __future__      import annotations
from ..core.data     import Path, SourceFunction, SinkFunction
from ..models.config import ConfigModel
from concurrent      import futures
from mole.common.log import log
from typing          import Callable, List, Optional
import binaryninja as bn


tag = "Mole.Slice"


class MediumLevelILBackwardSlicerThread(bn.BackgroundTaskThread):
    """
    This class implements a background thread that runs backward slicing for MLIL instructions.
    """
    def __init__(
            self,
            bv: bn.BinaryView,
            config_model: ConfigModel,
            max_workers: int | None = None,
            max_call_level: int = None,
            max_slice_depth: int = None,
            enable_all_funs: bool = False,
            path_callback: Optional[Callable[[Path, str], None]] = None
        ) -> None:
        """
        This method initializes the background task.
        """
        super().__init__(initial_progress_text="Start slicing...", can_cancel=True)
        self._bv = bv
        self._config_model = config_model
        self._max_workers = max_workers
        self._max_call_level = max_call_level
        self._max_slice_depth = max_slice_depth
        self._enable_all_funs = enable_all_funs
        self._path_callback = path_callback
        self._paths = None
        return
    
    def run(self) -> None:
        """
        This method implements the background task's functionality, i.e. it tries to identify
        intersting code paths using static backward slicing.
        """
        log.info(tag, "Starting analysis")
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
        src_funs: List[SourceFunction] = self._config_model.get_functions(fun_type="Sources", fun_enabled=(None if self._enable_all_funs else True))
        log.debug(tag, f"- number of sources: '{len(src_funs):d}'")
        snk_funs: List[SinkFunction] = self._config_model.get_functions(fun_type="Sinks", fun_enabled=(None if self._enable_all_funs else True))
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
                                lambda: self.cancelled
                            )
                        )
                    # Wait for tasks to complete
                    for cnt, _ in enumerate(futures.as_completed(tasks)):
                        if self.cancelled: 
                            break
                        self.progress = f"Mole processes source {cnt+1:d}/{len(src_funs):d}"
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
                            max_call_level,
                            max_slice_depth,
                            self._path_callback,
                            lambda: self.cancelled
                        )
                    )
                # Wait for tasks to complete and collect paths
                for cnt, task in enumerate(futures.as_completed(tasks)):
                    if self.cancelled: 
                        break
                    self.progress = f"Mole processes sink {cnt+1:d}/{len(snk_funs):d}"
                    # Collect paths from task results
                    if task.done() and not task.exception():
                        paths = task.result()
                        if paths:
                            self._paths.extend(paths)
        log.info(tag, "Analysis completed")
        return
    
    def get_paths(self) -> List[Path]:
        """
        This method blocks until backward slicing finished and then returns all identified
        interesting looking code paths.
        """
        self.join()
        return self._paths