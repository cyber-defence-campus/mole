from __future__   import annotations
from typing       import Dict, List, Union
from ..common.log import Logger
from ..ui.config  import ConfigController
import binaryninja as bn


class MediumLevelILBackwardSlicerThread(bn.BackgroundTaskThread):
    """
    This class implements a background thread that runs backward slicing for MLIL instructions.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            controller: ConfigController,
            runs_headless: bool = False,
            max_func_depth: int = None,
            enable_all_funs: bool = False,
            tag: str = "BackSlicer",
            log: Logger = Logger()
        ) -> None:
        super().__init__(initial_progress_text="Start slicing...", can_cancel=True)
        self._bv = bv
        self._controller = controller
        self._runs_headless = runs_headless
        self._max_func_depth = max_func_depth
        self._enable_all_funs = enable_all_funs
        self._tag = tag
        self._log = log
        return
    
    def run(self) -> None:
        """
        This method tries to identify intersting code paths using static backward slicing.
        """
        self._paths = []

        # Source functions
        if self._enable_all_funs:
            src_funs = self._controller.get_all_funs(flowtype="Sources")
        else:
            src_funs = self._controller.get_enabled_funs(flowtype="Sources")
        if not src_funs:
            self._log.warn(self._tag, "No source functions configured")
        else:
            for i, src_fun in enumerate(src_funs):
                if self.cancelled: break
                self.progress = f"Find targets for source function {i+1:d}/{len(src_funs):d}..."
                src_fun.find_targets(self._bv, lambda: self.cancelled)

        # Sink functions
        if self._enable_all_funs:
            snk_funs = self._controller.get_all_funs(flowtype="Sinks")
        else:
            snk_funs = self._controller.get_enabled_funs(flowtype="Sinks")
        if not snk_funs:
            self._log.warn(self._tag, "No sink functions configured")

        # Find paths
        max_func_depth = self._max_func_depth
        if max_func_depth is None:
            max_func_depth = self._controller.get_max_func_depth()
        if src_funs and snk_funs:
            for i, snk_fun in enumerate(snk_funs):
                if self.cancelled: break
                self.progress = f"Find paths for sink function {i+1:d}/{len(snk_funs):d}..."
                ps = snk_fun.find_paths(self._bv, src_funs, max_func_depth, lambda: self.cancelled)
                self._paths.extend(ps)
        return
    
    def get_paths(self) -> List[
            Dict[str, Union[str, Dict[str, Union[int, bn.MediumLevelILInstruction]]]]
        ]:
        """
        This method blocks until backward slicing finished and then returns all identified
        interesting looking code paths.
        """
        self.join()
        return self._paths