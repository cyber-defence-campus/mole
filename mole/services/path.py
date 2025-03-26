from mole.common.log import log
from typing          import Callable, Optional
import binaryninja as bn


tag = "Mole.Path"


class PathHelperThread(bn.BackgroundTaskThread):
    """
    This class implements a helper class to run path-related functionalities as background tasks.
    """

    def __init__(
            self,
            initial_progress_text: str = "",
            can_cancel: bool = False,
            run: Optional[Callable[[], None]] = None
        ) -> None:
        """
        This method initializes the background task.
        """
        super().__init__(initial_progress_text, can_cancel)
        self._run = run
        return
    
    def run(self) -> None:
        """
        This method runs the background task.
        """
        log.info(tag, "Starting background task")
        if self._run:
            self._run()
        log.info(tag, "Background task completed")
        return