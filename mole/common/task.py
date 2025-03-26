from mole.common.log import log
from typing          import Any, Callable, Optional, Tuple
import binaryninja as bn


tag = "Mole.Task"


class BackgroundTask(bn.BackgroundTaskThread):
    """
    This class implements a general background task.
    """

    def __init__(
            self,
            initial_progress_text: str = "",
            can_cancel: bool = False,
            run: Optional[Callable[..., Any]] = None,
            *args: Any,
            **kwargs: Any
        ) -> None:
        """
        This method initializes the background task.
        """
        super().__init__(initial_progress_text, can_cancel)
        self._run = run
        self._args: Tuple[Any, ...] = args
        self._kwargs: dict[str, Any] = kwargs
        self._results: Any = None
        return
    
    def run(self) -> None:
        """
        This method runs the background task.
        """
        log.info(tag, "Starting background task")
        if self._run:
            self._results = self._run(*self._args, **self._kwargs)
        log.info(tag, "Background task completed")
        return
    
    def results(self) -> Any:
        """
        This method waits for the background task to complete and returns its results.
        """
        self.join()
        return self._results