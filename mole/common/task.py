from __future__ import annotations
from typing import Any, Callable, Dict, Tuple
import binaryninja as bn


class BackgroundThread(bn.BackgroundTaskThread):
    """
    This class implements a generic background thread.
    """

    def __init__(
        self,
        initial_progress_text: str = "",
        can_cancel: bool = False,
        run: Callable[..., Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """
        This method initializes the background thread.
        """
        super().__init__(initial_progress_text, can_cancel)
        self._run = run
        self._args: Tuple[Any, ...] = args
        self._kwargs: Dict[str, Any] = kwargs
        self._is_running: bool = False
        self._results: Any = None
        return

    @property
    def is_alive(self) -> bool:
        """
        This property returns whether the background thread is currently running or not.
        """
        return self._is_running and not self.finished

    def run(self) -> None:
        """
        This method runs the background thread.
        """
        self._is_running = True
        if self._run:
            self._results = self._run(*self._args, **self._kwargs)
        self._is_running = False
        return

    def results(self) -> Any:
        """
        This method waits for the background thread to complete and returns its results.
        """
        self.join()
        return self._results


class BackgroundService:
    """
    This class implements a generic background service.
    """

    def __init__(self) -> None:
        """
        This method initializes the background service.
        """
        self._threads: Dict[str, BackgroundThread] = {}
        return

    def is_alive(self, thread_name: str = "") -> bool:
        """
        This method returns whether or not the thread with the given name is alive. If no thread
        name is given, it returns whether or not any thread of the service is alive.
        """
        if not thread_name:
            return any(thread.is_alive for thread in self._threads.values())
        thread = self._threads.get(thread_name)
        return thread is not None and thread.is_alive

    def cancelled(self, thread_name: str = "") -> bool:
        """
        This method returns whether or not the thread with the given name was cancelled. If no
        thread name is given, it returns whether or not any thread of the service was cancelled.
        """
        if not thread_name:
            return any(thread.cancelled for thread in self._threads.values())
        thread = self._threads.get(thread_name)
        return thread is not None and thread.cancelled

    def get_progress(self, thread_name: str) -> str | None:
        """
        This method returns the progress of the thread with the given name.
        """
        _thread = self._threads.get(thread_name)
        return _thread.progress if _thread is not None else None

    def set_progress(self, thread_name: str, value: str) -> None:
        """
        This method sets the progress of the thread with the given name.
        """
        _thread = self._threads.get(thread_name)
        if _thread is not None:
            _thread.progress = value
        return

    def start(
        self,
        thread_name: str,
        initial_progress_text: str = "",
        can_cancel: bool = False,
        run: Callable[..., Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        """
        This method starts the thread with the given name. It returns `True` if the thread was
        correctly started, and `False` if the same thread is already running.
        """
        # Background thread is already running
        if self.is_alive(thread_name):
            return False
        # Start background thread
        self._threads[thread_name] = BackgroundThread(
            initial_progress_text=initial_progress_text,
            can_cancel=can_cancel,
            run=run,
            *args,
            **kwargs,
        )
        self._threads[thread_name].start()
        return True

    def results(self, thread_name: str) -> Any:
        """
        This method waits for the thread with the given name to complete and returns its results.
        """
        _thread = self._threads.get(thread_name)
        return _thread.results() if _thread is not None else None
