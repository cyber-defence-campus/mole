from __future__ import annotations
from typing import Any, Callable, Dict, Tuple
import threading


class WorkerThread(threading.Thread):
    """
    This class implements a generic worker thread.
    """

    def __init__(
        self, run: Callable[..., Any] | None = None, *args: Any, **kwargs: Any
    ) -> None:
        """
        This method initializes the worker thread.
        """
        super().__init__()
        self._run = run
        self._args: Tuple[Any, ...] = args
        self._kwargs: Dict[str, Any] = kwargs
        self._results: Any = None
        self._cancel_event = threading.Event()
        return

    def run(self) -> None:
        """
        This method runs the worker thread.
        """
        if self._run is not None:
            self._results = self._run(*self._args, **self._kwargs)
        return

    def cancelled(self) -> bool:
        """
        This method returns whether or not the worker thread was cancelled.
        """
        return self._cancel_event.is_set()

    def cancel(self) -> None:
        """
        This method cancels the worker thread.
        """
        return self._cancel_event.set()

    def results(self) -> Any:
        """
        This method waits for the worker thread to complete and returns its results.
        """
        self.join()
        return self._results


class WorkerService:
    """
    This class implements a generic worker service.
    """

    def __init__(self) -> None:
        """
        This method initializes the worker service.
        """
        self._lock = threading.RLock()
        self._threads: Dict[str, WorkerThread] = {}
        return

    def is_alive(self, thread_name: str = "") -> bool:
        """
        This method returns whether or not the thread with the given name is alive. If no thread
        name is given, it returns whether or not any thread of the service is alive.
        """
        with self._lock:
            if not thread_name:
                return any(thread.is_alive() for thread in self._threads.values())
            thread = self._threads.get(thread_name)
            return thread is not None and thread.is_alive()

    def cancelled(self, thread_name: str = "") -> bool:
        """
        This method returns whether or not the thread with the given name was cancelled. If no
        thread name is given, it returns whether or not any thread of the service was cancelled.
        """
        with self._lock:
            if not thread_name:
                return any(thread.cancelled() for thread in self._threads.values())
            thread = self._threads.get(thread_name)
            return thread is not None and thread.cancelled()

    def cancel(self, thread_name: str = "") -> None:
        """
        This method cancels the thread with the given name. If no thread name is given, it cancels
        all threads of the service.
        """
        with self._lock:
            if not thread_name:
                for thread in self._threads.values():
                    thread.cancel()
            else:
                thread = self._threads.get(thread_name)
                if thread is not None:
                    thread.cancel()
            return

    def start(
        self,
        thread_name: str,
        run: Callable[..., Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        """
        This method starts the thread with the given name. It returns `True` if the thread was
        correctly started, and `False` if the same thread is already running.
        """
        with self._lock:
            # Background thread is already running
            if self.is_alive(thread_name):
                return False
            # Start background thread
            self._threads[thread_name] = WorkerThread(
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
        with self._lock:
            _thread = self._threads.get(thread_name)
        return _thread.results() if _thread is not None else None
