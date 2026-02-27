from __future__ import annotations
from datetime import datetime
from termcolor import colored
from typing import List, Literal
import binaryninja as bn
import os
import sys


class Logger:
    """
    This class implements a logger that can print messages to Binary Ninja's log and to the console.
    """

    _levels = ["debug", "info", "warning", "error", "none"]

    def __init__(
        self,
        bv: bn.BinaryView | None = None,
        level: Literal["debug", "info", "warning", "error", "none"] = "debug",
    ) -> None:
        """
        This method initializes a logger that can be used to write messages of a given level (and
        above) to Binary Ninja's log and to stdout/stderr.
        """
        self._logger = bn.Logger(0, "Plugin: Mole")
        self._level = self._levels.index(level)
        self._runs_debugger = False
        self._runs_headless = False
        self._file_tag = ""
        self._init(bv)
        return

    def _init(self, bv: bn.BinaryView | None = None) -> None:
        # Detect whether or not a debugger is attached
        self.detect_attached_debugger()
        # Try to import the Binary Ninja UI module
        try:
            import binaryninjaui as bnui
        except Exception:
            bnui = None
        # Detect whether or not running in headless mode
        self._runs_headless = bnui is None
        # Try to get the current BinaryView when running in UI mode
        if not self._runs_headless and bv is None:
            ctx = bnui.UIContext.activeContext()  # type: ignore
            if ctx is not None:
                vf = ctx.getCurrentViewFrame()
                if vf is not None:
                    bv = vf.getCurrentBinaryView()
        # File tag
        if bv is not None:
            # Project file
            if bv.project_file is not None:
                self._file_tag = (
                    f"[{bv.project_file.project.name:s}/{bv.project_file.name:s}]"
                )
            # Not a project file
            else:
                self._file_tag = f"[{os.path.basename(bv.file.filename)}]"
        return

    def detect_attached_debugger(self) -> None:
        """
        This method detects whether or not a debugger is attached.
        """
        self._runs_debugger = any(
            module.startswith("debugpy") for module in sys.modules
        )
        return

    def _tag_msg(
        self,
        tag: str = "",
        msg: str = "",
    ) -> str:
        """
        This method prepends a tag to the message.
        """
        m = self._file_tag
        if tag:
            m = f"{m:s} [{tag:s}]"
        if msg:
            m = f"{m:s} {msg:s}"
        return m.strip()

    def _print(
        self,
        tag: str,
        msg: str,
        color: str,
        on_color: str = "",
        print_raw: bool = False,
        attrs: List[str] = [],
        file=sys.stderr,
    ) -> None:
        """
        This method prints the given message to the console.
        """
        if not print_raw:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            head = f"[{now:s}] [{tag:s}] "
        else:
            head = ""
        print(
            colored(
                f"{head:s}{msg:s}",
                color=color,
                on_color=on_color if on_color else None,
                attrs=attrs,
            ),
            file=file,
            flush=True,
        )
        return

    def debug(
        self,
        tag: str = "",
        msg: str = "",
        color: str = "magenta",
        on_color: str = "",
        print_raw: bool = False,
        attrs: List[str] = [],
    ) -> None:
        """
        This method prints a tagged message of log level debug to the console or Binary Ninja's log.
        """
        text = self._tag_msg(tag, msg)
        if not self._runs_headless and not self._runs_debugger:
            self._logger.log_debug(text)
        elif self._runs_debugger or self._level <= 0:
            self._print(
                "DEBG",
                text,
                color=color,
                on_color=on_color,
                print_raw=print_raw,
                attrs=attrs,
                file=sys.stdout if self._runs_debugger else sys.stderr,
            )

        return

    def info(
        self,
        tag: str = "",
        msg: str = "",
        color: str = "blue",
        on_color: str = "",
        print_raw: bool = False,
        attrs: List[str] = [],
    ) -> None:
        """
        This method prints a tagged message of log level info to the console or Binary Ninja's log.
        """
        text = self._tag_msg(tag, msg)
        if not self._runs_headless and not self._runs_debugger:
            self._logger.log_info(text)
        elif self._runs_debugger or self._level <= 1:
            self._print(
                "INFO",
                text,
                color=color,
                on_color=on_color,
                print_raw=print_raw,
                attrs=attrs,
                file=sys.stdout if self._runs_debugger else sys.stderr,
            )
        return

    def warn(
        self,
        tag: str = "",
        msg: str = "",
        color: str = "yellow",
        on_color: str = "",
        print_raw: bool = False,
        attrs: List[str] = [],
    ) -> None:
        """
        This method prints a tagged message of log level warn to the console or Binary Ninja's log.
        """
        text = self._tag_msg(tag, msg)
        if not self._runs_headless and not self._runs_debugger:
            self._logger.log_warn(text)
        elif self._runs_debugger or self._level <= 2:
            self._print(
                "WARN",
                text,
                color=color,
                on_color=on_color,
                print_raw=print_raw,
                attrs=attrs,
                file=sys.stdout if self._runs_debugger else sys.stderr,
            )
        return

    def error(
        self,
        tag: str = "",
        msg: str = "",
        color: str = "red",
        on_color: str = "",
        print_raw: bool = False,
        attrs: List[str] = [],
    ) -> None:
        """
        This method prints a tagged message of log level error to the console or Binary Ninja's log.
        """
        text = self._tag_msg(tag, msg)
        if not self._runs_headless and not self._runs_debugger:
            self._logger.log_error(text)
        elif self._runs_debugger or self._level <= 3:
            self._print(
                "ERRO",
                text,
                color=color,
                on_color=on_color,
                print_raw=print_raw,
                attrs=attrs,
                file=sys.stdout if self._runs_debugger else sys.stderr,
            )
        return
