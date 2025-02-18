from   binaryninja import log_debug, log_info, log_warn, log_error
from   datetime    import datetime
from   termcolor   import colored
from   typing      import List, Literal
import sys


class Logger:
    """
    This class prints messages to the console or Binary Ninja's log.
    """

    _levels = ["debug", "info", "warning", "error"]

    def __init__(
            self,
            level: Literal["debug", "info", "warning", "error"] = "info",
            runs_headless: bool = False
        ) -> None:
        """
        This method initializes a logger that writes messages of a given `level` and above to
        `stdout`/`stderr`, as well as to Binary Ninja's log in case `runs_headless` is set to
        `False`.
        """
        self._level = self._levels.index(level)
        self._runs_headless: bool = runs_headless
        return
    
    def get_level(self) -> str:
        """
        This method returns the configured log level.
        """
        return self._levels[self._level]

    def _tag_msg(
            self,
            tag: str = None,
            msg: str = None,
        ) -> str:
        """
        This method concatenates tag `tag` to the message `msg`.
        """
        m = ""
        if tag:
            m = f"[{tag:s}]"
        if msg:
            m = f"{m:s} {msg:s}"
        return m.strip()

    def _print(
            self,
            tag: str,
            msg: str,
            color: str,
            on_color: str = None,
            print_raw: bool = False,
            attrs: List[str] = [],
            file = sys.stdout
        ) -> None:
        """
        This method prints the message `msg` to the console.
        """
        if not print_raw:
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            head = f"[{now:s}] [{tag:s}] "
        else:
            head = ""
        print(colored(f"{head:s}{msg:s}", color=color, on_color=on_color, attrs=attrs), file=file, flush=True)
        return
    
    def debug(
            self,
            tag: str = None,
            msg: str = None,
            color: str = "magenta",
            on_color: str = None,
            print_raw: bool = False,
            attrs: List[str] = []
        ) -> None:
        """
        This method prints a tagged message of log level debug to the console or Binary Ninja's log.
        """
        text = self._tag_msg(tag, msg)
        if self._level > 0: return
        if not self._runs_headless:
            log_debug(text, "Plugin.Mole")
        self._print(
            "DEBG", text,
            color=color, on_color=on_color, print_raw=print_raw,
            attrs=attrs, file=sys.stdout
        )
        return
    
    def info(
            self,
            tag: str = None,
            msg: str = None,
            color: str = "blue",
            on_color: str = None,
            print_raw: bool = False,
            attrs: List[str] = []
        ) -> None:
        """
        This method prints a tagged message of log level info to the console or Binary Ninja's log.
        """
        text = self._tag_msg(tag, msg)
        if self._level > 1: return
        if not self._runs_headless:
            log_info(text, "Plugin.Mole")
        self._print(
            "INFO", text,
            color=color, on_color=on_color, print_raw=print_raw,
            attrs=attrs, file=sys.stdout
        ) 
        return
    
    def warn(
            self,
            tag: str = None,
            msg: str = None,
            color: str = "yellow",
            on_color: str = None,
            print_raw: bool = False,
            attrs: List[str] = []
        ) -> None:
        """
        This method prints a tagged message of log level warn to the console or Binary Ninja's log.
        """
        text = self._tag_msg(tag, msg)
        if self._level > 2: return
        if not self._runs_headless:
            log_warn(text, "Plugin.Mole")
        self._print(
            "WARN", text,
            color=color, on_color=on_color, print_raw=print_raw,
            attrs=attrs, file=sys.stderr
        )
        return
    
    def error(
            self,
            tag: str = None,
            msg: str = None,
            color: str = "red",
            on_color: str = None,
            print_raw: bool = False,
            attrs: List[str] = []
        ) -> None:
        """
        This method prints a tagged message of log level error to the console or Binary Ninja's log.
        """
        text = self._tag_msg(tag, msg)
        if self._level > 3: return
        if not self._runs_headless:
            log_error(text, "Plugin.Mole")
        self._print(
            "ERRO", text,
            color=color, on_color=on_color, print_raw=print_raw,
            attrs=attrs, file=sys.stderr
        )   
        return