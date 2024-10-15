import sys
from   binaryninja  import log_alert, log_debug, log_info, log_warn, log_error
from   datetime     import datetime
from   termcolor    import colored
from   typing       import List, Literal


class Logger:
    """
    This class prints messages to the console or Binary Ninja's log.
    """

    def __init__(
            self,
            level: Literal["debug", "info", "warning", "error"] = "info",
            runs_headless: bool = False
        ) -> None:
        self._set_level(level)
        self._runs_headless = runs_headless
        return
    
    def _set_level(
            self,
            level: Literal["debug", "info", "warning", "error"]
        ) -> None:
        """
        This method sets the log level to `level`.
        """
        level = level.lower()
        match level:
            case "debug":
                self._level = 0
            case "info":
                self._level = 1
            case "warning":
                self._level = 2
            case "error":
                self._level = 3
            case _:
                self._level = 4

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
        print(colored(f"{head:s}{msg:s}", color=color, on_color=on_color, attrs=attrs), file=file)
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
        if self._runs_headless:
            if self._level <= 0:
                self._print(
                    "DEBG", text,
                    color=color, on_color=on_color, print_raw=print_raw,
                    attrs=attrs, file=sys.stdout)
        else:
            log_debug(text, "Plugin.Mole")
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
        if self._runs_headless:
            if self._level <= 1:
                self._print(
                    "INFO", text,
                    color=color, on_color=on_color, print_raw=print_raw,
                    attrs=attrs, file=sys.stdout)
        else:
            log_info(text, "Plugin.Mole")
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
        if self._runs_headless:
            if self._level <= 2:
                self._print(
                    "WARN", text,
                    color=color, on_color=on_color, print_raw=print_raw,
                    attrs=attrs, file=sys.stderr)
        else:
            log_warn(text, "Plugin.Mole")
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
        if self._runs_headless:        
            if self._level <= 3:
                self._print(
                    "ERRO", text,
                    color=color, on_color=on_color, print_raw=print_raw,
                    attrs=attrs, file=sys.stderr)
        else:
            log_error(text, "Plugin.Mole")
        return