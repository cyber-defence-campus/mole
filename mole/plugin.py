from __future__       import annotations
from typing           import List, Tuple
from .analysis.thread import MediumLevelILBackwardSlicerThread
from .common.log      import Logger
from .model           import libapr, libc, libgio
from .ui.config       import ConfigModel, ConfigView, ConfigController
import argparse
import binaryninja as bn


class Plugin:
    """
    This class registers the plugin with Binary Ninja or runs it in headless mode.
    """

    def __init__(
            self,
            runs_headless: bool = False,
            tag: str = None,
            log: Logger = Logger()
        ) -> None:
        self._runs_headless = runs_headless
        self._tag = tag
        self._log = log
        self._src_funs = [
            # Environment
            libc.getenv(log=self._log),             # Read environment variable
            # Stream, File and Directory
            libc.fgetc(log=self._log),              # Read character from given stream
            libc.getc(log=self._log),               # Read character from given stream
            libc.getchar(log=self._log),            # Read character from standard input stream
            libc.fgets(log=self._log),              # Read string from given stream
            libc.gets(log=self._log),               # Read string from standard input stream
            libc.scanf(log=self._log),              # Read formatted input from standard input stream
            libc.vscanf(log=self._log),             # Read formatted input from standard input stream
            libc.fscanf(log=self._log),             # Read formatted input from given stream
            libc.vfscanf(log=self._log),            # Read formatted input from given stream
            # "fopen", "__builtin_fopen",          # Open file
            # "fdopen", "__builtin_fdopen",        # Open file
            # "freopen", "__builtin_freopen",      # Open file
            # "opendir", "__builtin_opendir",      # Open directory
            # "fdopendir", "__builtin_fdopendir",  # Open directory
            # Network
            libgio.g_socket_receive(log=self._log),
            libapr.apr_socket_recv(log=self._log)
            # "recv", "__builtin_recv",            # Receive message from socket
            # "recvfrom", "__builtin_recvfrom",    # Receive message from socket
            # "recvmsg", "__builtin_recvmsg",      # Receive message from socket
        ]
        self._snk_funs = [
            # Stream, File and Directory
            libc.gets(log=self._log),
            # Memory
            libc.memcpy(log=self._log),
            libc.memmove(log=self._log),
            # String
            libc.strcpy(log=self._log),
            libc.wcscpy(log=self._log),
            libc.strcat(log=self._log),
            libc.strncpy(log=self._log),
            libc.sscanf(log=self._log),
            libc.vsscanf(log=self._log)
        ]
        return
    
    def register(self) -> None:
        """
        This method registers plugin commands with Binary Ninja.
        """
        bn.PluginCommand.register(
            "Mole\\1. Configure...",
           "Configure the Mole plugin",
            self.configure
        )
        bn.PluginCommand.register(
            "Mole\\2. Analyze Binary...",
            "Search the entire binary for potential vulnerabilities",
            self.analyze_binary
        )
        return
    
    def configure(self, bv: bn.BinaryView) -> None:
        """
        This method allows to configure the plugin.
        """
        controller = ConfigController(
            model=ConfigModel(),
            view=ConfigView(self._runs_headless),
            src_funs=self._src_funs,
            snk_funs=self._snk_funs,
            log=self._log
        )
        controller.init()
        controller.show_view()
        return
    
    def analyze_binary(
            self,
            bv: bn.BinaryView,
            max_func_depth: int = None,
            enable_all_funs: bool = False
        ) -> None | List[Tuple[
            str, bn.MediumLevelILInstruction,
            str, bn.MediumLevelILInstruction,
            int, bn.SSAVariable
        ]]:
        """
        This method analyzes the entire binary for interesting looking code paths.
        """
        controller = ConfigController(
            model=ConfigModel(),
            view=ConfigView(self._runs_headless),
            src_funs=self._src_funs,
            snk_funs=self._snk_funs,
            log=self._log
        )
        controller.init()
        thread = MediumLevelILBackwardSlicerThread(
            bv=bv,
            controller=controller,
            runs_headless=self._runs_headless,
            max_func_depth=max_func_depth,
            enable_all_funs=enable_all_funs,
            log=self._log
        )
        thread.start()
        if self._runs_headless:
            return thread.get_paths()
        return None

def main() -> None:
    """
    This function is used to process a given binary in headless mode.
    """
    # Parse arguments
    description = """
    Mole is a plugin for Binary Ninja that tries to identify interesting code paths using static
    backward slicing. The plugin can be run both in Binary Ninja and in headless mode.
    """
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        "file",
        help="file to analyze")
    parser.add_argument(
        "--log_level",
        choices=["error", "warning", "info", "debug"], default="info",
        help="log level")
    parser.add_argument(
        "--max_func_depth",
        type=int, default=None,
        help="backward slicing visits called functions up to the given depth"
    )
    args = parser.parse_args()

    # Initialize logger and plugin to operate in headless mode
    log = Logger(level=args.log_level, runs_headless=True)
    plugin = Plugin(runs_headless=True, log=log)

    try:
        # Load and analyze binary with Binary Ninja
        bv = bn.load(args.file)
        bv.update_analysis_and_wait()

        # Analyze binary with plugin
        plugin.analyze_binary(bv, args.max_func_depth)

        # Close binary
        bv.file.close()
    except KeyboardInterrupt:
        log.info(msg="Keyboard interrupt caught")
    except Exception as e:
        log.error(msg=f"Failed to analyze binary '{args.file:s}': {str(e):s}")
    return


if __name__ == "__main__":
    main()