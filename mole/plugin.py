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
            # Environment Access
            libc.getenv(self._log),                 # Read environment variable
            libc.secure_getenv(self._log),          # Read environment variable
            # Character Input
            libc.fgetc(self._log),                  # Read character from given stream
            libc.fgetwc(self._log),                 # Read character from given stream
            libc.fgetc_unlocked(self._log),         # Read character from given stream
            libc.fgetwc_unlocked(self._log),        # Read character from given stream
            libc.getc(self._log),                   # Read character from given stream
            libc.getwc(self._log),                  # Read character from given stream
            libc.getc_unlocked(self._log),          # Read character from given stream
            libc.getwc_unlocked(self._log),         # Read character from given stream
            libc.getchar(self._log),                # Read character from standard input stream
            libc.getwchar(self._log),               # Read character from standard input stream
            libc.getchar_unlocked(self._log),       # Read character from standard input stream
            libc.getwchar_unlocked(self._log),      # Read character from standard input stream
            libc.getw(self._log),                   # Read word from given stream
            # Line Input
            libc.getline(self._log),                # Read line from given stream
            libc.getdelim(self._log),               # Read line from given stream
            libc.fgets(self._log),                  # Read string from given stream
            libc.fgetws(self._log),                 # Read string from given stream
            libc.fgets_unlocked(self._log),         # Read string from given stream
            libc.fgetws_unlocked(self._log),        # Read string from given stream
            libc.gets(self._log),                   # Read string from standard input stream
            # Formatted Inputs
            libc.scanf(self._log),                  # Read formatted input from standard input stream
            libc.wscanf(self._log),                 # Read formatted input from standard input stream
            libc.fscanf(self._log),                 # Read formatted input from given stream
            libc.fwscanf(self._log),                # Read formatted input from given stream
            libc.vscanf(self._log),                 # Read formatted input from standard input stream
            libc.vfscanf(self._log),                # Read formatted input from given stream
            # Opening Streams
            libc.fopen(self._log),                  # Open file
            libc.freopen(self._log),                # Open file
            # Descriptors and Streams
            libc.fdopen(self._log),                 # Open file
            # Opening a Directory
            libc.opendir(self._log),                # Open directory
            libc.fdopendir(self._log),              # Open directory
            # Network
            libc.recv(self._log),                   # Receive message from socket
            libc.recvfrom(self._log),               # Receive message from socket
            libc.recvmsg(self._log),                # Receive message from socket
            libgio.g_socket_receive(self._log),     # Read bytes from socket
            libapr.apr_socket_recv(self._log)       # Read bytes from socket
        ]
        self._snk_funs = [
            # Memory
            libc.memcpy(self._log),                 # Copy memory area
            libc.wmemcpy(self._log),                # Copy memory area
            libc.memmove(self._log),                # Copy memory area
            # String Copy
            libc.strcpy(self._log),                 # Copy string
            libc.stpcpy(self._log),                 # Copy string
            libc.wcscpy(self._log),                 # Copy string
            libc.wcsncpy(self._log),                # Copy string
            libc.strncpy(self._log),                # Fill buffer with bytes from string
            libapr.apr_cpystrn(self._log),          # Fill buffer with bytes from string
            # String Concatenation
            libc.strcat(self._log),                 # Concatenate string
            libc.strncat(self._log),                # Concatenate string
            libc.wcscat(self._log),                 # Truncate string
            libc.wcsncat(self._log),                # Truncate string
            # String Format Conversion
            libc.sscanf(self._log),                 # Format string
            libc.swscanf(self._log),                # Format string
            libc.vsscanf(self._log),                # Format string
            libc.sprintf(self._log),                # Print formatted output
            libc.swprintf(self._log),               # Print formatted output
            libc.vsprintf(self._log),               # Print formatted output
            libc.vswprintf(self._log),              # Print formatted output
            # Line Input
            libc.gets(self._log),                   # Read string from standard input stream
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