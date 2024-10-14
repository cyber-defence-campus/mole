from __future__    import annotations
from   typing      import List, Tuple
from   .analysis   import libapr, libc, libgio
from   .common.log import Logger
from   .ui.config  import ConfigModel, ConfigView, ConfigController
import argparse
import binaryninja as bn


class Plugin:
    """
    This class registers the plugin with Binary Ninja or runs it in headless mode.
    """

    def __init__(
            self,
            runs_headless: bool,
            tag: str = None,
            log: Logger = Logger()
        ) -> None:
        self._runs_headless = runs_headless
        self._src_funs = None
        self._snk_funs = None
        self._tag = tag
        self._log = log
        return
    
    def init_controller(self, bv: bn.BinaryView) -> ConfigController:
        """
        This method initializes a plugin controller.
        """
        # Initialize source functions
        if self._src_funs is None:
            self._src_funs = [
                # Environment
                libc.getenv(bv=bv, log=self._log),
                # Stream, File and Directory
                libc.gets(bv=bv, log=self._log),
                libc.fgets(bv=bv, log=self._log),
                # Network
                libgio.g_socket_receive(bv=bv, log=self._log),
                libapr.apr_socket_recv(bv=bv, log=self._log)
            ]
        # Initialize sink functions
        if self._snk_funs is None:
            self._snk_funs = [
                # Stream, File and Directory
                libc.gets(bv=bv, log=self._log),
                # Memory
                libc.memcpy(bv=bv, log=self._log),
                libc.memmove(bv=bv, log=self._log),
                # String
                libc.strcpy(bv=bv, log=self._log),
                libc.wcscpy(bv=bv, log=self._log),
                libc.strcat(bv=bv, log=self._log),
                libc.strncpy(bv=bv, log=self._log),
                libc.sscanf(bv=bv, log=self._log),
                libc.vsscanf(bv=bv, log=self._log)
            ]
        # Initialize controller
        controller = ConfigController(
            model=ConfigModel(),
            view=ConfigView(self._runs_headless),
            src_funs=self._src_funs,
            snk_funs=self._snk_funs,
            log=self._log
        )
        controller.init()
        return controller
    
    def register(self) -> None:
        """
        This method registers plugin commands with Binary Ninja.
        """
        bn.PluginCommand.register(
            "Mole\\Configure...",
            "Configure the Mole plugin",
            self.configure
        )
        bn.PluginCommand.register(
            "Mole\\Analyze Binary...",
            "Search the entire binary for potential vulnerabilities",
            self.analyze_binary)
        return
    
    def configure(self, bv: bn.BinaryView) -> None:
        """
        This method configures the plugin.
        """
        controller = self.init_controller(bv)
        controller.show_view()
        return
    
    def analyze_binary(
            self,
            bv: bn.BinaryView,
            enable_all_funs: bool = False,
            max_func_depth: int = None
        ) -> List[Tuple[
            str, bn.MediumLevelILInstruction,
            str, bn.MediumLevelILInstruction, int, bn.SSAVariable
        ]]:
        """
        This method analyzes the entire binary.
        """
        paths = []
        controller = self.init_controller(bv)

        # src_sym_names = [
        #     # Environment
        #     "getenv", "__builtin_getenv",        # Read environment variable
        #     # Streams, Files and Directories
        #     "getchar", "__builtin_getchar"        # Read character from standard input stream
        #     "getc", "__builtin_getc",            # Read character from given sream
        #     "fgetc", "__builtin_fgetc",            # Read character from given stream
        #     "gets", "__builtin_gets",            # Read string from standard input stream
        #     "fgets", "__builtin_fgets",            # Read string from given stream
        #     "scanf", "__builtin_scanf",            # Read input from standard input stream
        #     "fscanf", "__builtin_fscanf",        # Read input from given stream
        #     "vscanf", "__builtin_vscanf",        # Read input from standard input stream
        #     "vfscanf", "__builtin_vfscanf",        # Read input from given stream
        #     "fopen", "__builtin_fopen",            # Open file
        #     "fdopen", "__builtin_fdopen",        # Open file
        #     "freopen", "__builtin_freopen",        # Open file
        #     "opendir", "__builtin_opendir",        # Open directory
        #     "fdopendir", "__builtin_fdopendir",    # Open directory
        #     # Network
        #     "recv", "__builtin_recv",            # Receive message from socket
        #     "recvfrom", "__builtin_recvfrom",    # Receive message from socket
        #     "recvmsg", "__builtin_recvmsg",        # Receive message from socket
        # ]
        # libc.memcpy(bv, log=log, src_sym_names=src_sym_names).analyze_all()
        # libc.sscanf(bv, log=log, src_sym_names=src_sym_names).analyze_all()

        # Source functions
        if enable_all_funs:
            src_funs = controller.get_all_funs(flowtype="Sources")
        else:
            src_funs = controller.get_enabled_funs(flowtype="Sources")
        if not src_funs:
            self._log.warn(self._tag, "No configured source functions")

        # Sink functions
        if enable_all_funs:
            snk_funs = controller.get_all_funs(flowtype="Sinks")
        else:
            snk_funs = controller.get_enabled_funs(flowtype="Sinks")
        if not snk_funs:
            self._log.warn(self._tag, "No configured sink functions")
        
        # Find paths
        if max_func_depth is None:
            max_func_depth = controller.get_max_func_depth()
        if src_funs and snk_funs:
            for snk_fun in snk_funs:
                paths.extend(snk_fun.find(src_funs, max_func_depth))

        return paths


def main() -> None:
    """
    This function processes a given binary in headless mode.
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
        help="backward slicing visits called functions up to the given depth (default: 5)"
    )
    args = parser.parse_args()

    # Initialize plugin and logger to operate in headless mode
    log = Logger(level=args.log_level, runs_headless=True)
    plugin = Plugin(
        runs_headless=True,
        log=log
    )

    try:
        # Load and analyze binary with Binary Ninja
        bv = bn.load(args.file)
        bv.update_analysis_and_wait()

        # Analyze binary with plugin
        plugin.analyze_binary(bv, max_func_depth=args.max_func_depth)

        # Close binary
        bv.file.close()
    except:
        log.error(msg=f"Failed to analze binary '{args.file:s}'")
    return


if __name__ == "__main__":
    main()