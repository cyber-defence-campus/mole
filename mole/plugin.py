import argparse
import binaryninja    as bn
from   typing         import List, Tuple
from   .analysis      import libapr, libc, libgio
from   .common.log    import Logger
from   .ui.config     import ConfigModel, ConfigView, ConfigController


log = Logger("debug")


class Plugin:
    """
    This class registers the plugin with Binary Ninja.
    """

    max_recursion = 10
    conf_controller = ConfigController(ConfigModel(), ConfigView())

    @staticmethod
    def register(
        ) -> None:
        """
        """
        bn.PluginCommand.register(
            "Mole\\Configure...",
            "Configure the Mole plugin",
            Plugin.configure
        )
        bn.PluginCommand.register(
            "Mole\\Analyze Binary...",
            "Search the entire binary for potential vulnerabilities",
            Plugin.analyze_binary)
        return
    
    @staticmethod
    def configure(
        bv: bn.BinaryView
        ) -> None:
        """
        Configure the plugin.
        """
        Plugin.conf_controller.show_view()
        return
    
    @staticmethod
    def analyze_binary(
        bv: bn.BinaryView
        ) -> List[Tuple[
                str, bn.MediumLevelILInstruction,
                str, bn.MediumLevelILInstruction, int, bn.SSAVariable
            ]]:
        """
        Analyze the whole binary.
        """
        paths = []
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

        # Sources
        sources = []
        # Sources: Environment
        env = Plugin.conf_controller.read().get("Sources", {}).get("Environment", {})
        if env.get("libc.getenv", {}).get("checked", False):
            sources.append(libc.getenv(bv=bv, log=log))
        # Sources: Stream, File and Directory
        sfd = Plugin.conf_controller.read().get("Sources", {}).get("Stream, File and Directory", {})
        if sfd.get("libc.fgets", {}).get("checked", False):
            sources.append(libc.fgets(bv=bv, log=log))
        if sfd.get("libc.gets", {}).get("checked", False):
            sources.append(libc.gets(bv=bv, log=log))
        # Sources: Network
        net = Plugin.conf_controller.read().get("Sources", {}).get("Network", {})
        if net.get("libgio.g_socket_receive", {}).get("checked", False):
            sources.append(libgio.g_socket_receive(bv=bv, log=log))
        if net.get("libapr.apr_socket_recv", {}).get("checked", False):
            sources.append(libapr.apr_socket_recv(bv=bv, log=log))
        if not sources:
            log.warn(None, f"No sources configured")
            return paths

        # Sinks
        paths.extend(libc.gets(bv=bv, log=log).find(sources, Plugin.max_recursion))
        paths.extend(libc.memcpy(bv=bv, log=log).find(sources, Plugin.max_recursion))
        paths.extend(libc.memmove(bv=bv, log=log).find(sources, Plugin.max_recursion))
        paths.extend(libc.strcpy(bv=bv, log=log).find(sources, Plugin.max_recursion))
        paths.extend(libc.strcat(bv=bv, log=log).find(sources, Plugin.max_recursion))
        paths.extend(libc.strncpy(bv=bv, log=log).find(sources, Plugin.max_recursion))
        paths.extend(libc.sscanf(bv=bv, log=log).find(sources, Plugin.max_recursion))
        paths.extend(libc.vsscanf(bv=bv, log=log).find(sources, Plugin.max_recursion))
        paths.extend(libc.wcscpy(bv=bv, log=log).find(sources, Plugin.max_recursion))
        return paths
    

def main(
    ) -> None:
    """
    This method processes a given binary in headless mode.
    """
    # Parse arguments
    description = """
    TODO: Provide a description
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
        "--max_recursion",
        type=int, default=Plugin.max_recursion,
        help="Backward slicing visits called functions up to the given recursion depth"
    )
    args = parser.parse_args()
    Plugin.max_recursion = args.max_recursion
    # Create logger
    global log
    log = Logger(args.log_level, runs_headless=True)
    # Analyze binary
    bv = bn.load(args.file)
    bv.update_analysis_and_wait()
    Plugin.analyze_binary(bv)
    bv.file.close()
    return


if __name__ == "__main__":
    main()