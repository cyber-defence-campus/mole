import argparse
import binaryninja    as bn
from   .analysis      import libc
from   .common.log    import Logger


log = Logger("debug")


class Plugin:
    """
    This class registers the plugin with Binary Ninja.
    """

    @staticmethod
    def register(
        ) -> None:
        """
        """
        bn.PluginCommand.register(
            "Mole\\Analyze Binary",
            "Search the entire binary for potential vulnerabilities",
            Plugin.analyze_binary)
        return
    
    @staticmethod
    def analyze_binary(
        bv: bn.BinaryView
        ) -> None:
        """
        """
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

        sources = [
            # Environment
            libc.getenv(bv, log),               # Read environment variable
            # Streams, Files and Directories
            libc.fgets(bv, log),                # Read string from given stream
            # Network
        ]
        
        libc.sscanf(bv, log).find(sources)
        libc.memcpy(bv, log).find(sources)
        return
    

def main(
    ) -> None:
    """
    This method processes a give binary in headless mode.
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
    args = parser.parse_args()
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