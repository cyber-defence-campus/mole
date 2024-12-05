from __future__       import annotations
from .common.log      import Logger
from .core.controller import Controller
import argparse    as ap
import binaryninja as bn


def main() -> None:
    """
    This function is used to process a given binary in headless mode.
    """
    # Parse arguments
    description = """
    Mole is a Binary Ninja plugin that tries to identify interesting code paths using static
    backward slicing. The plugin can be run both in Binary Ninja and in headless mode.
    """
    parser = ap.ArgumentParser(
        description=description,
        formatter_class=ap.ArgumentDefaultsHelpFormatter)
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

    # Initialize logger and controller to operate in headless mode
    log = Logger(level=args.log_level, runs_headless=True)
    ctr = Controller(runs_headless=True, log=log).init()
    try:
        # Load and analyze binary with Binary Ninja
        bv = bn.load(args.file)
        bv.update_analysis_and_wait()
        # Analyze binary with Mole
        ctr.analyze_binary(bv, args.max_func_depth)
        # Close binary
        bv.file.close()
    except KeyboardInterrupt:
        log.info(msg="Keyboard interrupt caught")
    except Exception as e:
        log.error(msg=f"Exception caught: '{str(e):s}'")
    return


if __name__ == "__main__":
    main()