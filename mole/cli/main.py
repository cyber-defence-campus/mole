from __future__ import annotations
from mole.common.log import Logger
from mole.models.config import ConfigModel
from mole.models.path import Path
from mole.services.config import ConfigService
from mole.services.path import PathService
from typing import Dict, List
import argparse as ap
import binaryninja as bn
import json
import math
import os
import time


def main() -> None:
    """
    This function is used to process a given binary in headless mode.
    """
    # Parse arguments
    description = """
    Mole is a Binary Ninja plugin designed to identify interesting paths in binaries. It performs
    static backward slicing on variables using BN's MLIL in its SSA form. The plugin can be run
    either in BN's UI or in headless mode.
    """
    parser = ap.ArgumentParser(
        description=description, formatter_class=ap.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("file", help="file to analyze")
    parser.add_argument("--config_file", help="custom configuration file to use")
    parser.add_argument(
        "--log_level",
        choices=["error", "warning", "info", "debug", "none"],
        default="debug",
        help="log level",
    )
    parser.add_argument(
        "--max_workers",
        type=int,
        default=None,
        help="maximum number of worker threads that backward slicing uses",
    )
    parser.add_argument(
        "--fix_func_type",
        action="store_true",
        help="whether to fix function types during analysis",
    )
    parser.add_argument(
        "--max_call_level",
        type=int,
        default=None,
        help="backward slicing visits called functions up to the given level",
    )
    parser.add_argument(
        "--max_slice_depth",
        type=int,
        default=None,
        help="maximum slice depth to stop the search",
    )
    parser.add_argument(
        "--max_memory_slice_depth",
        type=int,
        default=None,
        help="maximum memory slice depth to stop the search",
    )
    parser.add_argument(
        "--export_paths", help="export identified paths in NDJSON format"
    )
    parser.add_argument(
        "--save_bndb", help="save BN database file with analysis results"
    )
    args = vars(parser.parse_args())
    # Time before analysis
    start_time = time.time()
    # Load and analyze binary with Binary Ninja
    try:
        bv = bn.load(args["file"])
        bv.update_analysis_and_wait()
    except Exception:
        bv = None
    if bv is None:
        print(f"Failed to load binary '{args['file']:s}'.")
        return
    # Initialize logger
    log = Logger(bv, args["log_level"])
    # File handle for exporting paths
    export_file = None
    # Analyze binary with Mole
    try:
        # Open file for exporting paths
        if args["export_paths"]:
            export_file = open(
                os.path.abspath(
                    os.path.expanduser(os.path.expandvars(args["export_paths"]))
                ),
                "a",
                buffering=1,
            )
        # Serialized paths
        s_paths: List[Dict] = []

        # Serialize and export paths
        def serialize_and_export_paths(paths: List[Path]) -> None:
            for path in paths:
                # Serialize path
                s_path = path.to_dict()
                # Store serialized path
                s_paths.append(s_path)
                # Write NDJSON data
                if export_file is not None:
                    json.dump(s_path, export_file)
                    export_file.write("\n")
            return

        # Find paths
        config_model = ConfigModel(
            ConfigService(log, args["config_file"]).load_config()
        )
        path_service = PathService(bv, log, config_model)
        path_service.find_paths(
            max_workers=args["max_workers"],
            fix_func_type=args["fix_func_type"],
            max_call_level=args["max_call_level"],
            max_slice_depth=args["max_slice_depth"],
            max_memory_slice_depth=args["max_memory_slice_depth"],
            path_callback=serialize_and_export_paths
            if args["export_paths"] or args["save_bndb"]
            else lambda _: None,
        )
        paths = path_service.get_paths()
        # Write Binary Ninja database
        if args["save_bndb"]:
            bv.store_metadata("mole_paths", json.dumps(s_paths))
            fp = args["save_bndb"]
            fp = os.path.abspath(os.path.expanduser(os.path.expandvars(fp)))
            bv.create_database(fp)
        # Time after analysis
        end_time = time.time()
        # Calculate path statistics
        paths_stats: Dict[str, Dict[str, int]] = {}
        for path in paths:
            paths_stats[path.src_sym_name][path.snk_sym_name] = (
                paths_stats.setdefault(path.src_sym_name, {}).setdefault(
                    path.snk_sym_name, 0
                )
                + 1
            )
        sources: Dict[str, List[str]] = {}
        for lib_name in config_model.get_libraries("Sources").keys():
            src_funcs = [
                func.name
                for func in config_model.get_functions(
                    lib_name=lib_name, fun_type="Sources", fun_enabled=True
                )
            ]
            if src_funcs:
                sources.setdefault(lib_name, []).extend(src_funcs)
        sinks: Dict[str, List[str]] = {}
        for lib_name in config_model.get_libraries("Sinks").keys():
            snk_funcs = [
                func.name
                for func in config_model.get_functions(
                    lib_name=lib_name, fun_type="Sinks", fun_enabled=True
                )
            ]
            if snk_funcs:
                sinks.setdefault(lib_name, []).extend(snk_funcs)
        propagators: Dict[str, List[str]] = {}
        if args["fix_func_type"]:
            for lib_name in config_model.get_libraries("Propagators").keys():
                prp_funcs = [
                    func.name
                    for func in config_model.get_functions(
                        lib_name=lib_name, fun_type="Propagators"
                    )
                ]
                if prp_funcs:
                    propagators.setdefault(lib_name, []).extend(prp_funcs)
        # Output summary of results in machine-readable format
        print(
            json.dumps(
                {
                    "analysis_time_seconds": math.trunc((end_time - start_time) * 1000)
                    / 1000,
                    "paths_total": len(paths),
                    "paths_stats": paths_stats,
                    "sources": sources,
                    "sinks": sinks,
                    "propagators": propagators,
                },
                indent=2,
            )
        )
        # Close binary
        bv.file.close()
    except KeyboardInterrupt:
        log.info(msg="Keyboard interrupt caught")
    except Exception as e:
        log.error(msg=f"Exception caught: '{str(e):s}'")
    finally:
        # Close export file
        if export_file is not None:
            export_file.close()
    return


if __name__ == "__main__":
    main()
