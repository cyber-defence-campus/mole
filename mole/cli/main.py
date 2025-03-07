from __future__           import annotations
from mole.common.log      import Logger
from mole.models.config   import ConfigModel
from mole.services.config import ConfigService
from mole.services.slicer import MediumLevelILBackwardSlicerThread
from typing               import Dict, List
import argparse    as ap
import binaryninja as bn
import hashlib     as hl
import json        as json
import yaml        as yaml


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
        "--max_workers",
        type=int, default=None,
        help="maximum number of worker threads that backward slicing uses"
    )
    parser.add_argument(
        "--max_call_level",
        type=int, default=None,
        help="backward slicing visits called functions up to the given level"
    )
    parser.add_argument(
        "--max_slice_depth",
        type=int, default=None,
        help="maximum slice depth to stop the search"
    )
    parser.add_argument(
        "--export_paths_to_json_file",
        help="export identified paths in JSON format"
    )
    parser.add_argument(
        "--export_paths_to_yml_file",
        help="export identified paths in YAML format"
    )
    args = parser.parse_args()

    # Initialize logger to operate in headless mode
    tag = "Mole"
    log = Logger(level=args.log_level, runs_headless=True)
    try:
        # Load and analyze binary with Binary Ninja
        bv = bn.load(args.file)
        bv.update_analysis_and_wait()
        # Analyze binary with Mole
        slicer = MediumLevelILBackwardSlicerThread(
            bv=bv,
            model=ConfigModel(ConfigService(f"{tag:s}.ConfigService", log).load_configuration()),
            tag=f"{tag:s}.Slicer",
            log=log,
            max_workers=args.max_workers,
            max_call_level=args.max_call_level,
            max_slice_depth=args.max_slice_depth
        )
        slicer.start()
        paths = slicer.get_paths()
        # Export identified paths
        if args.export_paths_to_yml_file or args.export_paths_to_json_file:
            # Calculate SHA1 hash of binary
            sha1_hash = hl.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
            # Serialize paths
            s_paths: List[Dict] = []
            for path in paths:
                s_path = path.to_dict()
                s_path["comment"] = ""
                s_path["sha1"] = sha1_hash
                s_paths.append(s_path)
            # Write JSON data (default)
            if args.export_paths_to_json_file:
                with open(args.export_paths_to_json_file, "w") as f:
                    json.dump(
                        s_paths,
                        f,
                        indent=2
                    )
            # Write YAML data
            if args.export_paths_to_yml_file:
                with open(args.export_paths_to_yml_file, "w") as f:
                    yaml.safe_dump(
                        s_paths,
                        f,
                        sort_keys=False,
                        default_style=None,
                        default_flow_style=False,
                        encoding="utf-8"
                    )
        # Close binary
        bv.file.close()
    except KeyboardInterrupt:
        log.info(msg="Keyboard interrupt caught")
    except Exception as e:
        log.error(msg=f"Exception caught: '{str(e):s}'")
    return


if __name__ == "__main__":
    main()