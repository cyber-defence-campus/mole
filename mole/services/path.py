from mole.common.log import log
from mole.core.data  import Path
from typing          import Callable
import binaryninja as bn
import hashlib
import ijson


tag = "Mole.Path"


class PathImporterThread(bn.BackgroundTaskThread):
    """
    This class implements a background thread that imports paths.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            filepath: str,
            path_callback: Callable[[Path, str], None] = None,
        ) -> None:
        """
        This method initializes the background task.
        """
        super().__init__(initial_progress_text="Import paths...", can_cancel=True)
        self._bv = bv
        self._filepath = filepath
        self._path_callback = path_callback
        return
    
    def run(self) -> None:
        """
        This method implements the background task's functionality, i.e. it imports paths from a
        given file.
        """
        # Calculate SHA1 hash
        sha1_hash = hashlib.sha1(self._bv.file.raw.read(0, self._bv.file.raw.end)).hexdigest()
        # Import paths
        cnt_imported_paths = 0
        try:
            # Count the total number of paths to be imported
            cnt_total_paths = 0
            with open(self._filepath, "r") as f:
                for _ in ijson.items(f, "item"):
                    cnt_total_paths += 1
            # Iteratively import paths from the JSON file
            with open(self._filepath, "r") as f:
                for path_idx, s_path in enumerate(ijson.items(f, "item")):
                    try:
                        # Cancel task
                        if self.cancelled:
                            break
                        # Compare SHA1 hashes
                        if s_path["sha1"] != sha1_hash:
                            log.warn(tag, f"Path #{path_idx+1:d} seems to origin from another binary")
                        # Deserialize path
                        path = Path.from_dict(self._bv, s_path)
                        # Execute callback function
                        self._path_callback(path, s_path["comment"])
                        # Increment imported path counter
                        cnt_imported_paths += 1
                    except Exception as e:
                        log.error(tag, f"Failed to import path #{path_idx+1:d}: {str(e):s}")
                    finally:
                        self.progress = f"Paths imported: {path_idx+1:d}/{cnt_total_paths:d}"
        except Exception as e:
            log.error(tag, f"Failed to import paths: {str(e):s}")
        log.info(tag, f"Imported {cnt_imported_paths:d} path(s)")
        return