from __future__ import annotations
from tests.slicing.conftest import TestSlicing
from typing import List
import binaryninja as bn


class TestMultiThreading(TestSlicing):
    def test_consistency_01(
        self,
        filenames: List[str] = [
            "function_calling-02",
            "name_mangling-01",
            "load-05",
            "pointer_analysis-06",
            "simple_http_server-03",
            "memcpy-05",
        ],
    ) -> None:
        for file in self.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Assert results
            paths = self.get_paths(bv, max_workers=1, enable_all_funs=True)
            for max_workers in [2, 4, 8, -1]:
                paths_mt = self.get_paths(bv, max_workers, enable_all_funs=True)
                for path in paths:
                    if path in paths_mt:
                        paths_mt.remove(path)
                    else:
                        assert False, (
                            f"Inconsistent results with {max_workers:d} workers"
                        )
                assert not paths_mt, (
                    f"Inconsistent results with {max_workers:d} workers"
                )
            # Close binary
            bv.file.close()
        return
