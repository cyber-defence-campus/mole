from __future__ import annotations
from tests.slicing import TestSlicing
from typing import List
import binaryninja as bn


class TestMultiThreading(TestSlicing):
    def test_consistency_01(
        self,
        filenames: List[str] = [
            "fread-01",
            "function_calling-01",
            "function_calling-02",
            "function_calling-03",
            "function_calling-04",
            "function_calling-05",
            "function_calling-06",
            "function_calling-07",
            "function_calling-08",
            "function_calling-09",
            "function_calling-10",
            "function_calling-11",
            "function_calling-12",
            "function_calling-13",
            "function_calling-14",
            "function_calling-15",
            "gets-01",
            "gets-02",
            "memcpy-01",
            "memcpy-02",
            "memcpy-03",
            "memcpy-04",
            "memcpy-05",
            "memcpy-06",
            "memcpy-07",
            "memcpy-08",
            "memcpy-09",
            "memcpy-10",
            "memcpy-11",
            "name_mangling-01",
            "name_mangling-02",
            "name_mangling-03",
            "name_mangling-04",
            "name_mangling-05",
            "name_mangling-06",
            "pointer_analysis-01",
            "pointer_analysis-02",
            "pointer_analysis-03",
            "pointer_analysis-04",
            "pointer_analysis-05",
            "pointer_analysis-06",
            "pointer_analysis-07",
            "pointer_analysis-08",
            "pointer_analysis-09",
            "pointer_analysis-10",
            "pointer_analysis-11",
            "pointer_analysis-12",
            "pointer_analysis-13",
            "pointer_analysis-14",
            "pointer_analysis-15",
            "simple_http_server-01",
            "simple_http_server-02",
            "simple_http_server-03",
            "simple_http_server-04",
            "sscanf-01",
            "struct-01",
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
