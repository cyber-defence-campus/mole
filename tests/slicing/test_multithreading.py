from __future__ import annotations
from tests.slicing.conftest import TestSlicing
from typing import List
import binaryninja as bn


class TestMultiThreading(TestSlicing):
    def test_consistency_01(
        self, filenames: List[str] = ["function_calling-02"]
    ) -> None:
        for file in self.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Assert results
            paths = self.get_paths(bv, max_workers=1)
            for max_workers in [2, 4, 8, -1]:
                paths_mt = self.get_paths(bv, max_workers)
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

    def test_consistency_02(self, filenames: List[str] = ["name_mangling-01"]) -> None:
        self.test_consistency_01(filenames)
        return

    def test_consistency_03(self, filenames: List[str] = ["load-05"]) -> None:
        self.test_consistency_01(filenames)
        return

    def test_consistency_04(
        self, filenames: List[str] = ["pointer_analysis-06"]
    ) -> None:
        self.test_consistency_01(filenames)
        return

    def test_consistency_05(
        self, filenames: List[str] = ["simple_http_server-03"]
    ) -> None:
        self.test_consistency_01(filenames)
        return

    def test_consistency_06(self, filenames: List[str] = ["memcpy-05"]) -> None:
        self.test_consistency_01(filenames)
        return
