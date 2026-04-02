from __future__ import annotations
from mole.common.log import Logger
from mole.models.config import ConfigModel
from mole.services.config import ConfigService
from mole.services.path import PathService
from tests.slicing.conftest import TestSlicing
from typing import List
import binaryninja as bn


class TestMultiThreading(TestSlicing):
    def test_consistency_01(
        self, filenames: List[str] = ["function_calling-02"]
    ) -> None:
        # Logger
        log = Logger()
        # Configuration model
        model = ConfigModel(ConfigService(log).import_config(self._config_file))
        for file in self.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Find paths in test binary
            path_service = PathService(bv, log, model)
            path_service.find_paths(
                max_workers=1,
                max_call_level=5,
                max_slice_depth=-1,
                max_memory_slice_depth=-1,
            )
            paths = path_service.get_paths()
            for max_workers in [2, 4, 8, -1]:
                path_service_mt = PathService(bv, log, model)
                path_service_mt.find_paths(
                    max_workers=max_workers,
                    max_call_level=5,
                    max_slice_depth=-1,
                    max_memory_slice_depth=-1,
                )
                paths_mt = path_service_mt.get_paths()
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
