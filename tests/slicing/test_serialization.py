from __future__ import annotations
from mole.common.log import Logger
from mole.data.path import Path
from mole.models.config import ConfigModel
from mole.services.config import ConfigService
from mole.services.path import PathService
from tests.slicing.conftest import TestSlicing
from typing import List
import binaryninja as bn


class TestSerialization(TestSlicing):
    def test_serialization_01(
        self, filenames: List[str] = ["function_calling-02"]
    ) -> None:
        for file in self.load_files(filenames):
            # Logger
            log = Logger()
            # Configuration model
            model = ConfigModel(ConfigService(log).import_config(self._config_file))
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
            # Assert results
            for path in paths:
                assert path == Path.from_dict(bv, path.to_dict()), "serialization"
            bv.file.close()
        return
