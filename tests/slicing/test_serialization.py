from __future__ import annotations
from mole.core.data import Path
from tests.slicing.conftest import TestSlicing
from typing import List
import binaryninja as bn


class TestSerialization(TestSlicing):
    def test_serialization_01(
        self, filenames: List[str] = ["function_calling-02"]
    ) -> None:
        for file in self.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            for path in paths:
                assert path == Path.from_dict(bv, path.to_dict()), "serialization"
            bv.file.close()
        return
