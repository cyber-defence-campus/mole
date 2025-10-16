from __future__ import annotations
from typing import List
import binaryninja as bn
from mole.core.data import Path
from .conftest import SlicingTestBase


class TestSerialization(SlicingTestBase):
    """Tests for path serialization in slicing."""

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
                assert path == Path.from_dict(
                    bv, path.to_dict()
                ), "serialization failed"
            bv.file.close()
