from __future__ import annotations
from typing import List
import pytest
from .conftest import SlicingTestBase


class TestStruct(SlicingTestBase):
    """Tests for struct handling in slicing."""

    @pytest.mark.xfail
    def test_struct_01(self, filenames: List[str] = ["struct-01"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 2)],
            call_chains=[["main"]],
            filenames=filenames,
        )
