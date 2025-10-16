from __future__ import annotations
from tests.slicing.conftest import SlicingTestBase
from typing import List
import pytest


class TestStruct(SlicingTestBase):
    @pytest.mark.xfail
    def test_struct_01(self, filenames: List[str] = ["struct-01"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 2)],
            call_chains=[["main"]],
            filenames=filenames,
        )
