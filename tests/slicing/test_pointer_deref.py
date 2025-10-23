from __future__ import annotations
from tests.slicing.conftest import TestSlicing
from typing import List


class TestPointerDeref(TestSlicing):
    def test_load_01(self, filenames: List[str] = ["load-01"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_load_02(self, filenames: List[str] = ["load-02"]) -> None:
        self.test_load_01(filenames=filenames)
        return

    def test_load_03(self, filenames: List[str] = ["load-03"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return

    def test_load_04(self, filenames: List[str] = ["load-04"]) -> None:
        self.test_load_03(filenames=filenames)
        return

    def test_load_05(self, filenames: List[str] = ["load-05"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 2), ("memcpy", 3)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return
