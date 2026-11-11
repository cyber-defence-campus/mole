from __future__ import annotations
from tests.slicing.conftest import TestSlicing
from typing import List


class TestPointerDeref(TestSlicing):
    def test_load_01(self, filenames: List[str] = ["load-01"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_load_02(self, filenames: List[str] = ["load-02"]) -> None:
        self.test_load_01(filenames=filenames)
        return

    def test_load_03(self, filenames: List[str] = ["load-03"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return

    def test_load_04(self, filenames: List[str] = ["load-04"]) -> None:
        self.test_load_03(filenames=filenames)
        return

    def test_load_05(self, filenames: List[str] = ["load-05"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("memcpy", 2), ("memcpy", 3)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return

    def test_load_06(self, filenames: List[str] = ["load-06"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[["main", "set_cmd"]],
            filenames=filenames,
        )
        return

    def test_load_07(self, filenames: List[str] = ["load-07"]) -> None:
        self.test_load_06(filenames=filenames)
        return

    def test_load_08(self, filenames: List[str] = ["load-08"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[["run"]],
            filenames=filenames,
        )
        return

    def test_load_09(self, filenames: List[str] = ["load-09"]) -> None:
        self.test_load_01(filenames=filenames)
        return

    def test_load_10(self, filenames: List[str] = ["load-10"]) -> None:
        self.test_load_01(filenames=filenames)
        return
