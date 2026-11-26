from __future__ import annotations
from tests.slicing.conftest import TestSlicing
from typing import List
import pytest


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
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[["main", "set_cmd", "my_getenv"]],
            filenames=filenames,
        )
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

    def test_load_11(self, filenames: List[str] = ["load-11"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[
                ["main", "set_cmd1"],
                ["main", "set_cmd2"],
                ["main", "set_cmd2"],
            ],
            filenames=filenames,
        )
        return

    def test_load_12(self, filenames: List[str] = ["load-12"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[["run"], ["run"]],
            filenames=filenames,
        )
        return

    def test_load_13(self, filenames: List[str] = ["load-13"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[["run", "set_cmd"]],
            filenames=filenames,
        )
        return

    def test_load_14(self, filenames: List[str] = ["load-14"]) -> None:
        self.test_load_13(filenames=filenames)
        return

    def test_load_15(self, filenames: List[str] = ["load-15"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[["main", "set_cmd"]],
            filenames=filenames,
        )
        return

    @pytest.mark.xfail
    def test_load_16(self, filenames: List[str] = ["load-16"]) -> None:
        self.test_load_15(filenames=filenames)
        return

    def test_load_17(self, filenames: List[str] = ["load-17"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    @pytest.mark.xfail
    def test_load_18(self, filenames: List[str] = ["load-18"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[["main", "set_cmds", "new_cmds"]],
            filenames=filenames,
        )
        return

    def test_load_19(self, filenames: List[str] = ["load-19"]) -> None:
        self.test_load_13(filenames=filenames)
        return
