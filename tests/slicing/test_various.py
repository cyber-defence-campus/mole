from __future__ import annotations
from tests.slicing.conftest import TestSlicing
from typing import List
import pytest


class TestVarious(TestSlicing):
    def test_gets_01(self, filenames: List[str] = ["gets-01"]) -> None:
        self.assert_paths(
            srcs=[("gets", 1)],
            snks=[("gets", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_gets_02(self, filenames: List[str] = ["gets-02"]) -> None:
        self.assert_paths(
            srcs=[("gets", 1)],
            snks=[("gets", 1), ("memcpy", 2)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return

    def test_sscanf_01(self, filenames: List[str] = ["sscanf-01"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("sscanf", 1), ("__isoc99_sscanf", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_memcpy_01(self, filenames: List[str] = ["memcpy-01"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("memcpy", 3)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_memcpy_02(self, filenames: List[str] = ["memcpy-02"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("memcpy", 2), ("memcpy", 3)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return

    def test_memcpy_03(self, filenames: List[str] = ["memcpy-03"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("memcpy", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_memcpy_04(self, filenames: List[str] = ["memcpy-04"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("memcpy", 3)],
            call_chains=[["main", "my_getenv"]],
            filenames=filenames,
        )
        return

    def test_memcpy_05(self, filenames: List[str] = ["memcpy-05"]) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("memcpy", 2), ("memcpy", 3)],
            call_chains=[["main", "my_getenv"], ["main", "my_getenv"]],
            filenames=filenames,
        )
        return

    def test_memcpy_06(self, filenames: List[str] = ["memcpy-06"]) -> None:
        self.assert_paths(
            srcs=[],
            snks=[],
            call_chains=[],
            filenames=filenames,
        )
        return

    def test_memcpy_07(self, filenames: List[str] = ["memcpy-07"]) -> None:
        self.test_memcpy_02(filenames)
        return

    @pytest.mark.xfail
    def test_memcpy_08(self, filenames: List[str] = ["memcpy-08"]) -> None:
        self.test_memcpy_06(filenames)
        return

    def test_memcpy_09(self, filenames: List[str] = ["memcpy-09"]) -> None:
        self.test_memcpy_06(filenames)
        return

    @pytest.mark.xfail
    def test_memcpy_10(self, filenames: List[str] = ["memcpy-10"]) -> None:
        self.test_memcpy_06(filenames)
        return

    def test_memcpy_11(self, filenames: List[str] = ["memcpy-11"]) -> None:
        self.test_memcpy_06(filenames)
        return
