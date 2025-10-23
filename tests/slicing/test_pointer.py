from __future__ import annotations
from tests.slicing.conftest import TestSlicing
from typing import List
import pytest


class TestPointerAnalysis(TestSlicing):
    def test_pointer_analysis_01(
        self, filenames: List[str] = ["pointer_analysis-01"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_pointer_analysis_02(
        self, filenames: List[str] = ["pointer_analysis-02"]
    ) -> None:
        self.test_pointer_analysis_01(filenames)
        return

    def test_pointer_analysis_03(
        self, filenames: List[str] = ["pointer_analysis-03"]
    ) -> None:
        self.test_pointer_analysis_01(filenames)
        return

    def test_pointer_analysis_04(
        self, filenames: List[str] = ["pointer_analysis-04"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return

    def test_pointer_analysis_05(
        self, filenames: List[str] = ["pointer_analysis-05"]
    ) -> None:
        self.assert_paths(
            src=[],
            snk=[],
            call_chains=[],
            filenames=filenames,
        )
        return

    def test_pointer_analysis_06(
        self, filenames: List[str] = ["pointer_analysis-06"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 3)],
            call_chains=[["main", "modify_n"], ["main", "modify_n"]],
            filenames=filenames,
        )
        return

    def test_pointer_analysis_07(
        self, filenames: List[str] = ["pointer_analysis-07"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 2)],
            call_chains=[["main", "my_getenv"]],
            filenames=filenames,
        )
        return

    def test_pointer_analysis_08(
        self, filenames: List[str] = ["pointer_analysis-08"]
    ) -> None:
        self.test_pointer_analysis_07(filenames)
        return

    def test_pointer_analysis_09(
        self, filenames: List[str] = ["pointer_analysis-09"]
    ) -> None:
        self.test_pointer_analysis_01(filenames)
        return

    def test_pointer_analysis_10(
        self, filenames: List[str] = ["pointer_analysis-10"]
    ) -> None:
        self.test_pointer_analysis_01(filenames)
        return

    def test_pointer_analysis_11(
        self, filenames: List[str] = ["pointer_analysis-11"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["execute", "main"]],
            filenames=filenames,
        )
        return

    def test_pointer_analysis_12(
        self, filenames: List[str] = ["pointer_analysis-12"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return

    @pytest.mark.xfail
    def test_pointer_analysis_13(
        self, filenames: List[str] = ["pointer_analysis-13"]
    ) -> None:
        self.test_pointer_analysis_12(filenames)
        return

    def test_pointer_analysis_14(
        self, filenames: List[str] = ["pointer_analysis-14"]
    ) -> None:
        self.test_pointer_analysis_01(filenames)
        return

    @pytest.mark.xfail
    def test_pointer_analysis_15(
        self, filenames: List[str] = ["pointer_analysis-15"]
    ) -> None:
        self.assert_paths(
            src=[("getopt", 2)],
            snk=[("strcpy", 2)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return
