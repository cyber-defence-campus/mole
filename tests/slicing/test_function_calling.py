from __future__ import annotations
from typing import List
from .conftest import SlicingTestBase


class TestFunctionCalling(SlicingTestBase):
    """Tests for function calling scenarios in slicing."""

    def test_function_calling_01(
        self, filenames: List[str] = ["function_calling-01"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )

    def test_function_calling_02(
        self, filenames: List[str] = ["function_calling-02"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[
                ["system_2", "system_1a", "main", "getenv_1a", "getenv_2"],
                ["system_2", "system_1a", "main", "getenv_1b", "getenv_2"],
            ],
            filenames=filenames,
        )

    def test_function_calling_03(
        self, filenames: List[str] = ["function_calling-03"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[
                ["system_1a", "main", "getenv_1a"],
                ["system_1a", "main", "getenv_1b"],
            ],
            filenames=filenames,
        )

    def test_function_calling_04(
        self, filenames: List[str] = ["function_calling-04"]
    ) -> None:
        self.test_function_calling_02(filenames)

    def test_function_calling_05(
        self, filenames: List[str] = ["function_calling-05"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )

    def test_function_calling_06(
        self, filenames: List[str] = ["function_calling-06"]
    ) -> None:
        self.test_function_calling_05(filenames)

    def test_function_calling_07(
        self, filenames: List[str] = ["function_calling-07"]
    ) -> None:
        self.assert_paths(
            src=[],
            snk=[],
            call_chains=[],
            filenames=filenames,
        )

    def test_function_calling_08(
        self, filenames: List[str] = ["function_calling-08"]
    ) -> None:
        self.test_function_calling_07(filenames)

    def test_function_calling_09(
        self, filenames: List[str] = ["function_calling-09"]
    ) -> None:
        self.test_function_calling_05(filenames)

    def test_function_calling_10(
        self, filenames: List[str] = ["function_calling-10"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["system_1", "main", "getenv_1", "getenv_2"]],
            filenames=filenames,
        )

    def test_function_calling_11(
        self, filenames: List[str] = ["function_calling-11"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main", "getenv_1", "getenv_2"]],
            filenames=filenames,
        )

    def test_function_calling_12(
        self, filenames: List[str] = ["function_calling-12"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main", "getenv_1", "getenv_2", "getenv_3", "getenv_4"]],
            filenames=filenames,
        )

    def test_function_calling_13(
        self, filenames: List[str] = ["function_calling-13"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["system_1", "main"]],
            filenames=filenames,
        )

    def test_function_calling_14(
        self, filenames: List[str] = ["function_calling-14"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["system_3", "system_2", "system_1", "main"]],
            filenames=filenames,
        )

    def test_function_calling_15(
        self, filenames: List[str] = ["function_calling-15"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["system_2", "system_1", "main", "getenv_1", "getenv_2"]],
            filenames=filenames,
        )
