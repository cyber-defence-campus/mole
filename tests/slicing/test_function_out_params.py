from __future__ import annotations
from tests.slicing.conftest import TestSlicing
from typing import List


class TestFunctionOutParams(TestSlicing):
    def test_function_out_params_01(
        self, filenames: List[str] = ["function_out_params-01"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 3)],
            call_chains=[["main", "get_size"]],
            filenames=filenames,
        )
        return

    def test_function_out_params_02(
        self, filenames: List[str] = ["function_out_params-02"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main", "get_cmd"]],
            filenames=filenames,
        )
        return

    def test_function_out_params_03(
        self, filenames: List[str] = ["function_out_params-03"]
    ) -> None:
        self.test_function_out_params_02(filenames)
        return

    def test_function_out_params_04(
        self, filenames: List[str] = ["function_out_params-04"]
    ) -> None:
        self.test_function_out_params_02(filenames)
        return
