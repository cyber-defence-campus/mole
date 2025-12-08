from __future__ import annotations
from tests.slicing.conftest import TestSlicing
from typing import List
import binaryninja as bn


class TestFunctionOutParams(TestSlicing):
    def test_function_out_params_01(
        self, filenames: List[str] = ["function_out_params-01"]
    ) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("memcpy", 3)],
            call_chains=[["main", "get_size"]],
            filenames=filenames,
        )
        return

    def test_function_out_params_02(
        self, filenames: List[str] = ["function_out_params-02"]
    ) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
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

    def test_function_out_params_05(
        self, filenames: List[str] = ["function_out_params-05"]
    ) -> None:
        self.test_function_out_params_02(filenames)
        return

    def test_function_out_params_06(
        self, filenames: List[str] = ["function_out_params-06"]
    ) -> None:
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_function_out_params_07(
        self, filenames: List[str] = ["function_out_params-07"]
    ) -> None:
        self.test_function_out_params_06(filenames)
        return

    def test_function_out_params_08(
        self, filenames: List[str] = ["function_out_params-08"]
    ) -> None:
        def manually_set_types(bv: bn.BinaryView) -> None:
            get_cmd = bv.get_functions_by_name("get_cmd")[0]
            printf_call_site = get_cmd.call_sites[1]
            printf_type, _ = bv.parse_type_string(
                "int printf(const char* format, char* msg)"
            )
            get_cmd.set_call_type_adjustment(printf_call_site.address, printf_type)
            bv.update_analysis_and_wait()
            return

        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[["main", "check_cmd", "get_cmd"]],
            filenames=filenames,
            bv_callback=manually_set_types,
        )
        return
