from __future__ import annotations
from tests.slicing import TestSlicing
from typing import List
import pytest


class TestNameMangling(TestSlicing):
    def test_name_mangling_01(
        self, filenames: List[str] = ["name_mangling-01"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["overloaded_func", "main"], ["overloaded_func", "main"]],
            filenames=filenames,
        )
        return

    def test_name_mangling_02(
        self, filenames: List[str] = ["name_mangling-02"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["MyStruct::my_func", "main"], ["MyClass::my_func", "main"]],
            filenames=filenames,
        )
        return

    def test_name_mangling_03(
        self, filenames: List[str] = ["name_mangling-03"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["ns::my_func", "main"]],
            filenames=filenames,
        )
        return

    def test_name_mangling_04(
        self, filenames: List[str] = ["name_mangling-04"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["my_func<int>", "main"]],
            filenames=filenames,
        )
        return

    @pytest.mark.xfail
    def test_name_mangling_05(
        self, filenames: List[str] = ["name_mangling-05"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[
                ["MyStruct::my_func", "_GLOBAL__sub_I__ZN8MyStruct3cmdE"],
                ["MyClass::my_func", "_GLOBAL__sub_I__ZN8MyStruct3cmdE"],
            ],
            filenames=filenames,
        )
        return

    @pytest.mark.xfail
    def test_name_mangling_06(
        self, filenames: List[str] = ["name_mangling-06"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["MyStruct::my_func", "main", "MyStruct::operator+"]],
            filenames=filenames,
        )
        return
