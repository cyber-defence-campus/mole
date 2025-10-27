from __future__ import annotations
from tests.slicing.conftest import TestSlicing
from typing import List


class TestPolymorphism(TestSlicing):
    def test_polymorphism_01(self, filenames: List[str] = ["polymorphism-01"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1), ("popen", 1)],
            call_chains=[
                ["MyParentStruct::my_func", "main"],
                ["MyChildStruct::my_virt_func2", "main"],
            ],
            filenames=filenames,
        )
        return
