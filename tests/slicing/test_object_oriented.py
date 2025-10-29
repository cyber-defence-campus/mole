from __future__ import annotations
from tests.slicing.conftest import TestSlicing
from typing import List
import binaryninja as bn
import pytest


class TestObjectOriented(TestSlicing):
    def test_object_oriented_01(
        self, filenames: List[str] = ["object_oriented-01"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[
                ["MyParent::my_func", "main"],
                ["MyParent::my_func", "main"],
            ],
            filenames=filenames,
        )
        return

    @pytest.mark.xfail(
        reason="Binja returns an invalid code x-ref for `MyParent::VTable::my_func`"
    )
    def test_object_oriented_02(
        self, filenames: List[str] = ["object_oriented-02"]
    ) -> None:
        def manually_set_types(bv: bn.BinaryView) -> None:
            main_func = bv.get_functions_by_name("main")[0]
            # Manually define class MyParent
            p_class = """
            class MyParent __packed
            {
                `MyParent::VTable`* vptr;
                char const* name;
            };
            """
            parsed_p_class = bv.parse_types_from_string(p_class)
            for name, type in parsed_p_class.types.items():
                bv.define_user_type(name, type)
            # Manually set type and name of variable `p` (i.e. `MyParent* p = ...`)
            p_class_type = bv.get_type_by_name("MyParent")
            p_new_inst: bn.HighLevelILVarInit = main_func.call_sites[0].hlil
            p_new_inst.dest.type = bn.Type.pointer(bv.arch, p_class_type)
            p_new_inst.dest.name = "p"
            # Manually define class MyChild
            c_class = """
            class MyChild __packed
            {
                `MyParent::MyChild::VTable`* vptr;
                char const* name;
            };
            """
            parsed_c_class = bv.parse_types_from_string(c_class)
            for name, type in parsed_c_class.types.items():
                bv.define_user_type(name, type)
            # Manually set type and name of variable `c` (i.e. `MyChild* c = ...`)
            c_class_type = bv.get_type_by_name("MyChild")
            c_new_inst: bn.HighLevelILVarInit = main_func.call_sites[2].hlil
            c_new_inst.dest.type = bn.Type.pointer(bv.arch, c_class_type)
            c_new_inst.dest.name = "c"
            return

        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1), ("popen", 1)],
            call_chains=[
                ["MyParent::my_func", "main"],
                ["MyChild::my_func", "main"],
            ],
            filenames=filenames,
            bv_callback=manually_set_types,
        )
        return
