from mole.common.log import log
from mole.core.slice import MediumLevelILBackwardSlicer
from typing import List
import binaryninja as bn
import os
import unittest


class TestMediumLevelILInstruction(unittest.TestCase):
    """
    This class implements unit tests to test the slicing of MLIL instructions.
    """

    def setUp(self) -> None:
        # Logger properties
        log.change_properties(level="debug", runs_headless=True)
        return

    @staticmethod
    def load_files(names: List[str]) -> List[str]:
        """
        This method returns all files in the `testcases` directory matching
        `name` but ignoring the file extension.
        """
        directory = os.path.join(os.path.dirname(__file__), "bin")
        files = []
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                if os.path.splitext(filename)[0] in names:
                    files.append(os.path.join(dirpath, filename))
        return files


class Test_x86_64(TestMediumLevelILInstruction):
    def setUp(self) -> None:
        # Architecture and platform
        self.arch = bn.Architecture["x86_64"]
        self.plat = self.arch.standalone_platform
        return

    def test_mlil_store_struct(self, filenames: List[str] = ["struct-01"]) -> None:
        # Define structure name and type
        struct_name = "MyStruct"
        struct_type = bn.StructureBuilder.create()
        struct_type.append(bn.Type.int(4), "field_a")
        struct_type.append(bn.Type.int(4), "field_b")

        for file in TestMediumLevelILInstruction.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Create struct type
            bv.define_user_type(struct_name, struct_type)
            # Create data variable with the struct type
            my_struct_addr = bv.get_symbol_by_raw_name("my_struct").address
            my_struct_type = bn.Type.named_type_from_registered_type(bv, struct_name)
            bv.define_user_data_var(my_struct_addr, my_struct_type)
            # Manually add _start symbol and get the function
            bv.define_user_symbol(
                bn.Symbol(bn.SymbolType.FunctionSymbol, bv.entry_point, "_start")
            )
            func = bv.get_functions_by_name("_start")[0]
            # Define pointer type at use site
            # Create variable representing rdi
            rdi_id = bv.arch.get_reg_index("rdi")
            rdi_var = bn.Variable(
                func, bn.VariableSourceType.RegisterVariableSourceType, 0, rdi_id
            )
            # Create pointer to structure type
            my_struct_ptr_type = bn.Type.pointer(
                bv.arch, bn.Type.named_type_from_registered_type(bv, struct_name)
            )
            func.create_user_var(rdi_var, my_struct_ptr_type, "rdi")
        return

    def test_mlil_store(self) -> None:
        # Assembly code
        code = b"\xc7\x00\xef\xbe\xad\xde"
        # Binary view
        bv = bn.BinaryView.new(code)
        bv.platform = self.plat
        bv.add_function(0, self.plat)
        bv.update_analysis_and_wait()
        # Slice instruction
        slicer = MediumLevelILBackwardSlicer(bv)
        func = bv.get_function_at(0)
        for inst in func.mlil.ssa_form.instructions:
            if isinstance(inst, bn.MediumLevelILStoreSsa):
                slicer._slice_backwards(inst)
                break
        # Assert results
        self.assertEqual(len(slicer.inst_graph.nodes), 2, "count inst nodes")
        self.assertEqual(len(slicer.inst_graph.edges), 1, "count inst edges")
        return
