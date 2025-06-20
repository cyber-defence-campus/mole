from keystone import Ks, KS_ARCH_X86, KS_MODE_64
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
    """
    This class implements unit tests to test the slicing of MLIL instructions on the x86_64
    architecture.
    """

    def setUp(self) -> None:
        super().setUp()
        # Architecture and platform
        self.arch = bn.Architecture["x86_64"]
        self.plat = self.arch.standalone_platform
        # Keystone assembler
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        return

    def create_bv(self, size: int = 1024) -> bn.BinaryView:
        """
        This method creates a new binary view of the given size.
        """
        bv = bn.BinaryView.new(b"\x00" * size)
        bv.platform = self.plat
        return bv

    def create_function(
        self, bv: bn.BinaryView, addr: int = 0x0, assembly_code: str = ""
    ) -> bn.Function | None:
        """
        This method creates a new function in the given binary view at the specified address.
        """
        # Assemble code
        encoding, _ = self.ks.asm(assembly_code, as_bytes=True)
        # Write data at the given address
        bv.write(addr, encoding)
        # Create function at the given address
        bv.add_function(addr, self.plat)
        bv.update_analysis_and_wait()
        # Return the created function
        return bv.get_function_at(addr)

    def test_mlil_inst(
        self,
        bv: bn.BinaryView | None = None,
        assembly_code: str = "",
        expected_inst_types: List[bn.MediumLevelILInstruction] = [],
        expected_call_types: List[int] = [],
    ) -> None:
        """
        This method tests the slicing of a MLIL instruction.
        """
        if not bv or not assembly_code or not expected_inst_types:
            return
        # Create function
        func = self.create_function(bv, 0x0, assembly_code)
        # Assert correct MLIL instruction
        inst = list(func.mlil.ssa_form.instructions)[0]
        self.assertIsInstance(
            inst,
            expected_inst_types[0],
            f"instruction {str(inst):s} has type {expected_inst_types[0].__name__:s}",
        )
        # Slice instruction
        slicer = MediumLevelILBackwardSlicer(func.view)
        slicer._slice_backwards(inst)
        # Assert instruction slice
        inst_slice = list(slicer.inst_graph.nodes())
        self.assertEqual(
            len(inst_slice), len(expected_inst_types), "incorrect slice length"
        )
        for inst, type in zip(inst_slice, expected_inst_types):
            self.assertIsInstance(
                inst, type, f"instruction {str(inst):s} has type {type.__name__:s}"
            )
        # Assert call slice
        call_slice = list(slicer.call_graph.nodes())
        self.assertEqual(
            len(call_slice), len(expected_call_types), "incorrect call slice length"
        )
        for call, call_addr in zip(call_slice, expected_call_types):
            func: bn.Function = call.source_function
            self.assertEqual(
                func.start,
                call_addr,
                f"call address 0x{func.start:x} is not 0x{call_addr:x}",
            )
        return

    def test_mlil_jump(self) -> None:
        self.test_mlil_inst(
            self.create_bv(),
            "jmp 0x1000",
            [bn.MediumLevelILJump, bn.MediumLevelILConstPtr],
            [],
        )
        return

    def test_mlil_call(self) -> None:
        # Create binary view
        bv = self.create_bv()
        # Create a dummy function
        self.create_function(bv, 0x100, "ret")
        # Test call instruction
        self.test_mlil_inst(
            bv,
            "call 0x100",
            [bn.MediumLevelILCallSsa, bn.MediumLevelILRet],
            [0x0, 0x100],
        )
        return

    def test_mlil_jump(self) -> None:
        return self.test_mlil_inst(
            "jmp 0x1000",
            [bn.MediumLevelILJump, bn.MediumLevelILConstPtr],
        )

    # def test_mlil_jump_to(self) -> None:
    #     return self.test_mlil_inst(
    #         """
    #         mov eax, edi
    #         cmp eax, 2
    #         ja  0x1000
    #         mov eax, [0x2000 + rax*4]
    #         jmp rax
    #         """,
    #         [bn.MediumLevelILJumpTo, bn.MediumLevelILConst],
    #     )

    def test_mlil_store_ssa(self) -> None:
        self.test_mlil_inst(
            self.create_bv(),
            "mov dword ptr [rax], 0xdeadbeef",
            [bn.MediumLevelILStoreSsa, bn.MediumLevelILConst],
            [],
        )
        return

    # def test_mlil_store_struct(self, filenames: List[str] = ["struct-02"]) -> None:
    #     # Define structure name and type
    #     struct_name = "my_struct"
    #     struct = bn.StructureBuilder.create()
    #     struct.append(bn.Type.int(4), "field_a")
    #     struct.append(bn.Type.int(4), "field_b")
    #     struct.append(bn.Type.int(4), "field_c")
    #     struct_type = bn.Type.structure_type(struct)

    #     for file in TestMediumLevelILInstruction.load_files(filenames):
    #         # TODO: Does not yet lead to a MLIL_STORE_STRUCT instruction
    #         # TODO: Revise comments
    #         # Load and analyze test binary with Binary Ninja
    #         bv = bn.load(file)
    #         bv.update_analysis_and_wait()
    #         # Get _start function
    #         func = list(bv.functions)[0]
    #         # Create struct type
    #         bv.define_user_type(struct_name, struct_type)
    #         struct_named_type = bn.Type.named_type_from_registered_type(bv, struct_name)
    #         # Create data variable with the struct type
    #         s1_addr = bv.get_symbol_by_raw_name("s1").address
    #         bv.define_user_data_var(s1_addr, struct_named_type)
    #         s2_addr = bv.get_symbol_by_raw_name("s2").address
    #         bv.define_user_data_var(s2_addr, struct_named_type)
    #         # Define pointer type at use site
    #         # Create variable representing rdi
    #         rdi_id = bv.arch.get_reg_index("rdi")
    #         rdi_var = bn.Variable(
    #             func, bn.VariableSourceType.RegisterVariableSourceType, 0, rdi_id
    #         )
    #         # Create pointer to structure type
    #         my_struct_ptr_type = bn.Type.pointer(bv.arch, struct_named_type)
    #         func.create_user_var(rdi_var, my_struct_ptr_type, "rdi")
    #         # func = current_function
    #         # var = func.get_var_at(Architecture['x86_64'], "rdi")
    #         # func.create_user_var(var, Type.pointer(Architecture['x86_64'], Type.named_type_from_registered_type(bv, "my_struct")), "my_struct_ptr")
    #         # Reanalyze the _start function
    #         func.reanalyze()
    #     return
