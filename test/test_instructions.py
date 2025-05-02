from mole.common.log import log
from mole.core.slice import MediumLevelILBackwardSlicer
import binaryninja as bn
import unittest


class TestMediumLevelILInstruction(unittest.TestCase):
    """
    This class implements unit tests to test the slicing of MLIL instructions.
    """

    def setUp(self) -> None:
        # Logger properties
        log.change_properties(level="debug", runs_headless=True)
        # Architecture and platform
        self.arch = bn.Architecture["x86_64"]
        self.plat = self.arch.standalone_platform
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
