import unittest
from utils import TestCase
from typing import List
import binaryninja as bn

from typing               import List
from utils                import load_files

class TestPointerAnalysis(TestCase):
    
    def test_pointer_analysis_01_02(
            self,
            filenames: List[str] = ["pointer_analysis-01", "pointer_analysis-02"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 1, "1 path identified")
            path = paths[0]
            self.assertIn(path.src_sym_name, ["getenv"], "source has symbol 'getenv'")
            self.assertTrue(
                isinstance(path.insts[-1], bn.MediumLevelILInstruction),
                "source is a MLIL instruction"
            )
            self.assertIn(path.snk_sym_name, ["system"], "sink has symbol 'system'")
            self.assertTrue(
                (
                    isinstance(path.insts[0], bn.MediumLevelILCallSsa) or
                    isinstance(path.insts[0], bn.MediumLevelILTailcallSsa)
                ),
                "sink is a MLIL call instruction"
            )
            self.assertEqual(path.snk_par_idx, 0, "arg1")
            self.assertTrue(
                isinstance(path.snk_par_var, bn.MediumLevelILVarSsa),
                "argument is a MLIL variable"
            )
            calls = [path.snk_sym_name]
            for inst in path.insts:
                call = inst.function.source_function.name
                if calls[-1] != call:
                    calls.append(call)
            calls.append(path.src_sym_name)
            self.assertEqual(calls, ["system", "main", "getenv"], "call chain")
            # Close test binary
            bv.file.close()
        return
    
    @unittest.expectedFailure
    def test_pointer_analysis_03(
            self,
            filenames: List[str] = ["pointer_analysis-03"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertEqual(1, len(paths), "paths number not correctly identified")
            path = paths[0]
            self.assertIn(path.src_sym_name, ["getenv"], "source has symbol 'getenv'")
            self.assertTrue(
                isinstance(path.insts[-1], bn.MediumLevelILInstruction),
                "source is a MLIL instruction"
            )
            self.assertIn(path.snk_sym_name, ["system"], "sink has symbol 'system'")
            self.assertTrue(
                (
                    isinstance(path.insts[0], bn.MediumLevelILCallSsa) or
                    isinstance(path.insts[0], bn.MediumLevelILTailcallSsa)
                ),
                "sink is a MLIL call instruction"
            )
            self.assertEqual(path.snk_par_idx, 0, "arg1")
            self.assertTrue(
                isinstance(path.snk_par_var, bn.MediumLevelILVarSsa),
                "argument is a MLIL variable"
            )
            calls = [path.snk_sym_name]
            for inst in path.insts:
                call = inst.function.source_function.name
                if calls[-1] != call:
                    calls.append(call)
            calls.append(path.src_sym_name)
            self.assertEqual(calls, ["system", "main", "getenv"], "call chain")
            # Close test binary
            bv.file.close()
        return