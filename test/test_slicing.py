from __future__           import annotations
from mole.common.log      import Logger
from mole.core.controller import Controller
from typing               import List
import binaryninja as bn
import os
import unittest


def load_files(names: List[str]) -> List[str]:
    """
    This function returns all files in the `testcases` directory matching `name` but ignoring the
    file extension.
    """
    directory = os.path.join(os.path.dirname(__file__), "bin")
    files = []
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            if os.path.splitext(filename)[0] in names:
                files.append(os.path.join(dirpath, filename))
    return files


class TestCase(unittest.TestCase):
    """
    This class implements unit tests to test backward slicing for finding interesting code paths.
    """

    def setUp(self) -> None:
        # Initialize controller to operate in headless mode
        self.ctr = Controller(
            runs_headless=True,
            log=Logger(
                runs_headless=True,
                level="debug"
            )
        ).init()
        return


class TestSourceInCallee(TestCase):
    
    def test_01(
            self,
            filenames: List[str] = ["source_in_callee-01"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 2, "2 paths identified")
            for path in paths:
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
            # Close test binary
            bv.file.close()
        return
    
    def test_02(
            self,
            filenames: List[str] = ["source_in_callee-02"]
        ) -> None:
        self.test_01(filenames)
        return
    
    def test_03(
            self,
            filenames: List[str] = ["source_in_callee-03"]
        ) -> None:
        self.test_01(filenames)
        return
    
    def test_04(
            self,
            filenames: List[str] = ["source_in_callee-04"]
        ) -> None:
        self.test_01(filenames)
        return


class TestPointerAnalysis(TestCase):
    
    @unittest.expectedFailure
    def test_01(
            self,
            filenames: List[str] = ["pointer_analysis-01"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 1, "1 paths identified")
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
            # Close test binary
            bv.file.close()
        return


class TestServerExample(TestCase):
    
    def test_01(
            self,
            filenames: List[str] = ["recv-01"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) >= 2, ">= 2 paths identified")
            for path in paths:
                self.assertIn(path.src_sym_name, ["recv"], "source has symbol 'recv'")
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
            # Close test binary
            bv.file.close()
        return
    
    def test_02(
            self,
            filenames: List[str] = ["recv-02"]
        ) -> None:
        self.test_01(filenames)
        return