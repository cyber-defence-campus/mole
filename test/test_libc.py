from __future__           import annotations
from mole.common.log      import Logger
from mole.core.controller import Controller
from typing               import List
import binaryninja as bn
import os
import unittest


def load_files(name: str) -> List[str]:
    """
    This function returns all files in the `testcases` directory matching `name` but ignoring the
    file extension.
    """
    directory = os.path.join(os.path.dirname(__file__), "testcases", "bin")
    files = []
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            if os.path.splitext(filename)[0] == name:
                files.append(os.path.join(dirpath, filename))
    return files


class TestGets(unittest.TestCase):
    """
    This class implements unit tests for `libc` function `gets`.
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

    def test_gets_01(self) -> None:
        for file in load_files("gets-01"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) > 0, "path(s) identified")
            for path in paths:
                self.assertIn(path.src_sym_name, ["gets"], "source has symbol 'gets'")
                self.assertTrue(
                    isinstance(path.insts[-1], bn.MediumLevelILInstruction),
                    "source is a MLIL instruction"
                )
                self.assertIn(path.snk_sym_name, ["gets"], "sink has symbol 'gets'")
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
    
    @unittest.expectedFailure
    def test_gets_02(self) -> None:
        for file in load_files("gets-02"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) > 0, "path(s) identified")
            gets_memcpy_path = False
            for path in paths:
                self.assertIn(path.src_sym_name, ["gets"], "source has symbol 'gets'")
                self.assertTrue(
                    isinstance(path.insts[-1], bn.MediumLevelILInstruction),
                    "source is a MLIL instruction"
                )
                self.assertTrue(path.snk_sym_name in ["gets", "memcpy"], "sink has symbol 'gets' or 'memcpy'")
                self.assertTrue(
                    isinstance(path.insts[0], bn.MediumLevelILCallSsa),
                    "sink is a MLIL call instruction"
                )
                if path.src_sym_name == "gets" and path.snk_sym_name == "memcpy":
                    gets_memcpy_path = True
            self.assertTrue(gets_memcpy_path, "source 'gets' and sink 'memcpy'")
            # Close test binary
            bv.file.close()
        return


class TestMemcpy(unittest.TestCase):
    """
    This class implements unit tests for `libc` function `memcpy`.
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

    def test_memcpy_01(self) -> None:
        for file in load_files("memcpy-01"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 1, "path(s) identified")
            path = paths[0]
            self.assertIn(path.src_sym_name, ["getenv"], "source has symbol 'getenv'")
            self.assertTrue(
                isinstance(path.insts[-1], bn.MediumLevelILInstruction),
                "source is a MLIL instruction"
            )
            self.assertIn(path.snk_sym_name, ["memcpy"], "sink has symbol 'memcpy'")
            self.assertTrue(
                (
                    isinstance(path.insts[0], bn.MediumLevelILCallSsa) or
                    isinstance(path.insts[0], bn.MediumLevelILTailcallSsa)
                ),
                "sink is a MLIL call instruction"
            )
            self.assertEqual(path.snk_par_idx, 2, "arg3")
            self.assertTrue(
                isinstance(path.snk_par_var, bn.MediumLevelILVarSsa),
                "argument is a MLIL variable"
            )
            # Close test binary
            bv.file.close()
        return
    
    def test_memcpy_02(self) -> None:
        for file in load_files("memcpy-02"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) > 0, "path(s) identified")
            for path in paths:
                self.assertIn(path.src_sym_name, ["getenv"], "source has symbol 'getenv'")
                self.assertTrue(
                    isinstance(path.insts[-1], bn.MediumLevelILInstruction),
                    "source is a MLIL instruction"
                )
                self.assertIn(path.snk_sym_name, ["memcpy"], "sink has symbol 'memcpy'")
                self.assertTrue(
                    (
                        isinstance(path.insts[0], bn.MediumLevelILCallSsa) or
                        isinstance(path.insts[0], bn.MediumLevelILTailcallSsa)
                    ),
                    "sink is a MLIL call instruction"
                )
                self.assertTrue(path.snk_par_idx in [1, 2], "arg2 or arg3")
                self.assertTrue(
                    isinstance(path.snk_par_var, bn.MediumLevelILVarSsa),
                    "argument is a MLIL variable"
                )
            # Close test binary
            bv.file.close()
        return
    
    def test_memcpy_03(self) -> None:
        for file in load_files("memcpy-03"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) > 0, "path(s) identified")
            for path in paths:
                self.assertIn(path.src_sym_name, ["getenv"], "source has symbol 'getenv'")
                self.assertTrue(
                    isinstance(path.insts[-1], bn.MediumLevelILInstruction),
                    "source is a MLIL instruction"
                )
                self.assertIn(path.snk_sym_name, ["memcpy"], "sink has symbol 'memcpy'")
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
    
    def test_memcpy_04(self) -> None:
        for file in load_files("memcpy-04"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) > 0, "path(s) identified")
            for path in paths:
                self.assertIn(path.src_sym_name, ["getenv"], "source has symbol 'getenv'")
                self.assertTrue(
                    isinstance(path.insts[-1], bn.MediumLevelILInstruction),
                    "source is a MLIL instruction"
                )
                self.assertIn(path.snk_sym_name, ["memcpy"], "sink has symbol 'memcpy'")
                self.assertTrue(
                    (
                        isinstance(path.insts[0], bn.MediumLevelILCallSsa) or
                        isinstance(path.insts[0], bn.MediumLevelILTailcallSsa)
                    ),
                    "sink is a MLIL call instruction"
                )
                self.assertEqual(path.snk_par_idx, 2, "arg3")
                self.assertTrue(
                    isinstance(path.snk_par_var, bn.MediumLevelILVarSsa),
                    "argument is a MLIL variable"
                )
            # Close test binary
            bv.file.close()
        return
    
    def test_memcpy_05(self) -> None:
        for file in load_files("memcpy-05"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) > 0, "path(s) identified")
            for path in paths:
                self.assertIn(path.src_sym_name, ["getenv"], "source has symbol 'getenv'")
                self.assertTrue(
                    isinstance(path.insts[-1], bn.MediumLevelILInstruction),
                    "source is a MLIL instruction"
                )
                self.assertIn(path.snk_sym_name, ["memcpy"], "sink has symbol 'memcpy'")
                self.assertTrue(
                    (
                        isinstance(path.insts[0], bn.MediumLevelILCallSsa) or
                        isinstance(path.insts[0], bn.MediumLevelILTailcallSsa)
                    ),
                    "sink is a MLIL call instruction"
                )
                self.assertTrue(path.snk_par_idx in [1, 2], "arg2 or arg3")
                self.assertTrue(
                    isinstance(path.snk_par_var, bn.MediumLevelILVarSsa),
                    "argument is a MLIL variable"
                )
            # Close test binary
            bv.file.close()
        return
    
    def test_memcpy_06(self) -> None:
        for file in load_files("memcpy-06"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 0, "path(s) identified")
            # Close test binary
            bv.file.close()
        return
    
    def test_memcpy_07(self) -> None:
        for file in load_files("memcpy-07"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) > 0, "path(s) identified")
            for path in paths:
                self.assertIn(path.src_sym_name, ["getenv"], "source has symbol 'getenv'")
                self.assertTrue(
                    isinstance(path.insts[-1], bn.MediumLevelILInstruction),
                    "source is a MLIL instruction"
                )
                self.assertIn(path.snk_sym_name, ["memcpy"], "sink has symbol 'memcpy'")
                self.assertTrue(
                    (
                        isinstance(path.insts[0], bn.MediumLevelILCallSsa) or
                        isinstance(path.insts[0], bn.MediumLevelILTailcallSsa)
                    ),
                    "sink is a MLIL call instruction"
                )
                self.assertTrue(path.snk_par_idx in [1, 2], "arg2 or arg3")
                self.assertTrue(
                    isinstance(path.snk_par_var, bn.MediumLevelILVarSsa),
                    "argument is a MLIL variable"
                )
            # Close test binary
            bv.file.close()
        return
    
    @unittest.expectedFailure
    def test_memcpy_08(self) -> None:
        for file in load_files("memcpy-08"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 0, "path(s) identified")
            # Close test binary
            bv.file.close()
        return
    
    def test_memcpy_09(self) -> None:
        for file in load_files("memcpy-09"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 0, "path(s) identified")
            # Close test binary
            bv.file.close()
        return
    
    @unittest.expectedFailure
    def test_memcpy_10(self) -> None:
        for file in load_files("memcpy-10"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            # TODO: What should be the expected result?
            self.assertTrue(len(paths) == 0, "path(s) identified")
            bv.file.close()
        return
    
    def test_memcpy_11(self) -> None:
        for file in load_files("memcpy-11"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 0, "path(s) identified")
            bv.file.close()
        return
    

class TestSscanf(unittest.TestCase):
    """
    This class implements unit tests for `libc` function `sscanf`.
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
    
    def test_sscanf_01(self) -> None:
        for file in load_files("sscanf-01"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) > 0, "path(s) identified")
            for path in paths:
                self.assertIn(path.src_sym_name, ["getenv"], "source has symbol 'getenv'")
                self.assertTrue(
                    isinstance(path.insts[-1], bn.MediumLevelILInstruction),
                    "source is a MLIL instruction"
                )
                self.assertIn(path.snk_sym_name, ["sscanf", "__isoc99_sscanf"], "sink has symbol 'sscanf'")
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
    
class TestSystem(unittest.TestCase):
    """
    This class implements unit tests for `libc` function `system`.
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
    
    @unittest.expectedFailure
    def test_system_01(self) -> None:
        for file in load_files("system-01"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) > 0, "path(s) identified")
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
    
    def test_system_02(self) -> None:
        for file in load_files("system-02"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 1, "path(s) identified")
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
    
    def test_system_03(self) -> None:
        for file in load_files("system-03"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 1, "path(s) identified")
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