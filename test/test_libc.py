from __future__      import annotations
from mole.common.log import Logger
from mole.plugin     import Plugin
import binaryninja   as bn
import os
import unittest


class TestMemcpy(unittest.TestCase):
    """
    This class implements unit tests for `libc` function `memcpy`.
    """

    def setUp(self) -> None:
        # Initialize plugin and logger to operate in headless mode
        self.plugin = Plugin(runs_headless=True, log=Logger(level="debug", runs_headless=True))
        return

    def test_memcpy_01(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "memcpy-01"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertTrue((
                isinstance(snk_inst, bn.MediumLevelILCallSsa) or
                isinstance(snk_inst, bn.MediumLevelILTailcallSsa)), "sink is a MLIL call instruction")
            self.assertEqual(par_num, 2, "arg3")
            self.assertTrue(isinstance(par_var, bn.MediumLevelILVarSsa), "argument is a MLIL variable")
        # Close test binary
        bv.file.close()
        return
    
    def test_memcpy_02(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "memcpy-02"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertTrue((
                isinstance(snk_inst, bn.MediumLevelILCallSsa) or
                isinstance(snk_inst, bn.MediumLevelILTailcallSsa)), "sink is a MLIL call instruction")
            self.assertTrue(par_num in [1, 2], "arg2 or arg3")
            self.assertTrue(isinstance(par_var, bn.MediumLevelILVarSsa), "argument is a MLIL variable")
        # Close test binary
        bv.file.close()
        return
    
    def test_memcpy_03(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "memcpy-03"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertTrue((
                isinstance(snk_inst, bn.MediumLevelILCallSsa) or
                isinstance(snk_inst, bn.MediumLevelILTailcallSsa)), "sink is a MLIL call instruction")
            self.assertEqual(par_num, 0, "arg1")
            self.assertTrue(isinstance(par_var, bn.MediumLevelILVarSsa), "argument is a MLIL variable")
        # Close test binary
        bv.file.close()
        return
    
    def test_memcpy_04(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "memcpy-04"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertTrue((
                isinstance(snk_inst, bn.MediumLevelILCallSsa) or
                isinstance(snk_inst, bn.MediumLevelILTailcallSsa)), "sink is a MLIL call instruction")
            self.assertEqual(par_num, 2, "arg3")
            self.assertTrue(isinstance(par_var, bn.MediumLevelILVarSsa), "argument is a MLIL variable")
        # Close test binary
        bv.file.close()
        return
    
    def test_memcpy_05(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "memcpy-05"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertTrue((
                isinstance(snk_inst, bn.MediumLevelILCallSsa) or
                isinstance(snk_inst, bn.MediumLevelILTailcallSsa)), "sink is a MLIL call instruction")
            self.assertTrue(par_num in [1, 2], "arg2 or arg3")
            self.assertTrue(isinstance(par_var, bn.MediumLevelILVarSsa), "argument is a MLIL variable")
        # Close test binary
        bv.file.close()
        return
    
    def test_memcpy_06(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "memcpy-06"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) == 0, "path(s) identified")
        # Close test binary
        bv.file.close()
        return
    
    def test_memcpy_07(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "memcpy-07"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertTrue((
                isinstance(snk_inst, bn.MediumLevelILCallSsa) or
                isinstance(snk_inst, bn.MediumLevelILTailcallSsa)), "sink is a MLIL call instruction")
            self.assertTrue(par_num in [1, 2], "arg2 or arg3")
            self.assertTrue(isinstance(par_var, bn.MediumLevelILVarSsa), "argument is a MLIL variable")
        # Close test binary
        bv.file.close()
        return
    
    @unittest.expectedFailure
    def test_memcpy_08(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "memcpy-08"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) == 0, "path(s) identified")
        # Close test binary
        bv.file.close()
        return
    
    def test_memcpy_09(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "memcpy-09"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) == 0, "path(s) identified")
        # Close test binary
        bv.file.close()
        return
    
    @unittest.expectedFailure
    def test_memcpy_10(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "memcpy-10"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        # TODO: What should be the expected result?
        self.assertTrue(len(paths) == 0, "path(s) identified")
        bv.file.close()
        return
    
    def test_memcpy_11(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "memcpy-11"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) == 0, "path(s) identified")
        bv.file.close()
        return
    

class TestSscanf(unittest.TestCase):
    """
    This class implements unit tests for `libc` function `sscanf`.
    """

    def setUp(self) -> None:
        # Initialize plugin and logger to operate in headless mode
        self.plugin = Plugin(runs_headless=True, log=Logger(level="debug", runs_headless=True))
        return
    
    def test_sscanf_01(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "sscanf-01"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "sscanf", "sink has symbol 'sscanf'")
            self.assertTrue((
                isinstance(snk_inst, bn.MediumLevelILCallSsa) or
                isinstance(snk_inst, bn.MediumLevelILTailcallSsa)), "sink is a MLIL call instruction")
            self.assertEqual(par_num, 0, "arg1")
            self.assertTrue(isinstance(par_var, bn.MediumLevelILVarSsa), "argument is a MLIL variable")
        # Close test binary
        bv.file.close()
        return
    

class TestGets(unittest.TestCase):
    """
    This class implements unit tests for `libc` function `gets`.
    """

    def setUp(self) -> None:
        # Initialize plugin and logger to operate in headless mode
        self.plugin = Plugin(runs_headless=True, log=Logger(level="debug", runs_headless=True))
        return

    def test_gets_01(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "gets-01"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "gets", "source has symbol 'gets'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "gets", "sink has symbol 'gets'")
            self.assertTrue((
                isinstance(snk_inst, bn.MediumLevelILCallSsa) or
                isinstance(snk_inst, bn.MediumLevelILTailcallSsa)), "sink is a MLIL call instruction")
            self.assertEqual(par_num, 0, "arg1")
            self.assertTrue(isinstance(par_var, bn.MediumLevelILVarSsa), "argument is a MLIL variable")
        # Close test binary
        bv.file.close()
        return
    
    @unittest.expectedFailure
    def test_gets_02(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "gets-02"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = self.plugin.analyze_binary(bv, max_func_depth=3, enable_all_funs=True)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        gets_memcpy_path = False
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "gets", "source has symbol 'gets'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertTrue(snk_name in ["gets", "memcpy"], "sink has symbol 'gets' or 'memcpy'")
            self.assertTrue(isinstance(snk_inst, bn.MediumLevelILCallSsa), "sink is a MLIL call instruction")
            if src_name == "gets" and snk_name == "memcpy":
                gets_memcpy_path = True
        self.assertTrue(gets_memcpy_path, "source 'gets' and sink 'memcpy'")
        # Close test binary
        bv.file.close()
        return