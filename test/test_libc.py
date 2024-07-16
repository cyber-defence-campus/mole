import binaryninja   as bn
import os
import unittest
from   mole.plugin import Plugin


class TestFromGetenvToMemcpy(unittest.TestCase):
    """
    This class implements unit tests for `libc` functions `getenv` (source) and `memcpy` (sink).
    """

    def test_memcpy_01(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "memcpy-01"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = Plugin.analyze_binary(bv)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertTrue(isinstance(snk_inst, bn.MediumLevelILCallSsa), "sink is a MLIL call instruction")
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
        paths = Plugin.analyze_binary(bv)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertTrue(isinstance(snk_inst, bn.MediumLevelILCallSsa), "sink is a MLIL call instruction")
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
        paths = Plugin.analyze_binary(bv)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertTrue(isinstance(snk_inst, bn.MediumLevelILCallSsa), "sink is a MLIL call instruction")
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
        paths = Plugin.analyze_binary(bv)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertTrue(isinstance(snk_inst, bn.MediumLevelILCallSsa), "sink is a MLIL call instruction")
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
        paths = Plugin.analyze_binary(bv)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertTrue(isinstance(snk_inst, bn.MediumLevelILCallSsa), "sink is a MLIL call instruction")
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
        paths = Plugin.analyze_binary(bv)
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
        paths = Plugin.analyze_binary(bv)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertTrue(isinstance(snk_inst, bn.MediumLevelILCallSsa), "sink is a MLIL call instruction")
            self.assertTrue(par_num in [1, 2], "arg2 or arg3")
            self.assertTrue(isinstance(par_var, bn.MediumLevelILVarSsa), "argument is a MLIL variable")
        # Close test binary
        bv.file.close()
        return
    

class TestFromGetenvToSscanf(unittest.TestCase):
    """
    This class implements unit tests for `libc` functions `getenv` (source) and `sscanf` (sink).
    """
    
    def test_sscanf_01(self) -> None:
        # Load and analyze test binary with Binary Ninja
        bv = bn.load(os.path.join(os.path.dirname(__file__), "testcases", "sscanf-01"))
        bv.update_analysis_and_wait()
        # Analyze test binary with plugin
        paths = Plugin.analyze_binary(bv)
        # Assert results
        self.assertTrue(len(paths) > 0, "path(s) identified")
        for src_name, src_inst, snk_name, snk_inst, par_num, par_var in paths:
            self.assertEqual(src_name, "getenv", "source has symbol 'getenv'")
            self.assertTrue(isinstance(src_inst, bn.MediumLevelILInstruction), "source is a MLIL instruction")
            self.assertEqual(snk_name, "sscanf", "sink has symbol 'sscanf'")
            self.assertTrue(isinstance(snk_inst, bn.MediumLevelILCallSsa), "sink is a MLIL call instruction")
            self.assertEqual(par_num, 0, "arg1")
            self.assertTrue(isinstance(par_var, bn.MediumLevelILVarSsa), "argument is a MLIL variable")
        # Close test binary
        bv.file.close()
        return