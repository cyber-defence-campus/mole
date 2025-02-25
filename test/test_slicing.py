from __future__           import annotations
from mole.common.log      import Logger
from mole.core.controller import Controller
from mole.core.data       import Path
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


class TestVarious(TestCase):
    
    def test_gets_01(
            self,
            filenames: List[str] = ["gets-01"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 1, "1 path identified")
            path = paths[0]
            self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
            calls = [path.snk_sym_name]
            for inst in path.insts:
                call = inst.function.source_function.name
                if calls[-1] != call:
                    calls.append(call)
            calls.append(path.src_sym_name)
            self.assertEqual(
                calls,
                ["gets", "main", "gets"],
                "call paths"
            )
            # Close test binary
            bv.file.close()
        return
    
    @unittest.expectedFailure
    def test_gets_02(
        self,
        filenames: List[str] = ["gets-02"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 2, "2 paths identified")
            call_paths = []
            for path in paths:
                self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
                calls = [path.snk_sym_name]
                for inst in path.insts:
                    call = inst.function.source_function.name
                    if calls[-1] != call:
                        calls.append(call)
                calls.append(path.src_sym_name)
                call_paths.append(calls)
            self.assertCountEqual(
                call_paths,
                [
                    [
                        "gets", "main", "gets"
                    ],
                    [
                        "gets", "main", "memcpy"
                    ]
                ],
                "call paths"
            )
            # Close test binary
            bv.file.close()
        return
    
    def test_sscanf_01(
            self,
            filenames: List[str] = ["sscanf-01"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 1, "1 path identified")
            for path in paths:
                self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
                calls = [path.snk_sym_name]
                for inst in path.insts:
                    call = inst.function.source_function.name
                    if calls[-1] != call:
                        calls.append(call)
                calls.append(path.src_sym_name)
                self.assertTrue(
                    calls == ["sscanf", "main", "getenv"] or
                    calls == ["__isoc99_sscanf", "main", "getenv"],
                    "call paths"
                )
            # Close test binary
            bv.file.close()
        return
    
    def test_memcpy_01(self) -> None:
        for file in load_files("memcpy-01"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 1, "1 path identified")
            path = paths[0]
            self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
            calls = [path.snk_sym_name]
            for inst in path.insts:
                call = inst.function.source_function.name
                if calls[-1] != call:
                    calls.append(call)
            calls.append(path.src_sym_name)
            self.assertEqual(
                calls,
                ["memcpy", "main", "getenv"],
                "call paths"
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
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 2, "2 paths identified")
            for path in paths:
                self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
                calls = [path.snk_sym_name]
                for inst in path.insts:
                    call = inst.function.source_function.name
                    if calls[-1] != call:
                        calls.append(call)
                calls.append(path.src_sym_name)
                self.assertEqual(
                    calls,
                    ["memcpy", "main", "getenv"],
                    "call paths"
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
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 1, "1 path identified")
            path = paths[0]
            self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
            calls = [path.snk_sym_name]
            for inst in path.insts:
                call = inst.function.source_function.name
                if calls[-1] != call:
                    calls.append(call)
            calls.append(path.src_sym_name)
            self.assertEqual(
                calls,
                ["memcpy", "main", "getenv"],
                "call paths"
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
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 1, "1 path identified")
            path = paths[0]
            self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
            calls = [path.snk_sym_name]
            for inst in path.insts:
                call = inst.function.source_function.name
                if calls[-1] != call:
                    calls.append(call)
            calls.append(path.src_sym_name)
            self.assertEqual(
                calls,
                ["memcpy", "main", "my_getenv", "getenv"],
                "call paths"
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
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 2, "2 paths identified")
            for path in paths:
                self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
                calls = [path.snk_sym_name]
                for inst in path.insts:
                    call = inst.function.source_function.name
                    if calls[-1] != call:
                        calls.append(call)
                calls.append(path.src_sym_name)
                self.assertEqual(
                    calls,
                    ["memcpy", "main", "my_getenv", "getenv"],
                    "call paths"
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
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
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
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 2, "2 paths identified")
            for path in paths:
                self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
                calls = [path.snk_sym_name]
                for inst in path.insts:
                    call = inst.function.source_function.name
                    if calls[-1] != call:
                        calls.append(call)
                calls.append(path.src_sym_name)
                self.assertEqual(
                    calls,
                    ["memcpy", "main", "getenv"],
                    "call paths"
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
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 0, "0 paths identified")
            # Close test binary
            bv.file.close()
        return
    
    def test_memcpy_09(self) -> None:
        for file in load_files("memcpy-09"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 0, "0 paths identified")
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
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 0, "0 paths identified")
            bv.file.close()
        return
    
    def test_memcpy_11(self) -> None:
        for file in load_files("memcpy-11"):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 0, "0 paths identified")
            bv.file.close()
        return


class TestFunctionCalling(TestCase):
    
    def test_function_calling_01(
            self,
            filenames: List[str] = ["function_calling-01"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 2, "2 paths identified")
            for path in paths:
                self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
                self.assertTrue("system_1b" not in calls, "system_1b not called")
                self.assertTrue("getenv_1c" not in calls, "getenv_1c not called")
            # Close test binary
            bv.file.close()
        return
    
    def test_function_calling_02(
            self,
            filenames: List[str] = ["function_calling-02"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 2, "2 paths identified")
            call_paths = []
            for path in paths:
                self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
                call_paths.append(calls)
            self.assertCountEqual(
                call_paths,
                [
                    [
                        "system", "system_2", "system_1a", "main", "getenv_1a", "getenv_2", "getenv"
                    ],
                    [
                        "system", "system_2", "system_1a", "main", "getenv_1b", "getenv_2", "getenv"
                    ]
                ],
                "call paths"
            )
            # Close test binary
            bv.file.close()
        return
    
    def test_function_calling_03(
            self,
            filenames: List[str] = ["function_calling-03"]
        ) -> None:
        self.test_function_calling_01(filenames)
        return
    
    def test_function_calling_04(
            self,
            filenames: List[str] = ["function_calling-04"]
        ) -> None:
        self.test_function_calling_02(filenames)
        return
    
    def test_function_calling_05(
            self,
            filenames: List[str] = ["function_calling-05"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 1, "1 path identified")
            path = paths[0]
            self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
            self.assertEqual(
                calls,
                ["system", "main", "func", "main", "getenv"]
            )
            # Close test binary
            bv.file.close()
        return
    
    def test_function_calling_06(
            self,
            filenames: List[str] = ["function_calling-06"]
        ) -> None:
        self.test_function_calling_05(filenames)
        return
    
    def test_function_calling_07(
            self,
            filenames: List[str] = ["function_calling-07"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 0, "0 paths identified")
            # Close test binary
            bv.file.close()
        return
    
    def test_function_calling_08(
            self,
            filenames: List[str] = ["function_calling-08"]
        ) -> None:
        self.test_function_calling_07(filenames)
        return


class TestPointerAnalysis(TestCase):
    
    def test_pointer_analysis_01(
            self,
            filenames: List[str] = ["pointer_analysis-01"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 1, "1 path identified")
            path = paths[0]
            self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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

    def test_pointer_analysis_02(
            self,
            filenames: List[str] = ["pointer_analysis-02"]
        ) -> None:
        self.test_pointer_analysis_01(filenames)
        return
    
    def test_pointer_analysis_03(
            self,
            filenames: List[str] = ["pointer_analysis-03"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertEqual(1, len(paths), "paths number not correctly identified")
            path = paths[0]
            self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
    
    def test_pointer_analysis_04(
            self,
            filenames: List[str] = ["pointer_analysis-04"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertEqual(2, len(paths), "paths number not correctly identified")
            first_path = paths[0]
            self.assertIn(first_path.src_sym_name, ["getenv"], "source has symbol 'getenv'")
            self.assertIn(first_path.snk_sym_name, ["system"], "sink has symbol 'system'")
            second_path = paths[1]
            self.assertIn(second_path.src_sym_name, ["getenv"], "source has symbol 'getenv'")
            self.assertIn(second_path.snk_sym_name, ["system"], "sink has symbol 'system'")

            # Close test binary
            bv.file.close()
        return


class TestSimpleServer(TestCase):
    
    def test_simple_http_server_01(
            self,
            filenames: List[str] = ["simple_http_server-01"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 2, "2 paths identified")
            call_paths = []
            for path in paths:
                self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
                calls = [path.snk_sym_name]
                for inst in path.insts:
                    call = inst.function.source_function.name
                    if calls[-1] != call:
                        calls.append(call)
                calls.append(path.src_sym_name)
                call_paths.append(calls)
            self.assertCountEqual(
                call_paths,
                [
                    [
                        "system",
                        "handle_get_request",
                        "recv"
                    ],
                    [
                        "system",
                        "handle_post_request",
                        "recv"
                    ]
                ],
                "call paths"
            )
            # Close test binary
            bv.file.close()
        return
    
    def test_simple_http_server_02(
            self,
            filenames: List[str] = ["simple_http_server-02"]
        ) -> None:
        for file in load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.ctr.find_paths(bv, max_call_level=3, enable_all_funs=True)
            # Assert results
            self.assertTrue(len(paths) == 2, "2 paths identified")
            call_paths = []
            for path in paths:
                self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
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
                calls = [path.snk_sym_name]
                for inst in path.insts:
                    call = inst.function.source_function.name
                    if calls[-1] != call:
                        calls.append(call)
                calls.append(path.src_sym_name)
                call_paths.append(calls)
            self.assertCountEqual(
                call_paths,
                [
                    [
                        "system",
                        "execute_cgi_command",
                        "handle_get_request",
                        "receive_data",
                        "recv"
                    ],
                    [
                        "system",
                        "execute_cgi_command",
                        "handle_post_request",
                        "receive_data",
                        "recv"
                    ]
                ],
                "call paths"
            )
            # Close test binary
            bv.file.close()
        return