from __future__           import annotations
from mole.core.data       import Path
from mole.common.log      import Logger
from mole.models.config   import ConfigModel
from mole.services.config import ConfigService
from mole.services.slicer import MediumLevelILBackwardSlicerThread
from typing               import List
import binaryninja as bn
import os          as os
import unittest    as unittest


class TestCase(unittest.TestCase):
    """
    This class implements unit tests to test backward slicing for finding interesting code paths.
    """

    def setUp(self) -> None:
        self._tag = "Mole"
        self._log = Logger(level="debug", runs_headless=True)
        self._model = ConfigModel(ConfigService(f"{self._tag}.ConfigService", self._log).load_configuration())
        return
    
    @staticmethod
    def load_files(names: List[str]) -> List[str]:
        """
        This method returns all files in the `testcases` directory matching `name` but ignoring the
        file extension.
        """
        directory = os.path.join(os.path.dirname(__file__), "bin")
        files = []
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                if os.path.splitext(filename)[0] in names:
                    files.append(os.path.join(dirpath, filename))
        return files

    def get_paths(
            self,
            bv: bn.BinaryView,
            max_workers: int | None = -1,
            max_call_level: int = 3,
            max_slice_depth: int = -1,
            enable_all_funs: bool = True
        ) -> List[Path]:
        """
        This method is a helper to find paths.
        """
        slicer = MediumLevelILBackwardSlicerThread(
            bv=bv,
            model=self._model,
            tag=f"{self._tag:s}.Slicer",
            log=self._log,
            max_workers=max_workers,
            max_call_level=max_call_level,
            max_slice_depth=max_slice_depth,
            enable_all_funs=enable_all_funs
        )
        slicer.start()
        return slicer.get_paths()

class TestVarious(TestCase):
    
    def test_gets_01(
            self,
            filenames: List[str] = ["gets-01"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
            self.assertEqual(path.snk_par_idx, 1, "arg1")
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
            bv.file.close()
        return
    
    @unittest.expectedFailure
    def test_gets_02(
        self,
        filenames: List[str] = ["gets-02"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
            bv.file.close()
        return
    
    def test_sscanf_01(
            self,
            filenames: List[str] = ["sscanf-01"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
                self.assertEqual(path.snk_par_idx, 1, "arg1")
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
            bv.file.close()
        return
    
    def test_memcpy_01(
            self,
            filenames: List[str] = ["memcpy-01"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
            self.assertEqual(path.snk_par_idx, 3, "arg3")
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
            bv.file.close()
        return
    
    def test_memcpy_02(
            self,
            filenames: List[str] = ["memcpy-02"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
                self.assertTrue(path.snk_par_idx in [2, 3], "arg2 or arg3")
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
            bv.file.close()
        return
    
    def test_memcpy_03(
            self,
            filenames: List[str] = ["memcpy-03"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
            self.assertEqual(path.snk_par_idx, 1, "arg1")
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
            bv.file.close()
        return
    
    def test_memcpy_04(
            self,
            filenames: List[str] = ["memcpy-04"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
            self.assertEqual(path.snk_par_idx, 3, "arg3")
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
            bv.file.close()
        return
    
    def test_memcpy_05(
            self,
            filenames: List[str] = ["memcpy-05"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
                self.assertTrue(path.snk_par_idx in [2, 3], "arg2 or arg3")
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
            bv.file.close()
        return
    
    def test_memcpy_06(
            self,
            filenames: List[str] = ["memcpy-06"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertTrue(len(paths) == 0, "0 paths identified")
            bv.file.close()
        return
    
    def test_memcpy_07(
            self,
            filenames: List[str] = ["memcpy-07"]
        ) -> None:
        return self.test_memcpy_02(filenames)
    
    @unittest.expectedFailure
    def test_memcpy_08(
            self,
            filenames: List[str] = ["memcpy-08"]
        ) -> None:
        return self.test_memcpy_06(filenames)
    
    def test_memcpy_09(
            self,
            filenames: List[str] = ["memcpy-09"]
        ) -> None:
        return self.test_memcpy_06(filenames)
    
    @unittest.expectedFailure
    def test_memcpy_10(
            self,
            filenames: List[str] = ["memcpy-10"]
        ) -> None:
        return self.test_memcpy_06(filenames)
    
    def test_memcpy_11(
            self,
            filenames: List[str] = ["memcpy-11"]
        ) -> None:
        return self.test_memcpy_06(filenames)


class TestFunctionCalling(TestCase):
    
    def test_function_calling_01(
            self,
            filenames: List[str] = ["function_calling-01"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
                self.assertEqual(path.snk_par_idx, 1, "arg1")
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
            bv.file.close()
        return
    
    def test_function_calling_02(
            self,
            filenames: List[str] = ["function_calling-02"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = paths = self.get_paths(bv)
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
                self.assertEqual(path.snk_par_idx, 1, "arg1")
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
            bv.file.close()
        return
    
    def test_function_calling_03(
            self,
            filenames: List[str] = ["function_calling-03"]
        ) -> None:
        return self.test_function_calling_01(filenames)
    
    def test_function_calling_04(
            self,
            filenames: List[str] = ["function_calling-04"]
        ) -> None:
        return self.test_function_calling_02(filenames)
    
    def test_function_calling_05(
            self,
            filenames: List[str] = ["function_calling-05"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = paths = self.get_paths(bv)
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
            self.assertEqual(path.snk_par_idx, 1, "arg1")
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
            bv.file.close()
        return
    
    def test_function_calling_06(
            self,
            filenames: List[str] = ["function_calling-06"]
        ) -> None:
        return self.test_function_calling_05(filenames)
    
    def test_function_calling_07(
            self,
            filenames: List[str] = ["function_calling-07"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertTrue(len(paths) == 0, "0 paths identified")
            bv.file.close()
        return
    
    def test_function_calling_08(
            self,
            filenames: List[str] = ["function_calling-08"]
        ) -> None:
        return self.test_function_calling_07(filenames)


class TestPointerAnalysis(TestCase):
    
    def test_pointer_analysis_01(
            self,
            filenames: List[str] = ["pointer_analysis-01"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
            self.assertEqual(path.snk_par_idx, 1, "arg1")
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
            bv.file.close()
        return

    def test_pointer_analysis_02(
            self,
            filenames: List[str] = ["pointer_analysis-02"]
        ) -> None:
        return self.test_pointer_analysis_01(filenames)
    
    def test_pointer_analysis_03(
            self,
            filenames: List[str] = ["pointer_analysis-03"]
        ) -> None:
        return self.test_pointer_analysis_01(filenames)
    
    def test_pointer_analysis_04(
            self,
            filenames: List[str] = ["pointer_analysis-04"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
                    isinstance(path.insts[0], bn.MediumLevelILCallSsa),
                    "sink is a MLIL call instruction"
                )
                calls = [path.snk_sym_name]
                for inst in path.insts:
                    call = inst.function.source_function.name
                    if calls[-1] != call:
                        calls.append(call)
                calls.append(path.src_sym_name)
                self.assertEqual(calls, ["system", "main", "getenv"])
            bv.file.close()
        return
    
    def test_pointer_analysis_05(
            self,
            filenames: List[str] = ["pointer_analysis-05"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertTrue(len(paths) == 0, "0 paths identified")
            bv.file.close()
        return
    
    def test_pointer_analysis_06(
            self,
            filenames: List[str] = ["pointer_analysis-06"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
                    isinstance(path.insts[0], bn.MediumLevelILCallSsa),
                    "sink is a MLIL call instruction"
                )
                calls = [path.snk_sym_name]
                for inst in path.insts:
                    call = inst.function.source_function.name
                    if calls[-1] != call:
                        calls.append(call)
                calls.append(path.src_sym_name)
                self.assertEqual(calls, ["memcpy", "main", "modify_n", "getenv"])
            bv.file.close()
        return
    
    def test_pointer_analysis_07(
            self,
            filenames: List[str] = ["pointer_analysis-07"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertTrue(len(paths) == 1, "1 path identified")
            path = paths[0]
            self.assertEqual(path, Path.from_dict(bv, path.to_dict()), "serialization")
            self.assertIn(path.src_sym_name, ["getenv"], "source has symbol 'getenv'")
            self.assertTrue(
                isinstance(path.insts[-1], bn.MediumLevelILInstruction),
                "source is a MLIL instruction"
            )
            self.assertIn(path.snk_sym_name, ["memcpy"], "sink has symbol 'system'")
            self.assertTrue(
                (
                    isinstance(path.insts[0], bn.MediumLevelILCallSsa) or
                    isinstance(path.insts[0], bn.MediumLevelILTailcallSsa)
                ),
                "sink is a MLIL call instruction"
            )
            self.assertEqual(path.snk_par_idx, 2, "arg2")
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
            self.assertEqual(calls, ["memcpy", "main", "my_getenv", "getenv"], "call chain")
            bv.file.close()
        return
    
    def test_pointer_analysis_08(
            self,
            filenames: List[str] = ["pointer_analysis-08"]
        ) -> None:
        return self.test_pointer_analysis_07(filenames)
    
    def test_pointer_analysis_09(
            self,
            filenames: List[str] = ["pointer_analysis-09"]
        ) -> None:
        return self.test_pointer_analysis_01(filenames)
    
    def test_pointer_analysis_10(
            self,
            filenames: List[str] = ["pointer_analysis-10"]
        ) -> None:
        return self.test_pointer_analysis_01(filenames)


class TestSimpleServer(TestCase):
    
    def test_simple_http_server_01(
            self,
            filenames: List[str] = ["simple_http_server-01"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
                self.assertEqual(path.snk_par_idx, 1, "arg1")
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
            bv.file.close()
        return
    
    def test_simple_http_server_02(
            self,
            filenames: List[str] = ["simple_http_server-02"]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
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
                self.assertEqual(path.snk_par_idx, 1, "arg1")
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
            bv.file.close()
        return


class TestMultiThreading(TestCase):
    
    def test_consistency_01(
            self,
            filenames: List[str] = [
                "gets-01",
                "gets-02",
                "sscanf-01",
                "memcpy-01",
                "memcpy-02",
                "memcpy-03",
                "memcpy-04",
                "memcpy-05",
                "memcpy-06",
                "memcpy-07",
                "memcpy-08",
                "memcpy-09",
                "memcpy-10",
                "memcpy-11",
                "function_calling-01",
                "function_calling-02",
                "function_calling-03",
                "function_calling-04",
                "function_calling-05",
                "function_calling-06",
                "function_calling-07",
                "function_calling-08",
                "pointer_analysis-01",
                "pointer_analysis-02",
                "pointer_analysis-03",
                "pointer_analysis-04",
                "pointer_analysis-05",
                "pointer_analysis-06",
                "pointer_analysis-07",
                "pointer_analysis-08",
                "pointer_analysis-09",
                "pointer_analysis-10",
                "simple_http_server-01",
                "simple_http_server-02"
            ]
        ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Assert results
            paths = self.get_paths(bv, max_workers=1, max_call_level=3, enable_all_funs=True)
            for max_workers in [2, 4, 8, -1]:
                paths_mt = self.get_paths(bv, max_workers, max_call_level=3, enable_all_funs=True)
                self.assertCountEqual(paths, paths_mt, f"{max_workers:d} workers")
            # Close binary
            bv.file.close()
        return