from __future__ import annotations
from mole.common.log import log
from mole.core.data import Path
from mole.models.config import ConfigModel
from mole.services.config import ConfigService
from mole.services.path import PathService
from typing import List
import binaryninja as bn
import os as os
import unittest as unittest


class TestCase(unittest.TestCase):
    """
    This class implements unit tests to test backward slicing for finding interesting code paths.
    """

    def setUp(self) -> None:
        log.change_properties(level="debug", runs_headless=True)
        self._model = ConfigModel(ConfigService().load_config())
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
        enable_all_funs: bool = True,
    ) -> List[Path]:
        """
        This method is a helper to find paths.
        """
        slicer = PathService(
            bv=bv,
            config_model=self._model,
            max_workers=max_workers,
            max_call_level=max_call_level,
            max_slice_depth=max_slice_depth,
            enable_all_funs=enable_all_funs,
        )
        slicer.start()
        return slicer.paths()


class TestVarious(TestCase):
    def test_gets_01(self, filenames: List[str] = ["gets-01"]) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 1, "1 path identified")
            path = paths[0]

            self.assertEqual(path.src_sym_name, "gets", "source has symbol 'gets'")
            self.assertIsInstance(
                path.insts[-1],
                bn.Call,
                "source is a MLIL call instruction",
            )
            self.assertEqual(path.src_par_idx, 1, "arg1")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "source argument is a MLIL variable",
            )
            self.assertEqual(path.snk_sym_name, "gets", "sink has symbol 'gets'")
            self.assertIsInstance(
                path.insts[0],
                bn.Call,
                "sink is a MLIL call instruction",
            )
            self.assertEqual(path.snk_par_idx, 1, "arg1")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILInstruction,
                "sink argument is a MLIL variable",
            )
            calls = [call[1] for call in path.calls]
            self.assertEqual(calls, ["main"], "calls")
            bv.file.close()
        return

    def test_gets_02(self, filenames: List[str] = ["gets-02"]) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 2, "2 paths identified")
            # call_paths = []
            for path in paths:
                self.assertEqual(path.src_sym_name, "gets", "source has symbol 'gets'")
                self.assertIsInstance(
                    path.insts[-1],
                    bn.Call,
                    "source is a MLIL call instruction",
                )
                self.assertEqual(path.src_par_idx, 1, "arg1")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "source argument is a MLIL variable",
                )
                self.assertIn(
                    path.snk_sym_name,
                    ["gets", "memcpy"],
                    "sink has symbol 'gets' or 'memcpy'",
                )
                self.assertIsInstance(
                    path.insts[0],
                    bn.Call,
                    "sink is a MLIL call instruction",
                )
                calls = [call[1] for call in path.calls]
                self.assertEqual(calls, ["main"], "calls")
            bv.file.close()
        return

    def test_sscanf_01(self, filenames: List[str] = ["sscanf-01"]) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 1, "1 path identified")
            for path in paths:
                self.assertEqual(
                    path.src_sym_name, "getenv", "source has symbol 'getenv'"
                )
                self.assertIsInstance(
                    path.insts[-1],
                    bn.Call,
                    "source is a MLIL call instruction",
                )
                self.assertEqual(path.src_par_idx, None, "hit call instruction")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "source argument is a MLIL variable",
                )
                self.assertIn(
                    path.snk_sym_name,
                    ["sscanf", "__isoc99_sscanf"],
                    "sink has symbol 'sscanf'",
                )
                self.assertIsInstance(
                    path.insts[0],
                    bn.Call,
                    "sink is a MLIL call instruction",
                )
                self.assertEqual(path.snk_par_idx, 1, "arg1")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "sink argument is a MLIL variable",
                )
                calls = [call[1] for call in path.calls]
                self.assertEqual(calls, ["main"], "calls")
            bv.file.close()
        return

    def test_memcpy_01(self, filenames: List[str] = ["memcpy-01"]) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 1, "1 path identified")
            path = paths[0]

            self.assertEqual(path.src_sym_name, "getenv", "source has symbol 'getenv'")
            self.assertIsInstance(
                path.insts[-1],
                bn.Call,
                "source is a MLIL call instruction",
            )
            self.assertEqual(path.src_par_idx, None, "hit call instruction")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "source argument is a MLIL variable",
            )
            self.assertEqual(path.snk_sym_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertIsInstance(
                path.insts[0],
                bn.Call,
                "sink is a MLIL call instruction",
            )
            self.assertEqual(path.snk_par_idx, 3, "arg3")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "sink argument is a MLIL variable",
            )
            calls = [call[1] for call in path.calls]
            self.assertEqual(calls, ["main"], "calls")
            bv.file.close()
        return

    def test_memcpy_02(self, filenames: List[str] = ["memcpy-02"]) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 2, "2 paths identified")
            for path in paths:
                self.assertEqual(
                    path.src_sym_name, "getenv", "source has symbol 'getenv'"
                )
                self.assertIsInstance(
                    path.insts[-1],
                    bn.Call,
                    "source is a MLIL call instruction",
                )
                self.assertEqual(path.src_par_idx, None, "hit call instruction")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "source argument is a MLIL variable",
                )
                self.assertEqual(
                    path.snk_sym_name, "memcpy", "sink has symbol 'memcpy'"
                )
                self.assertIsInstance(
                    path.insts[0],
                    bn.Call,
                    "sink is a MLIL call instruction",
                )
                self.assertIn(path.snk_par_idx, [2, 3], "arg2 or arg3")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "sink argument is a MLIL variable",
                )
            bv.file.close()
        return

    def test_memcpy_03(self, filenames: List[str] = ["memcpy-03"]) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 1, "1 path identified")
            path = paths[0]

            self.assertEqual(path.src_sym_name, "getenv", "source has symbol 'getenv'")
            self.assertIsInstance(
                path.insts[-1],
                bn.Call,
                "source is a MLIL call instruction",
            )
            self.assertEqual(path.src_par_idx, None, "hit call instruction")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "source argument is a MLIL variable",
            )
            self.assertEqual(path.snk_sym_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertIsInstance(
                path.insts[0],
                bn.Call,
                "sink is a MLIL call instruction",
            )
            self.assertEqual(path.snk_par_idx, 1, "arg1")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "sink argument is a MLIL variable",
            )
            calls = [call[1] for call in path.calls]
            self.assertEqual(calls, ["main"], "calls")
            bv.file.close()
        return

    def test_memcpy_04(self, filenames: List[str] = ["memcpy-04"]) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 1, "1 path identified")
            path = paths[0]

            self.assertEqual(path.src_sym_name, "getenv", "source has symbol 'getenv'")
            self.assertIsInstance(
                path.insts[-1],
                bn.Call,
                "source is a MLIL call instruction",
            )
            self.assertEqual(path.src_par_idx, None, "hit call instruction")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "source argument is a MLIL variable",
            )
            self.assertEqual(path.snk_sym_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertIsInstance(
                path.insts[0],
                bn.Call,
                "sink is a MLIL call instruction",
            )
            self.assertEqual(path.snk_par_idx, 3, "arg3")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "sink argument is a MLIL variable",
            )
            calls = [call[1] for call in path.calls]
            self.assertEqual(calls, ["main", "my_getenv"], "calls")
            bv.file.close()
        return

    def test_memcpy_05(self, filenames: List[str] = ["memcpy-05"]) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 2, "2 paths identified")
            for path in paths:
                self.assertEqual(
                    path.src_sym_name, "getenv", "source has symbol 'getenv'"
                )
                self.assertIsInstance(
                    path.insts[-1],
                    bn.Call,
                    "source is a MLIL call instruction",
                )
                self.assertEqual(path.src_par_idx, None, "hit call instruction")
                self.assertEqual(
                    path.src_par_var, None, "source argument hit call instruction"
                )

                self.assertEqual(
                    path.snk_sym_name, "memcpy", "sink has symbol 'memcpy'"
                )
                self.assertIsInstance(
                    path.insts[0],
                    bn.Call,
                    "sink is a MLIL call instruction",
                )
                self.assertIn(path.snk_par_idx, [2, 3], "arg2 or arg3")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "sink argument is a MLIL variable",
                )
                calls = [call[1] for call in path.calls]
                self.assertEqual(calls, ["main", "my_getenv"], "calls")
            bv.file.close()
        return

    def test_memcpy_06(self, filenames: List[str] = ["memcpy-06"]) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 0, "0 paths identified")
            bv.file.close()
        return

    def test_memcpy_07(self, filenames: List[str] = ["memcpy-07"]) -> None:
        return self.test_memcpy_02(filenames)

    @unittest.expectedFailure
    def test_memcpy_08(self, filenames: List[str] = ["memcpy-08"]) -> None:
        return self.test_memcpy_06(filenames)

    def test_memcpy_09(self, filenames: List[str] = ["memcpy-09"]) -> None:
        return self.test_memcpy_06(filenames)

    @unittest.expectedFailure
    def test_memcpy_10(self, filenames: List[str] = ["memcpy-10"]) -> None:
        return self.test_memcpy_06(filenames)

    def test_memcpy_11(self, filenames: List[str] = ["memcpy-11"]) -> None:
        return self.test_memcpy_06(filenames)


class TestFunctionCalling(TestCase):
    def test_function_calling_01(
        self, filenames: List[str] = ["function_calling-01"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 2, "2 paths identified")
            for path in paths:
                self.assertEqual(
                    path.src_sym_name, "getenv", "source has symbol 'getenv'"
                )
                self.assertIsInstance(
                    path.insts[-1],
                    bn.Call,
                    "source is a MLIL call instruction",
                )
                self.assertEqual(path.src_par_idx, None, "hit call instruction")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "source argument is a MLIL variable",
                )
                self.assertEqual(
                    path.snk_sym_name, "system", "sink has symbol 'system'"
                )
                self.assertIsInstance(
                    path.insts[0],
                    bn.Call,
                    "sink is a MLIL call instruction",
                )
                self.assertEqual(path.snk_par_idx, 1, "arg1")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "sink argument is a MLIL variable",
                )
                calls = [call[1] for call in path.calls]
                self.assertNotIn("system_1b", calls, "system_1b not called")
                self.assertNotIn("getenv_1c", calls, "getenv_1c not called")
            bv.file.close()
        return

    def test_function_calling_02(
        self, filenames: List[str] = ["function_calling-02"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 2, "2 paths identified")
            call_paths = []
            for path in paths:
                self.assertEqual(
                    path.src_sym_name, "getenv", "source has symbol 'getenv'"
                )
                self.assertIsInstance(
                    path.insts[-1],
                    bn.Call,
                    "source is a MLIL call instruction",
                )
                self.assertEqual(path.src_par_idx, None, "hit call instruction")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "source argument is a MLIL variable",
                )
                self.assertEqual(
                    path.snk_sym_name, "system", "sink has symbol 'system'"
                )
                self.assertIsInstance(
                    path.insts[0],
                    bn.Call,
                    "sink is a MLIL call instruction",
                )
                self.assertEqual(path.snk_par_idx, 1, "arg1")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "sink argument is a MLIL variable",
                )
                calls = [call[1] for call in path.calls]
                call_paths.append(calls)
            self.assertCountEqual(
                call_paths,
                [
                    ["system_2", "system_1a", "main", "getenv_1a", "getenv_2"],
                    ["system_2", "system_1a", "main", "getenv_1b", "getenv_2"],
                ],
                "call paths",
            )
            bv.file.close()
        return

    def test_function_calling_03(
        self, filenames: List[str] = ["function_calling-03"]
    ) -> None:
        return self.test_function_calling_01(filenames)

    def test_function_calling_04(
        self, filenames: List[str] = ["function_calling-04"]
    ) -> None:
        return self.test_function_calling_02(filenames)

    def test_function_calling_05(
        self, filenames: List[str] = ["function_calling-05"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 1, "1 path identified")
            path = paths[0]

            self.assertEqual(path.src_sym_name, "getenv", "source has symbol 'getenv'")
            self.assertIsInstance(
                path.insts[-1],
                bn.Call,
                "source is a MLIL call instruction",
            )
            self.assertEqual(path.src_par_idx, None, "hit call instruction")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "source argument is a MLIL variable",
            )
            self.assertEqual(path.snk_sym_name, "system", "sink has symbol 'system'")
            self.assertIsInstance(
                path.insts[0],
                bn.Call,
                "sink is a MLIL call instruction",
            )
            self.assertEqual(path.snk_par_idx, 1, "arg1")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "sink argument is a MLIL variable",
            )
            calls = [call[1] for call in path.calls]
            self.assertEqual(calls, ["main", "func", "main"], "calls")
            bv.file.close()
        return

    def test_function_calling_06(
        self, filenames: List[str] = ["function_calling-06"]
    ) -> None:
        return self.test_function_calling_05(filenames)

    def test_function_calling_07(
        self, filenames: List[str] = ["function_calling-07"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 0, "0 paths identified")
            bv.file.close()
        return

    def test_function_calling_08(
        self, filenames: List[str] = ["function_calling-08"]
    ) -> None:
        return self.test_function_calling_07(filenames)


class TestPointerAnalysis(TestCase):
    def test_pointer_analysis_01(
        self, filenames: List[str] = ["pointer_analysis-01"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 1, "1 path identified")
            path = paths[0]

            self.assertEqual(path.src_sym_name, "getenv", "source has symbol 'getenv'")
            self.assertIsInstance(
                path.insts[-1],
                bn.Call,
                "source is a MLIL call instruction",
            )
            self.assertEqual(path.src_par_idx, None, "hit call instruction")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "source argument is a MLIL variable",
            )
            self.assertEqual(path.snk_sym_name, "system", "sink has symbol 'system'")
            self.assertIsInstance(
                path.insts[0],
                bn.Call,
                "sink is a MLIL call instruction",
            )
            self.assertEqual(path.snk_par_idx, 1, "arg1")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILInstruction,
                "sink argument is a MLIL variable",
            )
            calls = [call[1] for call in path.calls]
            self.assertEqual(calls, ["main"], "calls")
            bv.file.close()
        return

    def test_pointer_analysis_02(
        self, filenames: List[str] = ["pointer_analysis-02"]
    ) -> None:
        return self.test_pointer_analysis_01(filenames)

    def test_pointer_analysis_03(
        self, filenames: List[str] = ["pointer_analysis-03"]
    ) -> None:
        return self.test_pointer_analysis_01(filenames)

    def test_pointer_analysis_04(
        self, filenames: List[str] = ["pointer_analysis-04"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 2, "2 paths identified")
            for path in paths:
                self.assertEqual(
                    path.src_sym_name, "getenv", "source has symbol 'getenv'"
                )
                self.assertIsInstance(
                    path.insts[-1],
                    bn.Call,
                    "source is a MLIL call instruction",
                )
                self.assertEqual(path.src_par_idx, None, "hit call instruction")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "source argument is a MLIL variable",
                )
                self.assertEqual(
                    path.snk_sym_name, "system", "sink has symbol 'system'"
                )
                self.assertIsInstance(
                    path.insts[0],
                    bn.MediumLevelILCallSsa,
                    "sink is a MLIL call instruction",
                )
                calls = [call[1] for call in path.calls]
                self.assertEqual(calls, ["main"], "calls")
            bv.file.close()
        return

    def test_pointer_analysis_05(
        self, filenames: List[str] = ["pointer_analysis-05"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 0, "0 paths identified")
            bv.file.close()
        return

    def test_pointer_analysis_06(
        self, filenames: List[str] = ["pointer_analysis-06"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 2, "2 paths identified")
            for path in paths:
                self.assertEqual(
                    path.src_sym_name, "getenv", "source has symbol 'getenv'"
                )
                self.assertIsInstance(
                    path.insts[-1],
                    bn.Call,
                    "source is a MLIL call instruction",
                )
                self.assertEqual(path.src_par_idx, None, "hit call instruction")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "source argument is a MLIL variable",
                )
                self.assertEqual(
                    path.snk_sym_name, "memcpy", "sink has symbol 'memcpy'"
                )
                self.assertIsInstance(
                    path.insts[0],
                    bn.MediumLevelILCallSsa,
                    "sink is a MLIL call instruction",
                )
                calls = [call[1] for call in path.calls]
                self.assertEqual(calls, ["main", "modify_n"], "calls")
            bv.file.close()
        return

    def test_pointer_analysis_07(
        self, filenames: List[str] = ["pointer_analysis-07"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 1, "1 path identified")
            path = paths[0]

            self.assertEqual(path.src_sym_name, "getenv", "source has symbol 'getenv'")
            self.assertIsInstance(
                path.insts[-1],
                bn.Call,
                "source is a MLIL call instruction",
            )
            self.assertEqual(path.src_par_idx, None, "hit call instruction")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "source argument is a MLIL variable",
            )
            self.assertEqual(path.snk_sym_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertIsInstance(
                path.insts[0],
                bn.Call,
                "sink is a MLIL call instruction",
            )
            self.assertEqual(path.snk_par_idx, 2, "arg2")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "sink argument is a MLIL variable",
            )
            calls = [call[1] for call in path.calls]
            self.assertEqual(calls, ["main", "my_getenv"], "calls")
            bv.file.close()
        return

    def test_pointer_analysis_08(
        self, filenames: List[str] = ["pointer_analysis-08"]
    ) -> None:
        return self.test_pointer_analysis_07(filenames)

    def test_pointer_analysis_09(
        self, filenames: List[str] = ["pointer_analysis-09"]
    ) -> None:
        return self.test_pointer_analysis_01(filenames)

    def test_pointer_analysis_10(
        self, filenames: List[str] = ["pointer_analysis-10"]
    ) -> None:
        return self.test_pointer_analysis_01(filenames)

    @unittest.expectedFailure
    def test_pointer_analysis_11(
        self, filenames: List[str] = ["pointer_analysis-11"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 1, "1 path identified")
            path = paths[0]

            self.assertEqual(path.src_sym_name, "getenv", "source has symbol 'getenv'")
            self.assertIsInstance(
                path.insts[-1],
                bn.Call,
                "source is a MLIL call instruction",
            )
            self.assertEqual(path.src_par_idx, 1, "arg1")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "source argument is a MLIL variable",
            )
            self.assertEqual(path.snk_sym_name, "system", "sink has symbol 'system'")
            self.assertIsInstance(
                path.insts[0],
                bn.Call,
                "sink is a MLIL call instruction",
            )
            self.assertEqual(path.snk_par_idx, 1, "arg1")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "sink argument is a MLIL variable",
            )
            calls = [call[1] for call in path.calls]
            self.assertEqual(calls, ["execute", "validate", "execute", "main"], "calls")
            bv.file.close()
        return


class TestStruct(TestCase):
    @unittest.expectedFailure
    def test_struct_01(self, filenames: List[str] = ["struct-01"]) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 1, "1 path identified")
            path = paths[0]

            self.assertEqual(path.src_sym_name, "getenv", "source has symbol 'getenv'")
            self.assertIsInstance(
                path.insts[-1],
                bn.Call,
                "source is a MLIL call instruction",
            )
            self.assertEqual(path.src_par_idx, None, "hit call instruction")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILVarSsa,
                "source argument is a MLIL variable",
            )
            self.assertEqual(path.snk_sym_name, "memcpy", "sink has symbol 'memcpy'")
            self.assertIsInstance(
                path.insts[0],
                bn.Call,
                "sink is a MLIL call instruction",
            )
            self.assertEqual(path.snk_par_idx, 2, "arg2")
            self.assertIsInstance(
                path.snk_par_var,
                bn.MediumLevelILInstruction,
                "sink argument is a MLIL variable",
            )
            calls = [call[1] for call in path.calls]
            self.assertEqual(calls, ["main"], "calls")
            bv.file.close()
        return


class TestSimpleServer(TestCase):
    def test_simple_http_server_01(
        self, filenames: List[str] = ["simple_http_server-01"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 2, "2 paths identified")
            call_paths = []
            for path in paths:
                self.assertEqual(path.src_sym_name, "recv", "source has symbol 'recv'")
                self.assertIsInstance(
                    path.insts[-1],
                    bn.Call,
                    "source is a MLIL call instruction",
                )
                self.assertEqual(path.src_par_idx, 2, "arg2")
                self.assertIsInstance(
                    path.src_par_var,
                    bn.MediumLevelILVarSsa,
                    "source argument is a MLIL variable",
                )
                self.assertEqual(
                    path.snk_sym_name, "system", "sink has symbol 'system'"
                )
                self.assertIsInstance(
                    path.insts[0],
                    bn.Call,
                    "sink is a MLIL call instruction",
                )
                self.assertEqual(path.snk_par_idx, 1, "arg1")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "sink argument is a MLIL variable",
                )
                calls = [call[1] for call in path.calls]
                call_paths.append(calls)

            self.assertCountEqual(
                call_paths, [["handle_get_request"], ["handle_post_request"]], "calls"
            )
            bv.file.close()
        return

    def test_simple_http_server_02(
        self, filenames: List[str] = ["simple_http_server-02"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 2, "2 paths identified")
            call_paths = []
            for path in paths:
                self.assertEqual(path.src_sym_name, "recv", "source has symbol 'recv'")
                self.assertIsInstance(
                    path.insts[-1],
                    bn.Call,
                    "source is a MLIL call instruction",
                )
                self.assertEqual(path.src_par_idx, 2, "arg2")
                self.assertIsInstance(
                    path.src_par_var,
                    bn.MediumLevelILVarSsa,
                    "source argument is a MLIL variable",
                )
                self.assertEqual(
                    path.snk_sym_name, "system", "sink has symbol 'system'"
                )
                self.assertIsInstance(
                    path.insts[0],
                    bn.Call,
                    "sink is a MLIL call instruction",
                )
                self.assertEqual(path.snk_par_idx, 1, "arg1")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "sink argument is a MLIL variable",
                )
                calls = [call[1] for call in path.calls]
                call_paths.append(calls)
            self.assertCountEqual(
                call_paths,
                [
                    ["execute_cgi_command", "handle_get_request", "receive_data"],
                    ["execute_cgi_command", "handle_post_request", "receive_data"],
                ],
                "calls",
            )
            bv.file.close()
        return

    def test_simple_http_server_03(
        self, filenames: List[str] = ["simple_http_server-03"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertEqual(len(paths), 4, "4 paths identified")
            call_paths = []
            for path in paths:
                self.assertEqual(path.src_sym_name, "recv", "source has symbol 'recv'")
                self.assertIsInstance(
                    path.insts[-1],
                    bn.Call,
                    "source is a MLIL call instruction",
                )
                self.assertEqual(path.src_par_idx, 2, "arg2")
                self.assertIsInstance(
                    path.src_par_var,
                    bn.MediumLevelILVarSsa,
                    "source argument is a MLIL variable",
                )
                self.assertEqual(
                    path.snk_sym_name, "system", "sink has symbol 'system'"
                )
                self.assertIsInstance(
                    path.insts[0],
                    bn.Call,
                    "sink is a MLIL call instruction",
                )
                self.assertEqual(path.snk_par_idx, 1, "arg1")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "sink argument is a MLIL variable",
                )
                calls = [call[1] for call in path.calls]
                call_paths.append(calls)
            self.assertCountEqual(
                call_paths,
                [
                    [
                        "execute_cgi_command",
                        "wrap_and_execute",
                        "process_request",
                        "handle_get_request",
                        "receive_data",
                    ],
                    [
                        "execute_cgi_command",
                        "wrap_and_execute",
                        "process_request",
                        "handle_post_request",
                        "receive_data",
                    ],
                    [
                        "execute_cgi_command",
                        "wrap_and_execute",
                        "process_request",
                        "handle_put_request",
                        "receive_data",
                    ],
                    [
                        "execute_cgi_command",
                        "wrap_and_execute",
                        "process_request",
                        "handle_delete_request",
                        "receive_data",
                    ],
                ],
                "calls",
            )
            bv.file.close()
        return

    def test_simple_http_server_04(
        self, filenames: List[str] = ["simple_http_server-04"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            self.assertGreaterEqual(len(paths), 1, "at least 1 path identified")
            for path in paths:
                self.assertEqual(path.src_sym_name, "recv", "source has symbol 'recv'")
                self.assertIsInstance(
                    path.insts[-1],
                    bn.Call,
                    "source is a MLIL call instruction",
                )
                self.assertEqual(path.src_par_idx, 2, "arg2")
                self.assertIsInstance(
                    path.src_par_var,
                    bn.MediumLevelILVarSsa,
                    "source argument is a MLIL variable",
                )
                self.assertEqual(
                    path.snk_sym_name, "system", "sink has symbol 'system'"
                )
                self.assertIsInstance(
                    path.insts[0],
                    bn.Call,
                    "sink is a MLIL call instruction",
                )
                self.assertEqual(path.snk_par_idx, 1, "arg1")
                self.assertIsInstance(
                    path.snk_par_var,
                    bn.MediumLevelILVarSsa,
                    "sink argument is a MLIL variable",
                )
                calls = [call[1] for call in path.calls]
                self.assertEqual(
                    calls,
                    [
                        "execute_cgi_command",
                        "process_post_request",
                        "handle_post_request",
                        "receive_data",
                    ],
                )
            bv.file.close()
        return


class TestSerialization(TestCase):
    def test_serialization_01(
        self, filenames: List[str] = ["function_calling-02"]
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Analyze test binary
            paths = self.get_paths(bv)
            # Assert results
            for path in paths:
                self.assertEqual(
                    path, Path.from_dict(bv, path.to_dict()), "serialization"
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
            "simple_http_server-02",
        ],
    ) -> None:
        for file in TestCase.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Assert results
            paths = self.get_paths(
                bv, max_workers=1, max_call_level=3, enable_all_funs=True
            )
            for max_workers in [2, 4, 8, -1]:
                paths_mt = self.get_paths(
                    bv, max_workers, max_call_level=3, enable_all_funs=True
                )
                self.assertCountEqual(paths, paths_mt, f"{max_workers:d} workers")
            # Close binary
            bv.file.close()
        return
