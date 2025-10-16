from __future__ import annotations
from mole.common.log import log
from mole.core.data import Path
from mole.models.config import ConfigModel
from mole.services.config import ConfigService
from mole.services.path import PathService
from typing import List, Optional, Tuple
import atexit
import binaryninja as bn
import os as os
import unittest as unittest


tested_files = set()


def print_tested_files():
    print(f"\nTested slicing on {len(tested_files):d} files")
    return


atexit.register(print_tested_files)


class TestCase(unittest.TestCase):
    """
    This class implements unit tests to test backward slicing for finding interesting code paths.
    """

    def setUp(self) -> None:
        log.change_properties(level="debug", runs_headless=True)
        config = ConfigService().load_config()
        config.sources = {
            "libc": config.sources["libc"] if "libc" in config.sources else {}
        }
        config.sinks = {"libc": config.sinks["libc"] if "libc" in config.sinks else {}}
        self._model = ConfigModel(config)
        self._ext = os.environ.get("EXT", None)
        return

    def load_files(self, names: List[str]) -> List[str]:
        """
        This method returns all files in the `testcases` directory matching `name` but ignoring the
        file extension.
        """
        directory = os.path.join(os.path.dirname(__file__), "bin")
        files = []
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                name, ext = os.path.splitext(filename)
                if name in names:
                    if self._ext is None or self._ext == ext:
                        files.append(os.path.join(dirpath, filename))
                        tested_files.add(filename)
        return files

    def get_paths(
        self,
        bv: bn.BinaryView,
        max_workers: int | None = -1,
        max_call_level: int = 5,
        max_slice_depth: int = -1,
        max_memory_slice_depth: int = -1,
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
            max_memory_slice_depth=max_memory_slice_depth,
            enable_all_funs=enable_all_funs,
        )
        slicer.start()
        return slicer.paths()

    def assert_paths(
        self,
        src: List[Tuple[str, Optional[int]]],
        snk: List[Tuple[str, Optional[int]]],
        call_chains: List[List[str]],
        filenames: List[str],
    ) -> None:
        for file in self.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Find paths in test binary with backward slicing
            paths = self.get_paths(bv)
            # Determine call chains
            _call_chains = []
            for path in paths:
                _call_chains.append(
                    [call[1].source_function.symbol.short_name for call in path.calls]
                )
                # Assert source
                self.assertIsInstance(
                    path.insts[-1],
                    bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa,
                    "invalid source instruction type",
                )
                self.assertIn(
                    (path.src_sym_name, path.src_par_idx), src, "invalid source"
                )
                # Assert sink
                self.assertIsInstance(
                    path.insts[0],
                    bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa,
                    "invalid sink instruction type",
                )
                self.assertIn(
                    (path.snk_sym_name, path.snk_par_idx), snk, "invalid sink"
                )
            # Assert call chains
            self.assertCountEqual(_call_chains, call_chains, "invalid call chains")
            # Close test binary
            bv.file.close()
        return


class TestVarious(TestCase):
    def test_gets_01(self, filenames: List[str] = ["gets-01"]) -> None:
        self.assert_paths(
            src=[("gets", 1)],
            snk=[("gets", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_gets_02(self, filenames: List[str] = ["gets-02"]) -> None:
        self.assert_paths(
            src=[("gets", 1)],
            snk=[("gets", 1), ("memcpy", 2)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return

    def test_sscanf_01(self, filenames: List[str] = ["sscanf-01"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("sscanf", 1), ("__isoc99_sscanf", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_memcpy_01(self, filenames: List[str] = ["memcpy-01"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 3)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_memcpy_02(self, filenames: List[str] = ["memcpy-02"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 2), ("memcpy", 3)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return

    def test_memcpy_03(self, filenames: List[str] = ["memcpy-03"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_memcpy_04(self, filenames: List[str] = ["memcpy-04"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 3)],
            call_chains=[["main", "my_getenv"]],
            filenames=filenames,
        )
        return

    def test_memcpy_05(self, filenames: List[str] = ["memcpy-05"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 2), ("memcpy", 3)],
            call_chains=[["main", "my_getenv"], ["main", "my_getenv"]],
            filenames=filenames,
        )
        return

    def test_memcpy_06(self, filenames: List[str] = ["memcpy-06"]) -> None:
        self.assert_paths(
            src=[],
            snk=[],
            call_chains=[],
            filenames=filenames,
        )
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
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return

    def test_function_calling_02(
        self, filenames: List[str] = ["function_calling-02"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[
                ["system_2", "system_1a", "main", "getenv_1a", "getenv_2"],
                ["system_2", "system_1a", "main", "getenv_1b", "getenv_2"],
            ],
            filenames=filenames,
        )
        return

    def test_function_calling_03(
        self, filenames: List[str] = ["function_calling-03"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[
                ["system_1a", "main", "getenv_1a"],
                ["system_1a", "main", "getenv_1b"],
            ],
            filenames=filenames,
        )
        return

    def test_function_calling_04(
        self, filenames: List[str] = ["function_calling-04"]
    ) -> None:
        return self.test_function_calling_02(filenames)

    def test_function_calling_05(
        self, filenames: List[str] = ["function_calling-05"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_function_calling_06(
        self, filenames: List[str] = ["function_calling-06"]
    ) -> None:
        return self.test_function_calling_05(filenames)

    def test_function_calling_07(
        self, filenames: List[str] = ["function_calling-07"]
    ) -> None:
        self.assert_paths(
            src=[],
            snk=[],
            call_chains=[],
            filenames=filenames,
        )
        return

    def test_function_calling_08(
        self, filenames: List[str] = ["function_calling-08"]
    ) -> None:
        return self.test_function_calling_07(filenames)

    def test_function_calling_09(
        self, filenames: List[str] = ["function_calling-09"]
    ) -> None:
        return self.test_function_calling_05(filenames)

    def test_function_calling_10(
        self, filenames: List[str] = ["function_calling-10"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["system_1", "main", "getenv_1", "getenv_2"]],
            filenames=filenames,
        )
        return

    def test_function_calling_11(
        self, filenames: List[str] = ["function_calling-11"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main", "getenv_1", "getenv_2"]],
            filenames=filenames,
        )
        return

    def test_function_calling_12(
        self, filenames: List[str] = ["function_calling-12"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main", "getenv_1", "getenv_2", "getenv_3", "getenv_4"]],
            filenames=filenames,
        )
        return

    def test_function_calling_13(
        self, filenames: List[str] = ["function_calling-13"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["system_1", "main"]],
            filenames=filenames,
        )
        return

    def test_function_calling_14(
        self, filenames: List[str] = ["function_calling-14"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["system_3", "system_2", "system_1", "main"]],
            filenames=filenames,
        )
        return

    def test_function_calling_15(
        self, filenames: List[str] = ["function_calling-15"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["system_2", "system_1", "main", "getenv_1", "getenv_2"]],
            filenames=filenames,
        )
        return


class TestPointerAnalysis(TestCase):
    def test_pointer_analysis_01(
        self, filenames: List[str] = ["pointer_analysis-01"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
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
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return

    def test_pointer_analysis_05(
        self, filenames: List[str] = ["pointer_analysis-05"]
    ) -> None:
        self.assert_paths(
            src=[],
            snk=[],
            call_chains=[],
            filenames=filenames,
        )
        return

    def test_pointer_analysis_06(
        self, filenames: List[str] = ["pointer_analysis-06"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 3)],
            call_chains=[["main", "modify_n"], ["main", "modify_n"]],
            filenames=filenames,
        )
        return

    def test_pointer_analysis_07(
        self, filenames: List[str] = ["pointer_analysis-07"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 2)],
            call_chains=[["main", "my_getenv"]],
            filenames=filenames,
        )
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

    def test_pointer_analysis_11(
        self, filenames: List[str] = ["pointer_analysis-11"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["execute", "main"]],
            filenames=filenames,
        )
        return

    def test_pointer_analysis_12(
        self, filenames: List[str] = ["pointer_analysis-12"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"], ["main"]],
            filenames=filenames,
        )
        return

    @unittest.expectedFailure
    def test_pointer_analysis_13(
        self, filenames: List[str] = ["pointer_analysis-13"]
    ) -> None:
        return self.test_pointer_analysis_12(filenames)

    def test_pointer_analysis_14(
        self, filenames: List[str] = ["pointer_analysis-14"]
    ) -> None:
        return self.test_pointer_analysis_01(filenames)

    @unittest.expectedFailure
    def test_pointer_analysis_15(
        self, filenames: List[str] = ["pointer_analysis-15"]
    ) -> None:
        self.assert_paths(
            src=[("getopt", 2)],
            snk=[("strcpy", 2)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return


class TestLoad(TestCase):
    def test_load_01(self, filenames: List[str] = ["load-01"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return

    def test_load_02(self, filenames: List[str] = ["load-02"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return


class TestStruct(TestCase):
    @unittest.expectedFailure
    def test_struct_01(self, filenames: List[str] = ["struct-01"]) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("memcpy", 2)],
            call_chains=[["main"]],
            filenames=filenames,
        )
        return


class TestNameMangling(TestCase):
    def test_name_mangling_01(
        self, filenames: List[str] = ["name_mangling-01"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["overloaded_func", "main"], ["overloaded_func", "main"]],
            filenames=filenames,
        )
        return

    def test_name_mangling_02(
        self, filenames: List[str] = ["name_mangling-02"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["MyStruct::my_func", "main"], ["MyClass::my_func", "main"]],
            filenames=filenames,
        )
        return

    def test_name_mangling_03(
        self, filenames: List[str] = ["name_mangling-03"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["ns::my_func", "main"]],
            filenames=filenames,
        )
        return

    def test_name_mangling_04(
        self, filenames: List[str] = ["name_mangling-04"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["my_func<int>", "main"]],
            filenames=filenames,
        )
        return

    @unittest.expectedFailure
    def test_name_mangling_05(
        self, filenames: List[str] = ["name_mangling-05"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[
                ["MyStruct::my_func", "_GLOBAL__sub_I__ZN8MyStruct3cmdE"],
                ["MyClass::my_func", "_GLOBAL__sub_I__ZN8MyStruct3cmdE"],
            ],
            filenames=filenames,
        )
        return

    @unittest.expectedFailure
    def test_name_mangling_06(
        self, filenames: List[str] = ["name_mangling-06"]
    ) -> None:
        self.assert_paths(
            src=[("getenv", None)],
            snk=[("system", 1)],
            call_chains=[["MyStruct::my_func", "main", "MyStruct::operator+"]],
            filenames=filenames,
        )
        return


class TestSimpleServer(TestCase):
    def test_simple_http_server_01(
        self, filenames: List[str] = ["simple_http_server-01"]
    ) -> None:
        self.assert_paths(
            src=[("recv", 2)],
            snk=[("system", 1)],
            call_chains=[["handle_get_request"], ["handle_post_request"]],
            filenames=filenames,
        )
        return

    def test_simple_http_server_02(
        self, filenames: List[str] = ["simple_http_server-02"]
    ) -> None:
        self.assert_paths(
            src=[("recv", 2)],
            snk=[("system", 1)],
            call_chains=[
                ["execute_cgi_command", "handle_get_request", "receive_data"],
                ["execute_cgi_command", "handle_post_request", "receive_data"],
            ],
            filenames=filenames,
        )
        return

    def test_simple_http_server_03(
        self, filenames: List[str] = ["simple_http_server-03"]
    ) -> None:
        self.assert_paths(
            src=[("recv", 2)],
            snk=[("system", 1)],
            call_chains=[
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
            filenames=filenames,
        )
        return

    def test_simple_http_server_04(
        self, filenames: List[str] = ["simple_http_server-04"]
    ) -> None:
        self.assert_paths(
            src=[("recv", 2)],
            snk=[("system", 1)],
            call_chains=[
                [
                    "execute_cgi_command",
                    "process_post_request",
                    "handle_post_request",
                    "receive_data",
                ],
                [
                    "execute_cgi_command",
                    "process_post_request",
                    "handle_post_request",
                    "receive_data",
                ],
                [
                    "execute_cgi_command",
                    "process_post_request",
                    "handle_post_request",
                    "receive_data",
                ],
                [
                    "execute_cgi_command",
                    "process_post_request",
                    "handle_post_request",
                    "receive_data",
                ],
            ],
            filenames=filenames,
        )
        return


class TestSerialization(TestCase):
    def test_serialization_01(
        self, filenames: List[str] = ["function_calling-02"]
    ) -> None:
        for file in self.load_files(filenames):
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
            "fread-01",
            "function_calling-01",
            "function_calling-02",
            "function_calling-03",
            "function_calling-04",
            "function_calling-05",
            "function_calling-06",
            "function_calling-07",
            "function_calling-08",
            "function_calling-09",
            "function_calling-10",
            "function_calling-11",
            "function_calling-12",
            "function_calling-13",
            "function_calling-14",
            "function_calling-15",
            "gets-01",
            "gets-02",
            "load-01",
            "laod-02",
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
            "name_mangling-01",
            "name_mangling-02",
            "name_mangling-03",
            "name_mangling-04",
            "name_mangling-05",
            "name_mangling-06",
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
            "pointer_analysis-11",
            "pointer_analysis-12",
            "pointer_analysis-13",
            "pointer_analysis-14",
            "pointer_analysis-15",
            "simple_http_server-01",
            "simple_http_server-02",
            "simple_http_server-03",
            "simple_http_server-04",
            "sscanf-01",
            "struct-01",
        ],
    ) -> None:
        for file in self.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            # Assert results
            paths = self.get_paths(bv, max_workers=1, enable_all_funs=True)
            for max_workers in [2, 4, 8, -1]:
                paths_mt = self.get_paths(bv, max_workers, enable_all_funs=True)
                self.assertCountEqual(paths, paths_mt, f"{max_workers:d} workers")
            # Close binary
            bv.file.close()
        return
