from __future__ import annotations
from mole.common.log import Logger
from mole.models.config import ConfigModel, TaintModelColumns
from mole.services.config import ConfigService
from mole.services.path import PathService
from typing import Callable, List, Tuple
import atexit
import binaryninja as bn
import os
import pytest


tested_files = set()
atexit_registered = False


def print_tested_files() -> None:
    print(f"\nTested slicing on {len(tested_files):d} files")
    return


if not atexit_registered:
    atexit.register(print_tested_files)
    atexit_registered = True


class TestSlicing:
    """
    This class implements general functionality for slicing tests.
    """

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self._config_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "../../mole/conf/003-libc.json"
        )
        self._ext = os.environ.get("EXT", None)
        return

    def load_files(self, names: List[str]) -> List[str]:
        """
        This method returns all files in the `testcases` directory matching `name` but ignoring the
        file extension.
        """
        directory = os.path.join(os.path.dirname(__file__), "..", "data", "bin")
        files = []
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                name, ext = os.path.splitext(filename)
                if name in names:
                    if self._ext is None or self._ext == ext:
                        files.append(os.path.join(dirpath, filename))
                        tested_files.add(filename)
        return files

    def assert_paths(
        self,
        srcs: List[Tuple[str, int | None]],
        snks: List[Tuple[str, int | None]],
        call_chains: List[List[str]],
        filenames: List[str],
        bv_callback: Callable[[bn.BinaryView], None] = lambda bv: None,
    ) -> None:
        # Logger
        log = Logger()
        # Configuration model
        model = ConfigModel(ConfigService(log).import_config(self._config_file))
        # Ensure relevant source functions are enabled
        src_names = [src[0] for src in srcs]
        src_funs = model.get_functions(
            lib_names=["libc"], fun_types=[TaintModelColumns.SOURCE]
        )
        for src_fun in src_funs:
            if src_fun.name in src_names:
                src_fun.src_enabled = True
        # Ensure relevant sink functions are enabled
        snk_names = [snk[0] for snk in snks]
        snk_funs = model.get_functions(
            lib_names=["libc"], fun_types=[TaintModelColumns.SINK]
        )
        for snk_fun in snk_funs:
            if snk_fun.name in snk_names:
                snk_fun.snk_enabled = True
        # Iterate over all test files
        for file in self.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            bv_callback(bv)
            # Find paths in test binary
            path_service = PathService(bv, log, model)
            path_service.find_paths(
                max_workers=1,
                max_call_level=5,
                max_slice_depth=-1,
                max_memory_slice_depth=-1,
            )
            paths = path_service.get_paths()
            # Determine call chains
            _call_chains = []
            for path in paths:
                _call_chains.append(
                    [call[0].source_function.symbol.short_name for call in path.calls]
                )
                # Assert source
                assert isinstance(
                    path.insts[-1],
                    bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa,
                ), "invalid source instruction type"
                assert (
                    path.src_sym_name,
                    path.src_par_idx,
                ) in srcs, "invalid source"
                # Assert sink
                assert isinstance(
                    path.insts[0],
                    bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa,
                ), "invalid sink instruction type"
                assert (
                    path.snk_sym_name,
                    path.snk_par_idx,
                ) in snks, "invalid sink"
            # Assert call chains
            for call_chain in call_chains:
                if call_chain in _call_chains:
                    _call_chains.remove(call_chain)
                else:
                    assert False, "invalid call chains"
            assert not _call_chains, "invalid call chains"
            # Close test binary
            bv.file.close()
        return
