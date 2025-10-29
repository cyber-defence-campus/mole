from __future__ import annotations
from mole.common.log import log
from mole.core.data import Path
from mole.models.config import ConfigModel
from mole.services.config import ConfigService
from mole.services.path import PathService
from typing import Callable, List, Optional, Tuple
import atexit
import binaryninja as bn
import os
import pytest


tested_files = set()
atexit_registered = False


def print_tested_files() -> None:
    if tested_files:  # Only print if we actually tested files
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

    def get_paths(
        self,
        bv: bn.BinaryView,
        max_workers: int | None = 1,
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
        bv_callback: Optional[Callable[[bn.BinaryView], None]] = lambda bv: None,
    ) -> None:
        for file in self.load_files(filenames):
            # Load and analyze test binary with Binary Ninja
            bv = bn.load(file)
            bv.update_analysis_and_wait()
            bv_callback(bv)
            # Find paths in test binary with backward slicing
            paths = self.get_paths(bv)
            # Determine call chains
            _call_chains = []
            for path in paths:
                _call_chains.append(
                    [call[1].source_function.symbol.short_name for call in path.calls]
                )
                # Assert source
                assert isinstance(
                    path.insts[-1],
                    bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa,
                ), "invalid source instruction type"
                assert (
                    path.src_sym_name,
                    path.src_par_idx,
                ) in src, "invalid source"
                # Assert sink
                assert isinstance(
                    path.insts[0],
                    bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa,
                ), "invalid sink instruction type"
                assert (
                    path.snk_sym_name,
                    path.snk_par_idx,
                ) in snk, "invalid sink"
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
