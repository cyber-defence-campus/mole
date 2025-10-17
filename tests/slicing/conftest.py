from __future__ import annotations
from mole.common.log import log
from mole.core.data import Path
from mole.models.config import ConfigModel
from mole.services.config import ConfigService
from mole.services.path import PathService
from typing import List, Optional, Tuple
import atexit
import binaryninja as bn
import os
import pytest


tested_files = set()


def print_tested_files():
    print(f"\nTested slicing on {len(tested_files):d} files")
    return


atexit.register(print_tested_files)


class SlicingTestBase:
    """
    This class implements base functionality for slicing tests.
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        log.change_properties(level="debug", runs_headless=True)
        config = ConfigService().load_config()
        config.sources = {
            "libc": config.sources["libc"] if "libc" in config.sources else {}
        }
        config.sinks = {"libc": config.sinks["libc"] if "libc" in config.sinks else {}}
        self._model = ConfigModel(config)
        self._ext = os.environ.get("EXT", None)

    def load_files(self, names: List[str]) -> List[str]:
        """
        This method returns all files in the `testcases` directory matching `name` but ignoring the
        file extension.
        """
        directory = os.path.join(os.path.dirname(__file__), "..", "data", "bin")
        files = []
        all_matching_files = []  # Track all files that match by name

        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                name, ext = os.path.splitext(filename)
                if name in names:
                    all_matching_files.append(filename)
                    if self._ext is None or self._ext == ext:
                        files.append(os.path.join(dirpath, filename))
                        tested_files.add(filename)

        # Validate that we found files
        if not all_matching_files:
            raise FileNotFoundError(
                f"No test files found matching names: {names}. "
                f"Check that files exist in {directory}"
            )

        if self._ext is not None and not files:
            available_exts = set(os.path.splitext(f)[1] for f in all_matching_files)
            raise FileNotFoundError(
                f"No test files found with extension '{self._ext}' for names: {names}. "
                f"Available extensions: {sorted(available_exts)}"
            )

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
            assert sorted(_call_chains) == sorted(call_chains), (
                f"invalid call chains: expected {call_chains}, got {_call_chains}"
            )
            # Close test binary
            bv.file.close()
