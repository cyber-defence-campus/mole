"""
This module implements a call graph grouping strategy.
"""

from __future__ import annotations
from mole.core.data import Path
from mole.grouping.source_sink import SourceSinkPathGrouper


class CallgraphPathGrouper(SourceSinkPathGrouper):
    """
    This class implements a strategy that groups by source and sink symbols, as well as call graphs.
    """

    def get_group_keys(self, path: Path, *args, **kwargs):
        """
        This method groups paths by source and sink symbols, as well as call graphs.
        """
        max_calls = kwargs.get("max_calls", 6)
        calls = [call[1].source_function.symbol.short_name for call in path.calls]
        if len(calls) > max_calls:
            calls = calls[: int(max_calls / 2)] + ["..."] + calls[int(-max_calls / 2) :]
        calls = " - ".join(reversed(calls))
        keys = super().get_group_keys(path, *args, **kwargs)
        keys.append(
            (
                f"Calls: {calls:s}",
                f"{path.src_sym_name:s}:{path.snk_sym_name}:{calls:s}",
                2,
            )
        )
        return keys

    def get_strategy_name(self) -> str:
        """
        This method returns the name of this grouping strategy.
        """
        return "Call Graph"
