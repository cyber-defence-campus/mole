"""
This module implements a call graph grouping strategy.
"""
from __future__   import annotations
from ..core.data  import Path
from .source_sink import SourceSinkPathGrouper


class CallgraphPathGrouper(SourceSinkPathGrouper):
    """
    This class implements a strategy that groups by source and sink symbols, as well as call graphs.
    """
    
    def get_group_keys(self, path: Path):
        """
        This method groups paths by source and sink symbols, as well as call graphs.
        """
        # TODO: Make `max_calls` a setting
        max_calls = 4
        calls = [call[1] for call in path.calls[1:-1]]
        if len(calls) > max_calls:
            calls = calls[:int(max_calls/2)] + ["..."] + calls[int(-max_calls/2):]
        calls = " -> ".join(reversed(calls))
        keys = super().get_group_keys(path)
        keys.append((f"Path: {calls:s}", f"{path.src_sym_name:s}:{path.snk_sym_name}:{calls:s}", 2))
        return keys
    
    def get_strategy_name(self) -> str:
        """
        This method returns the name of this grouping strategy.
        """
        return "Call Graph"