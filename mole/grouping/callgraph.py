"""
Call graph grouping strategy implementation.
"""
from __future__   import annotations
from ..core.data  import Path
from .source_sink import SourceSinkPathGrouper


class CallgraphPathGrouper(SourceSinkPathGrouper):
    """
    Grouping strategy that groups by source and sink symbols, as well as same call graphs.
    """
    
    def get_group_keys(self, path: Path):
        """
        Group paths by source and sink symbols, as well as call graphs.
        """
        # TODO: Make `max_calls` a setting
        max_calls = 4
        calls = path.calls[1:-1]
        if len(calls) > max_calls:
            calls = calls[:int(max_calls/2)] + ["..."] + calls[int(-max_calls/2):]
        calls = " -> ".join(reversed(calls))
        keys = super().get_group_keys(path)
        keys.append((f"Path: {calls:s}", f"{path.src_sym_name:s}:{path.snk_sym_name}:{calls:s}", 2))
        return keys
    
    def get_strategy_name(self) -> str:
        return "Call Graph"