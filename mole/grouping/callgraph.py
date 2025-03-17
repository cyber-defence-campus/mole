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

    def _format_callgraph_name(self, path: Path) -> str:
        """
        Format a readable call graph path from the path's call graph.
        """
        return " -> ".join(reversed(path.calls))
    
    def get_group_keys(self, path: Path):
        """
        Group paths by source and sink symbols, as well as call graphs.
        """
        # Get source / sink grouping from parent class
        keys = super().get_group_keys(path)
        # Add call graph grouping
        callgraph_name = self._format_callgraph_name(path)
        keys.append((f"Path: {callgraph_name}", f"{path.src_sym_name}:{path.snk_sym_name}:{callgraph_name}", 2))
        return keys
    
    def get_strategy_name(self) -> str:
        return "Call Graph"