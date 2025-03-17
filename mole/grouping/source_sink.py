"""
Source / Sink grouping strategy implementation.
"""
from __future__  import annotations
from .           import PathGrouper
from ..core.data import Path
from typing      import List, Tuple


class SourceSinkPathGrouper(PathGrouper):
    """
    Grouping strategy that groups by source and sink symbols.
    """
    
    def get_group_keys(self, path: Path) -> List[Tuple[str, str, int]]:
        """
        Group paths by source and sink symbols.
        """
        return [
            (f"Source: {path.src_sym_name:s}", path.src_sym_name, 0),
            (f"Sink: {path.snk_sym_name:s}", f"{path.src_sym_name:s}:{path.snk_sym_name:s}", 1)
        ]
    
    def get_strategy_name(self) -> str:
        return "Source / Sink"
