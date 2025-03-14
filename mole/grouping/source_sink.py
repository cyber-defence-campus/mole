"""
Source-Sink grouping strategy implementation.
"""
from typing import List, Tuple
from . import PathGrouper
from ..core.data import Path

class SourceSinkPathGrouper(PathGrouper):
    """
    Grouping strategy that only groups by source and sink, without call graph grouping.
    """
    
    def get_group_keys(self, path: Path) -> List[Tuple[str, str, int]]:
        """
        Group paths only by source and sink.
        """
        return [
            (f"Source: {path.src_sym_name}", path.src_sym_name, 0),
            (f"Sink: {path.snk_sym_name}", f"{path.src_sym_name}:{path.snk_sym_name}", 1)
        ]
    
    def get_strategy_name(self) -> str:
        return "Source - Sink"
