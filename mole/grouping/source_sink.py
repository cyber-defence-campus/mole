"""
This module implements a source / sink grouping strategy.
"""
from __future__  import annotations
from ..core.data import Path
from .           import PathGrouper
from typing      import List, Tuple


class SourceSinkPathGrouper(PathGrouper):
    """
    This class implements a strategy that groups by source and sink symbols.
    """
    
    def get_group_keys(self, path: Path, *args, **kwargs) -> List[Tuple[str, str, int]]:
        """
        This method groups paths by source and sink symbols.
        """
        return [
            (f"Source: {path.src_sym_name:s}", path.src_sym_name, 0),
            (f"Sink: {path.snk_sym_name:s}", f"{path.src_sym_name:s}:{path.snk_sym_name:s}", 1)
        ]
    
    def get_strategy_name(self) -> str:
        """
        This method returns the name of this grouping strategy.
        """
        return "Source / Sink"
