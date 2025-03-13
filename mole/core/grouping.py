from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Tuple
from .data import Path

class PathGrouper(ABC):
    """
    Abstract base class for path grouping strategies.
    Implementations should provide logic for how paths are organized in a tree structure.
    """
    
    # Define strategy constants to replace the enum
    NONE = "None"
    CALLGRAPH = "Callgraph"
    
    @abstractmethod
    def get_group_keys(self, path: Path) -> List[Tuple[str, str, int]]:
        """
        Return a list of hierarchy keys for organizing paths.
        Each key is a tuple of (display_name, internal_id, level)
        The level indicates the depth in the tree (0=root, 1=first level, etc.)
        
        Args:
            path: Path object to be grouped
            
        Returns:
            List of tuples containing (display_name, internal_id, level)
        """
        pass
    
    @abstractmethod
    def get_strategy_name(self) -> str:
        """
        Return the name of this grouping strategy.
        Should match the corresponding strategy constant.
        """
        pass
    
    @staticmethod
    def create(strategy: str) -> PathGrouper:
        """
        Factory method to create a grouper based on the strategy.
        
        Args:
            strategy: The strategy name (use PathGrouper.NONE, PathGrouper.CALLGRAPH)
            
        Returns:
            An instance of the appropriate PathGrouper implementation
        """
        strategy_map = {
            PathGrouper.NONE: FlatPathGrouper(),
            PathGrouper.CALLGRAPH: CallgraphPathGrouper()
        }
        return strategy_map.get(strategy, CallgraphPathGrouper())  # Default to Callgraph


class FlatPathGrouper(PathGrouper):
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
        return PathGrouper.NONE


class CallgraphPathGrouper(PathGrouper):
    """
    Grouping strategy that groups by source, sink, and call graph.
    """
    
    def get_group_keys(self, path: Path) -> List[Tuple[str, str, int]]:
        """
        Group paths by source, sink, and call graph.
        """
        callgraph_name = self._format_callgraph_name(path)
        return [
            (f"Source: {path.src_sym_name}", path.src_sym_name, 0),
            (f"Sink: {path.snk_sym_name}", f"{path.src_sym_name}:{path.snk_sym_name}", 1),
            (f"Path: {callgraph_name}", f"{path.src_sym_name}:{path.snk_sym_name}:{callgraph_name}", 2)
        ]
    
    def get_strategy_name(self) -> str:
        return PathGrouper.CALLGRAPH
    
    def _format_callgraph_name(self, path: Path) -> str:
        """
        Format a readable call graph path from the path's call graph.
        """
        if not path.call_graph or not path.call_graph.nodes:
            return "Direct call"
            
        # Extract function names from the call graph
        func_names = []
        for node in path.call_graph.nodes:
            if path.call_graph.nodes[node]["in_path"]:
                func_names.append(node.source_function.name)
                
        # Format the call graph path
        if func_names:
            return " -> ".join(func_names)
        return "Unknown call path"
