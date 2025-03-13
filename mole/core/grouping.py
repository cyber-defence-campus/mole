from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple
from .data import Path

class PathGrouper(ABC):
    """
    Abstract base class for path grouping strategies.
    Implementations should provide logic for how paths are organized in a tree structure.
    """
    
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
    
    # We no longer need the get_item_type_for_level method as we're using levels directly
    
    @staticmethod
    def create(strategy: str) -> PathGrouper:
        """
        Factory method to create a grouper based on the strategy.
        
        Args:
            strategy: The strategy name
            
        Returns:
            An instance of the appropriate PathGrouper implementation or None if the strategy is invalid
        """
        return PathGrouper.get_strategy_map().get(strategy, None)  # Default to Callgraph
    
    @staticmethod
    def get_strategy_map() -> Dict[str, PathGrouper]:
        """
        Returns a mapping of all available strategy names to their implementations.
        
        Returns:
            Dictionary mapping strategy names to PathGrouper instances
        """
        ssGrouper = SourceSinkPathGrouper()
        cgGrouper = CallgraphPathGrouper()
        phGrouper = PhiPathGrouper()
        return {
            "None": None,
            ssGrouper.get_strategy_name(): ssGrouper,
            cgGrouper.get_strategy_name(): cgGrouper,
            phGrouper.get_strategy_name(): phGrouper,
        }
    
    @staticmethod
    def get_all_strategies() -> List[str]:
        """
        Returns a list of all available strategy names.
        
        Returns:
            List of strategy names as strings
        """
        return list(PathGrouper.get_strategy_map().keys())


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


class CallgraphPathGrouper(SourceSinkPathGrouper):
    """
    Grouping strategy that groups by source, sink, and same call graph.
    """
    
    def get_group_keys(self, path: Path) -> List[Tuple[str, str, int]]:
        """
        Group paths by source, sink, and call graph.
        """
        # Get source-sink grouping from parent class
        keys = super().get_group_keys(path)
        
        # Add callgraph grouping
        callgraph_name = self._format_callgraph_name(path)
        keys.append((f"Path: {callgraph_name}", f"{path.src_sym_name}:{path.snk_sym_name}:{callgraph_name}", 2))
        
        return keys
    
    def get_strategy_name(self) -> str:
        return "Same Callgraph"
    
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

class PhiPathGrouper(CallgraphPathGrouper):
    """
    Grouping strategy that groups by source, sink, call graph, and phi value.
    """
    
    def get_group_keys(self, path: Path) -> List[Tuple[str, str, int]]:
        """
        Group paths by source, sink, call graph, and phi value.
        """
        # Get source-sink-callgraph grouping from parent class
        keys = super().get_group_keys(path)
        
        # Add phi value grouping
        phi_value = len(path.phiis)
        phi_display = f"φ: {phi_value}"
        base_id = f"{path.src_sym_name}:{path.snk_sym_name}:{self._format_callgraph_name(path)}"
        keys.append((phi_display, f"{base_id}:{phi_value}", 3))
        
        return keys
    
    def get_strategy_name(self) -> str:
        return "Phi Value"