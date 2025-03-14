"""
Call graph grouping strategy implementation.
"""
from .source_sink import SourceSinkPathGrouper
from ..core.data import Path

class CallgraphPathGrouper(SourceSinkPathGrouper):
    """
    Grouping strategy that groups by source, sink, and same call graph.
    """
    
    def get_group_keys(self, path: Path):
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
