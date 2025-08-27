from __future__ import annotations
from mole.common.helper.function import FunctionHelper
from typing import Any, Dict, List, Optional, Type
import binaryninja as bn
import networkx as nx


class MediumLevelILFunctionGraph(nx.DiGraph):
    """
    This class represents a directed graph that stores a `MediumLevelILFunction` call graph.
    """

    def add_node(
        self,
        func: bn.MediumLevelILFunction,
        level: Optional[int] = None,
        **attr: Any,
    ) -> None:
        """
        This method adds a node for the given `func`, with the following node attribute: The
        attribute `level` is expected to be `func`'s level within the call stack.
        """
        if not isinstance(func, bn.MediumLevelILFunction):
            raise TypeError("Node is not of type 'bn.MediumLevelILFunction'")
        super().add_node(func, level=level, **attr)
        return

    def add_edge(
        self,
        from_func: bn.MediumLevelILFunction,
        to_func: bn.MediumLevelILFunction,
        from_level: Optional[int] = None,
        to_level: Optional[int] = None,
        **attr: Any,
    ) -> None:
        """
        This method adds an edge between `from_func` and `to_func`, with the given levels as node
        attributes.
        """
        if not isinstance(from_func, bn.MediumLevelILFunction):
            raise TypeError("Source node is not of type 'bn.MediumLevelILFunction'")
        if not isinstance(to_func, bn.MediumLevelILFunction):
            raise TypeError("Target node is not of type 'bn.MediumLevelILFunction'")
        self.add_node(from_func, from_level)
        self.add_node(to_func, to_level)
        super().add_edge(from_func, to_func, **attr)
        return

    def to_dict(self, debug: bool = False) -> Dict:
        """
        This method serializes a graph to a dictionary.
        """
        # Serialize nodes
        nodes: List[Dict[str, Any]] = []
        for node, atts in self.nodes(data=True):
            node = node  # type: bn.MediumLevelILFunction
            node_dict = {
                "adr": hex(node.source_function.start),
                "att": atts,
            }
            if debug:
                node_dict["func"] = FunctionHelper.get_func_info(node, True)
            nodes.append(node_dict)
        # Serialize edges
        edges: List[Dict[str, Any]] = []
        for src_node, tgt_node, atts in self.edges(data=True):
            src_node = src_node  # type: bn.MediumLevelILFunction
            tgt_node = tgt_node  # type: bn.MediumLevelILFunction
            edges.append(
                {
                    "src": hex(src_node.source_function.start),
                    "snk": hex(tgt_node.source_function.start),
                    "att": atts,
                }
            )
        return {"nodes": nodes, "edges": edges}

    @classmethod
    def from_dict(
        cls: Type[MediumLevelILFunctionGraph], bv: bn.BinaryView, d: Dict
    ) -> MediumLevelILFunctionGraph:
        """
        This method deserializes a dictionary to a graph.
        """
        call_graph: MediumLevelILFunctionGraph = cls()
        # Deserialize nodes
        for node in d["nodes"]:
            addr = int(node["adr"], 0)
            func = bv.get_function_at(addr)
            atts = node["att"]
            call_graph.add_node(func.mlil.ssa_form, **atts)
        # Deserialize edges
        for edge in d["edges"]:
            src_addr = int(edge["src"], 0)
            src_func = bv.get_function_at(src_addr)
            tgt_addr = int(edge["snk"], 0)
            tgt_func = bv.get_function_at(tgt_addr)
            atts = edge["att"]
            call_graph.add_edge(src_func.mlil.ssa_form, tgt_func.mlil.ssa_form, **atts)
        return call_graph
