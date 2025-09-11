from __future__ import annotations
from mole.common.helper.function import FunctionHelper
from typing import Any, Dict, List, Type
import binaryninja as bn
import networkx as nx


class MediumLevelILInstructionGraph(nx.DiGraph):
    """
    This class represents a directed graph that stores the `MediumLevelILInstruction` slice graph.
    """

    def add_node(
        self,
        inst: bn.MediumLevelILInstruction,
        **attr: Any,
    ) -> None:
        """
        This method adds a node for the given `inst`.
        """
        if not isinstance(inst, bn.MediumLevelILInstruction | None) and not (
            isinstance(inst, tuple)
            and len(inst) == 2
            and all(isinstance(i, bn.MediumLevelILInstruction | None) for i in inst)
        ):
            raise TypeError(
                "Node is not of type 'MediumLevelILInstruction' or '(MediumLevelILInstruction, MediumLevelILInstruction)'"
            )
        super().add_node(inst, **attr)
        return

    def add_edge(
        self,
        from_inst: bn.MediumLevelILInstruction,
        to_inst: bn.MediumLevelILInstruction,
        **attr: Any,
    ) -> None:
        """
        This method adds an edge from `from_inst` and `to_inst`.
        """
        if not isinstance(from_inst, bn.MediumLevelILInstruction | None) and not (
            isinstance(from_inst, tuple)
            and len(from_inst) == 2
            and all(
                isinstance(i, bn.MediumLevelILInstruction | None) for i in from_inst
            )
        ):
            raise TypeError(
                "Source node is not of type 'MediumLevelILInstruction' or '(MediumLevelILInstruction, MediumLevelILInstruction)'"
            )
        if not isinstance(to_inst, bn.MediumLevelILInstruction | None) and not (
            isinstance(to_inst, tuple)
            and len(to_inst) == 2
            and all(isinstance(i, bn.MediumLevelILInstruction | None) for i in to_inst)
        ):
            raise TypeError(
                "Target node is not of type 'MediumLevelILInstruction' or '(MediumLevelILInstruction, MediumLevelILInstruction)'"
            )
        self.add_node(from_inst)
        self.add_node(to_inst)
        super().add_edge(from_inst, to_inst, **attr)
        return


class MediumLevelILFunctionGraph(nx.DiGraph):
    """
    This class represents a directed graph that stores a `MediumLevelILFunction` call graph.
    """

    def add_node(
        self,
        func: bn.MediumLevelILFunction,
        **attr: Any,
    ) -> None:
        """
        This method adds a node for the given `func`.
        """
        if not isinstance(func, bn.MediumLevelILFunction):
            raise TypeError("Node is not of type 'MediumLevelILFunction'")
        super().add_node(func, **attr)
        return

    def add_edge(
        self,
        from_func: bn.MediumLevelILFunction,
        to_func: bn.MediumLevelILFunction,
        **attr: Any,
    ) -> None:
        """
        This method adds an edge between `from_func` and `to_func`.
        """
        if not isinstance(from_func, bn.MediumLevelILFunction):
            raise TypeError("Source node is not of type 'MediumLevelILFunction'")
        if not isinstance(to_func, bn.MediumLevelILFunction):
            raise TypeError("Target node is not of type 'MediumLevelILFunction'")
        self.add_node(from_func)
        self.add_node(to_func)
        super().add_edge(from_func, to_func, **attr)
        return

    def update_call_levels(self) -> bool:
        """
        This method updates the call levels of all in-path functions in the call graph. It returns
        True if the update was successful, False otherwise.
        """
        # Set all node levels to -1
        nx.set_node_attributes(self, -1, "level")
        # Get all nodes included in the path
        in_path_nodes = [
            node for node, attr in self.nodes(data=True) if attr["in_path"]
        ]
        # Create a subgraph view for the in-path nodes
        in_path_subgraph: MediumLevelILFunctionGraph = self.subgraph(in_path_nodes)
        # Ensure in-path subgraph is weakly connected (connected when ignoring direction)
        if not nx.is_weakly_connected(in_path_subgraph):
            return False
        # Determine root candidates (nodes with in-degree 0)
        roots = [
            node for node, in_degree in in_path_subgraph.in_degree() if in_degree == 0
        ]
        # Ensure in-path subgraph has exactly one root
        if len(roots) != 1:
            return False
        # Compute call levels (distance from root)
        levels = dict(nx.single_source_shortest_path_length(in_path_subgraph, roots[0]))
        # Update the levels of all in-path nodes
        nx.set_node_attributes(self, levels, "level")
        return True

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
