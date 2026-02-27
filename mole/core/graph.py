from __future__ import annotations
from mole.common.helper.function import FunctionHelper
from mole.common.log import Logger
from typing import Any, cast, Dict, List, Tuple, Type
import binaryninja as bn
import networkx as nx


tag = "Graph"


class MediumLevelILInstructionGraph(nx.DiGraph):
    """
    This class represents a directed graph that stores the `MediumLevelILInstruction` slice graph.
    """

    def add_node(
        self,
        node_for_adding: bn.MediumLevelILInstruction
        | Tuple[bn.MediumLevelILInstruction | None, bn.MediumLevelILInstruction | None]
        | None,
        **attr: Any,
    ) -> None:
        """
        This method adds a node for the given `node_for_adding`.
        """
        if not isinstance(node_for_adding, bn.MediumLevelILInstruction | None) and not (
            isinstance(node_for_adding, tuple)
            and len(node_for_adding) == 2
            and all(
                isinstance(i, bn.MediumLevelILInstruction | None)
                for i in node_for_adding
            )
        ):
            raise TypeError("MediumLevelILInstructionGraph node with invalid type")
        super().add_node(node_for_adding, **attr)
        return

    def add_edge(
        self,
        u_of_edge: bn.MediumLevelILInstruction
        | Tuple[bn.MediumLevelILInstruction | None, bn.MediumLevelILInstruction | None]
        | None,
        v_of_edge: bn.MediumLevelILInstruction
        | Tuple[bn.MediumLevelILInstruction | None, bn.MediumLevelILInstruction | None]
        | None,
        **attr: Any,
    ) -> None:
        """
        This method adds an edge from `u_of_edge` to `v_of_edge`.
        """
        if not isinstance(u_of_edge, bn.MediumLevelILInstruction | None) and not (
            isinstance(u_of_edge, tuple)
            and len(u_of_edge) == 2
            and all(
                isinstance(i, bn.MediumLevelILInstruction | None) for i in u_of_edge
            )
        ):
            raise TypeError(
                "MediumLevelILInstructionGraph source node with invalid type"
            )
        if not isinstance(v_of_edge, bn.MediumLevelILInstruction | None) and not (
            isinstance(v_of_edge, tuple)
            and len(v_of_edge) == 2
            and all(
                isinstance(i, bn.MediumLevelILInstruction | None) for i in v_of_edge
            )
        ):
            raise TypeError(
                "MediumLevelILInstructionGraph target node with invalid type"
            )
        self.add_node(u_of_edge)
        self.add_node(v_of_edge)
        super().add_edge(u_of_edge, v_of_edge, **attr)
        return


class MediumLevelILFunctionGraph(nx.DiGraph):
    """
    This class represents a directed graph that stores a `MediumLevelILFunction` call graph.
    """

    def add_node(
        self,
        node_for_adding: bn.MediumLevelILFunction,
        **attr: Any,
    ) -> None:
        """
        This method adds a node for function `node_for_adding`.
        """
        if not isinstance(node_for_adding, bn.MediumLevelILFunction):
            raise TypeError("Node is not of type 'MediumLevelILFunction'")
        super().add_node(node_for_adding, **attr)
        return

    def add_edge(
        self,
        u_of_edge: bn.MediumLevelILFunction,
        v_of_edge: bn.MediumLevelILFunction,
        **attr: Any,
    ) -> None:
        """
        This method adds an edge from function `u_of_edge` to function `v_of_edge`.
        """
        if not isinstance(u_of_edge, bn.MediumLevelILFunction):
            raise TypeError("Source node is not of type 'MediumLevelILFunction'")
        if not isinstance(v_of_edge, bn.MediumLevelILFunction):
            raise TypeError("Target node is not of type 'MediumLevelILFunction'")
        self.add_node(u_of_edge)
        self.add_node(v_of_edge)
        super().add_edge(u_of_edge, v_of_edge, **attr)
        return

    def update_call_levels(self) -> bool:
        """
        This method updates the call levels of all in-path functions in the call graph. It returns
        True if the update was successful, False otherwise.
        """
        # Set all node levels to -1
        nx.set_node_attributes(self, {n: -1 for n in self.nodes}, "level")
        # Get all nodes included in the path
        in_path_nodes = [
            node for node, attrs in self.nodes(data=True) if attrs.get("in_path", False)
        ]
        # Create a subgraph view for the in-path nodes
        in_path_subgraph = cast(
            MediumLevelILFunctionGraph, self.subgraph(in_path_nodes)
        )
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

    def to_dict(self) -> Dict:
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
                "func": FunctionHelper.get_func_info(node, True),
            }
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
        log = Logger(bv)
        try:
            # Deserialize nodes
            for node in d["nodes"]:
                addr = int(node["adr"], 0)
                func = bv.get_function_at(addr)
                if func is None or func.mlil is None or func.mlil.ssa_form is None:
                    log.error(
                        tag, f"No valid MLIL SSA function found at address 0x{addr:x}"
                    )
                    continue
                func_info = FunctionHelper.get_func_info(func.mlil.ssa_form, True)
                if func_info != node["func"]:
                    log.warn(tag, "Function mismatch:")
                    log.warn(tag, f"- Expected: {node['func']:s}")
                    log.warn(tag, f"- Found   : {func_info:s}")
                atts = node["att"]
                call_graph.add_node(func.mlil.ssa_form, **atts)
            # Deserialize edges
            for edge in d["edges"]:
                src_addr = int(edge["src"], 0)
                src_func = bv.get_function_at(src_addr)
                if (
                    src_func is None
                    or src_func.mlil is None
                    or src_func.mlil.ssa_form is None
                ):
                    log.error(
                        tag,
                        f"No valid MLIL SSA function found at address 0x{src_addr:x}",
                    )
                    continue
                tgt_addr = int(edge["snk"], 0)
                tgt_func = bv.get_function_at(tgt_addr)
                if (
                    tgt_func is None
                    or tgt_func.mlil is None
                    or tgt_func.mlil.ssa_form is None
                ):
                    log.error(
                        tag,
                        f"No valid MLIL SSA function found at address 0x{tgt_addr:x}",
                    )
                    continue
                atts = edge["att"]
                call_graph.add_edge(
                    src_func.mlil.ssa_form, tgt_func.mlil.ssa_form, **atts
                )
        except Exception as e:
            raise e
        return call_graph
