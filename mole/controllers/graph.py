from __future__ import annotations
from mole.common.helper.instruction import InstructionHelper
from mole.services.graph import GraphService
from mole.views.graph import GraphView
from typing import cast, Dict, List, TYPE_CHECKING
import binaryninja as bn

if TYPE_CHECKING:
    from mole.data.path import Path


class GraphController:
    """
    This class implements a controller for Mole's graph.
    """

    def __init__(
        self, bv: bn.BinaryView, graph_service: GraphService, graph_view: GraphView
    ) -> None:
        """
        This method initializes the graph controller.
        """
        self.bv = bv
        self.graph_service = graph_service
        self.graph_view = graph_view
        self._path_id: int | None = None
        self._path: Path | None = None
        return

    def show_call_graph(
        self,
        path_id: int | None = None,
        path: Path | None = None,
        show_tab: bool = True,
    ) -> None:
        """
        This method creates a flow graph from the given path's call graph and shows it in the graph
        view.
        """
        # Store path ID and path
        if path_id is not None:
            self._path_id = path_id
        if path is not None:
            self._path = path
        # Ensure valid path ID and path
        if self._path_id is None or self._path is None:
            return
        # Create flow graph from call graph
        flow_graph = bn.FlowGraph()
        call_graph = self._path.call_graph
        node_map: Dict[bn.MediumLevelILFunction, bn.FlowGraphNode] = {}
        # Add nodes to flow graph
        for call, attrs in call_graph.nodes(data=True):
            call = cast(bn.MediumLevelILFunction, call)
            # Ignore node if already added or being out-of-path while in-path-only is enabled
            if call in node_map or (
                self.graph_view.in_path_only
                and not call_graph.nodes[call].get("in_path", False)
            ):
                continue
            # Create flow graph node
            fg_node = bn.FlowGraphNode(flow_graph)
            # Add function tokens
            func = call.source_function
            func_tokens: List[bn.InstructionTextToken] = (
                InstructionHelper.mark_func_tokens(func.type_tokens, set(), set())
            )
            fg_node.lines += [func_tokens]
            # Add source tokens
            if "src" in attrs:
                src_inst = self._path.insts[-1]
                src_inst_par_idx = self._path.src_par_idx
                src_inst_tokens = InstructionHelper.replace_addr_tokens(src_inst)
                src_inst_tokens = InstructionHelper.mark_func_tokens(
                    src_inst_tokens,
                    {0} if src_inst_par_idx is None else set(),
                    {src_inst_par_idx} if src_inst_par_idx is not None else set(),
                )
                src_inst_tokens = [
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.CommentToken, "- SRC:\t"
                    ),
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.AddressDisplayToken,
                        f"0x{src_inst.address:x}\t",
                        src_inst.address,
                    ),
                    *src_inst_tokens,
                ]
                fg_node.lines += [src_inst_tokens]
                fg_node.highlight = self.graph_service.get_color("src")
            # Add sink tokens
            if "snk" in attrs:
                snk_inst = self._path.insts[0]
                snk_inst_par_idx = self._path.snk_par_idx
                snk_inst_tokens = InstructionHelper.replace_addr_tokens(snk_inst)
                snk_inst_tokens = InstructionHelper.mark_func_tokens(
                    snk_inst_tokens,
                    set(),
                    {snk_inst_par_idx} if snk_inst_par_idx is not None else set(),
                )
                snk_inst_tokens = [
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.CommentToken, "- SNK:\t"
                    ),
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.AddressDisplayToken,
                        f"0x{snk_inst.address:x}\t",
                        snk_inst.address,
                    ),
                    *snk_inst_tokens,
                ]
                fg_node.lines += [snk_inst_tokens]
                fg_node.highlight = self.graph_service.get_color("snk")
            # Highlight in-path nodes
            if (
                "src" not in attrs
                and "snk" not in attrs
                and "in_path" in attrs
                and attrs["in_path"]
            ):
                fg_node.highlight = self.graph_service.get_color("in_path")
            # Add node to flow graph
            node_map[call] = fg_node
            flow_graph.append(fg_node)
        # Add edges to flow graph
        for from_call, to_call, attrs in call_graph.edges(data=True):
            from_call = cast(bn.MediumLevelILFunction, from_call)
            to_call = cast(bn.MediumLevelILFunction, to_call)
            fg_from_node = node_map.get(from_call, None)
            fg_to_node = node_map.get(to_call, None)
            # Ignore edge if necessary attributes are missing
            if "downwards" not in attrs or "param_idx" not in attrs:
                continue
            path_follows_downwards: bool = attrs["downwards"]
            path_follows_param_idx: int = attrs["param_idx"]
            in_path: bool = attrs.get("in_path", False)
            # Ignore edge if not both nodes are in the flow graph
            if (
                fg_from_node is None
                or fg_to_node is None
                or (self.graph_view.in_path_only and not in_path)
            ):
                continue
            # Add edge
            fg_from_node.add_outgoing_edge(
                bn.enums.BranchType.UnconditionalBranch, fg_to_node
            )
            # Path went down to a possible return instruction
            if path_follows_downwards and path_follows_param_idx <= 0:
                to_func_tokens = InstructionHelper.mark_func_tokens(
                    to_call.source_function.type_tokens, {0}, set()
                )
            # Path went down to a specific output parameter
            elif path_follows_downwards and path_follows_param_idx > 0:
                to_func_tokens = InstructionHelper.mark_func_tokens(
                    to_call.source_function.type_tokens, set(), {path_follows_param_idx}
                )
            #  Path went up to a possible parameter
            elif not path_follows_downwards and path_follows_param_idx <= 0:
                to_func_tokens = InstructionHelper.mark_func_tokens(
                    to_call.source_function.type_tokens, {0}, set()
                )
            # Path went up to a specific parameter
            else:
                to_func_tokens = InstructionHelper.mark_func_tokens(
                    to_call.source_function.type_tokens, set(), {path_follows_param_idx}
                )
            # Add call site tokens
            call_site = attrs.get("call_site", None)
            if call_site is not None:
                to_func_tokens += [
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.CommentToken, " @ "
                    ),
                    bn.InstructionTextToken(
                        bn.InstructionTextTokenType.AddressDisplayToken,
                        f"0x{call_site:x}\t",
                        call_site,
                    ),
                ]
            # Mark parameters in function tokens
            fg_to_node.lines = [to_func_tokens] + fg_to_node.lines[1:]
        # Set flow graph in view
        bn.execute_on_main_thread(
            lambda bv=self.bv,
            path_id=self._path_id,
            flow_graph=flow_graph,
            show_tab=show_tab: self.graph_view.set_flow_graph(
                bv, path_id, flow_graph, show_tab
            )
        )
        # Update legend
        src_color = self.graph_service.get_color("src")
        snk_color = self.graph_service.get_color("snk")
        in_path_color = self.graph_service.get_color("in_path")
        bn.execute_on_main_thread(
            lambda: self.graph_view.set_legend(src_color, snk_color, in_path_color)
        )
        return
