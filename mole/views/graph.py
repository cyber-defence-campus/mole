from __future__ import annotations
from mole.common.helper.instruction import InstructionHelper
from mole.core.data import Path
from typing import Literal, Optional, TYPE_CHECKING
import binaryninja as bn
import binaryninjaui as bnui
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui
import PySide6.QtWidgets as qtw

if TYPE_CHECKING:
    from mole.controllers.path import PathController


class CallGraphWidget(qtw.QWidget):
    """
    This class implements a view to display call graphs.
    """

    def __init__(self, path_ctr: PathController, parent=None) -> None:
        """
        This method initializes the call graph view.
        """
        super().__init__(parent)
        self.path_ctr = path_ctr
        self._bv = None
        self._path = None
        self._path_id = None
        # Graph
        self.graph = bn.FlowGraph()
        self.graph_wid = bnui.FlowGraphWidget(self, self._bv, self.graph)
        # Fit to view
        fit_to_view = qtui.QAction("Fit to View", self)
        fit_to_view.triggered.connect(lambda: self.load_path())
        # In-path only
        self.in_path_only = qtui.QAction("In-Path Only", self)
        self.in_path_only.setCheckable(True)
        self.in_path_only.setChecked(True)
        self.in_path_only.toggled.connect(lambda: self.load_path())
        # Spacer
        spacer = qtw.QWidget()
        spacer.setSizePolicy(
            qtw.QSizePolicy.Policy.Expanding, qtw.QSizePolicy.Policy.Preferred
        )
        # Legend
        self.legend = self._update_legend()
        # Toolbar
        toolbar = qtw.QToolBar("Graph Toolbar")
        toolbar.addAction(fit_to_view)
        toolbar.addAction(self.in_path_only)
        toolbar.addWidget(spacer)
        toolbar.addWidget(self.legend)
        # Layout
        self.layout: qtw.QVBoxLayout = qtw.QVBoxLayout()
        self.layout.addWidget(self.graph_wid)
        self.layout.addWidget(toolbar)
        self.setLayout(self.layout)
        return

    def _get_color(
        self, name: Literal["src", "snk", "in_path"]
    ) -> bn.HighlightStandardColor:
        """
        This method retries the highlight color from the settings.
        """
        color = bn.HighlightStandardColor.WhiteHighlightColor
        if name == "src":
            try:
                setting = self.path_ctr.config_ctr.get_setting("src_highlight_color")
                color_name = setting.widget.currentText().capitalize()
                color = bn.HighlightStandardColor[f"{color_name:s}HighlightColor"]
            except Exception as _:
                color = bn.HighlightStandardColor.OrangeHighlightColor
        elif name == "snk":
            try:
                setting = self.path_ctr.config_ctr.get_setting("snk_highlight_color")
                color_name = setting.widget.currentText().capitalize()
                color = bn.HighlightStandardColor[f"{color_name:s}HighlightColor"]
            except Exception as _:
                color = bn.HighlightStandardColor.RedHighlightColor
        return color

    def _update_legend(self) -> qtw.QLabel:
        """
        This method updates the legend with the correct highlight colors.
        """
        if not hasattr(self, "legend") or not self.legend:
            self.legend = qtw.QLabel()
        src_color: qtui.QColor = bnui.getThemeHighlightColor(self._get_color("src"))
        snk_color: qtui.QColor = bnui.getThemeHighlightColor(self._get_color("snk"))
        in_path_color: qtui.QColor = bnui.getThemeHighlightColor(
            self._get_color("in_path")
        )
        text = (
            f'<span style="color: {src_color.name()};">Source</span> | '
            f'<span style="color: {snk_color.name()};">Sink</span> | '
            f'<span style="color: {in_path_color.name()};">In-Path</span>'
        )
        self.legend.setText(text)
        return self.legend

    def _fit_to_view(self, min_scale: float = 0.05, padding: int = 10) -> None:
        """
        This method fits the entire graph into the visible area.
        """
        # Get graph and view dimensions
        gw = max(self.graph.width, 1)
        gh = max(self.graph.height, 1)
        vw = max(self.graph_wid.width(), 1)
        vh = max(self.graph_wid.height(), 1)
        # Calculate scale
        scale_w = (vw - padding) / float(gw)
        scale_h = (vh - padding) / float(gh)
        max_scale = self.graph_wid.maxScale()
        scale = max(min_scale, min(scale_w, scale_h, max_scale))
        # Zoom to scale
        self.graph_wid.zoomToScale(scale)
        # Center the view
        try:
            self.graph_wid.showTopNode()
        except Exception:
            pass
        return

    def load_path(
        self,
        bv: Optional[bn.BinaryView] = None,
        path: Optional[Path] = None,
        path_id: Optional[int] = None,
    ) -> None:
        """
        This method creates a new Binary Ninja flow graph for the given path's call graph and loads
        it into the view.
        """
        # Fit graph to view
        self._fit_to_view()
        # Update legend
        self._update_legend()
        # Update references to BinaryView and path information
        if bv is not None:
            self._bv = bv
        if path is not None:
            self._path = path
        if path_id is not None:
            self._path_id = path_id
        # Ensure valid references to BinaryView and path information
        if self._bv is None or self._path is None or self._path_id is None:
            return
        # Tooltip showing the corresponding path ID
        self.setToolTip(f"Path {self._path_id:d}")
        # Create graph
        self.graph = bn.FlowGraph()
        nodes_map = {}
        for node, attrs in self._path.call_graph.nodes(data=True):
            node = node  # type: bn.MediumLevelILFunction
            attrs = attrs  # type: dict[str, Any]
            # Skip nodes that are not in-path
            if self.in_path_only.isChecked() and not attrs["in_path"]:
                continue
            # Create node
            flow_graph_node = bn.FlowGraphNode(self.graph)
            # Add function tokens to node's text lines
            func = node.source_function
            func_tokens = InstructionHelper.mark_param_token(
                func.type_tokens, attrs.get("par_indices", [])
            )
            flow_graph_node.lines = [
                bn.function.DisassemblyTextLine(func_tokens, address=func.start)
            ]
            # Source node
            if "src" in attrs:
                # Add source instruction tokens to text lines
                src_inst = self._path.insts[-1]
                src_inst_par_idx = self._path.src_par_idx
                src_inst_tokens = InstructionHelper.replace_addr_tokens(src_inst)
                src_inst_tokens = InstructionHelper.mark_param_token(
                    src_inst_tokens,
                    [src_inst_par_idx] if src_inst_par_idx is not None else [],
                )
                tokens = [
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
                flow_graph_node.lines += [
                    bn.function.DisassemblyTextLine(
                        tokens,
                        address=src_inst.address,
                        il_instr=src_inst,
                    )
                ]
                # Highlight node
                flow_graph_node.highlight = self._get_color("src")
            # Sink node
            if "snk" in attrs:
                # Add sink instruction tokens to text lines
                snk_inst = self._path.insts[0]
                snk_inst_par_idx = self._path.snk_par_idx
                snk_inst_tokens = InstructionHelper.replace_addr_tokens(snk_inst)
                snk_inst_tokens = InstructionHelper.mark_param_token(
                    snk_inst_tokens,
                    [snk_inst_par_idx] if snk_inst_par_idx is not None else [],
                )
                tokens = [
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
                flow_graph_node.lines += [
                    bn.function.DisassemblyTextLine(
                        tokens,
                        address=snk_inst.address,
                        il_instr=snk_inst,
                    )
                ]
                # Highlight node
                flow_graph_node.highlight = self._get_color("snk")
            # Other nodes
            if "src" not in attrs and "snk" not in attrs:
                if "in_path" in attrs and attrs["in_path"]:
                    flow_graph_node.highlight = self._get_color("in_path")
            # Add node to graph
            self.graph.append(flow_graph_node)
            nodes_map[node] = flow_graph_node
        # Add edges to graph
        for from_node, to_node in self._path.call_graph.edges():
            if from_node in nodes_map and to_node in nodes_map:
                nodes_map[from_node].add_outgoing_edge(
                    bn.enums.BranchType.UnconditionalBranch, nodes_map[to_node]
                )
        # Update graph widget
        index = self.layout.indexOf(self.graph_wid)
        self.layout.removeWidget(self.graph_wid)
        self.graph_wid.deleteLater()
        self.graph_wid = bnui.FlowGraphWidget(self, self._bv, self.graph)
        self.layout.insertWidget(index, self.graph_wid)
        # Fit graph to window
        qtc.QTimer.singleShot(200, self._fit_to_view)
        return
