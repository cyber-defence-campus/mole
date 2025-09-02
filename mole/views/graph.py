from __future__ import annotations
from mole.core.data import Path
from typing import Optional
import binaryninja as bn
import binaryninjaui as bnui
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui
import PySide6.QtWidgets as qtw


class CallGraphWidget(qtw.QWidget):
    """
    This class implements a view to display call graphs.
    """

    def __init__(self, parent=None) -> None:
        """
        This method initializes the call graph view.
        """
        super().__init__(parent)
        self._bv = None
        self._path = None
        self._path_id = None
        # Graph
        self.graph = bn.FlowGraph()
        self.graph_wid = bnui.FlowGraphWidget(self, self._bv, self.graph)
        # Fit to view
        fit_to_view = qtui.QAction("Fit to View", self)
        fit_to_view.triggered.connect(lambda: self.fit_to_view())
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
        r_color = bn.enums.ThemeColor.RedStandardHighlightColor
        g_color = bn.enums.ThemeColor.GreenStandardHighlightColor
        b_color = bn.enums.ThemeColor.BlueStandardHighlightColor
        r = str(bnui.getThemeColor(r_color).name())
        g = str(bnui.getThemeColor(g_color).name())
        b = str(bnui.getThemeColor(b_color).name())
        legend = qtw.QLabel(
            (
                f'<span style="color: {r:s};">Sink</span> | '
                f'<span style="color: {g:s};">Source</span> | '
                f'<span style="color: {b:s};">In-Path</span>'
            )
        )
        # Toolbar
        toolbar = qtw.QToolBar("Graph Toolbar")
        toolbar.addAction(fit_to_view)
        toolbar.addAction(self.in_path_only)
        toolbar.addWidget(spacer)
        toolbar.addWidget(legend)
        # Layout
        self.layout: qtw.QVBoxLayout = qtw.QVBoxLayout()
        self.layout.addWidget(self.graph_wid)
        self.layout.addWidget(toolbar)
        self.setLayout(self.layout)
        return

    def fit_to_view(self, min_scale: float = 0.05, padding: int = 10) -> None:
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
            # Skip nodes that are not in-path
            if self.in_path_only.isChecked() and not attrs["in_path"]:
                continue
            # Create node
            flow_graph_node = bn.FlowGraphNode(self.graph)
            flow_graph_node.lines = [
                bn.function.DisassemblyTextLine(
                    node.source_function.type_tokens, address=node.source_function.start
                )
            ]
            # Set node's color
            if "snk" in attrs:
                flow_graph_node.highlight = (
                    bn.enums.HighlightStandardColor.RedHighlightColor
                )
            elif "src" in attrs:
                flow_graph_node.highlight = (
                    bn.enums.HighlightStandardColor.GreenHighlightColor
                )
            elif attrs["in_path"]:
                flow_graph_node.highlight = (
                    bn.enums.HighlightStandardColor.BlueHighlightColor
                )
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
        self.graph_wid.setGraph(self.graph)
        # Fit graph to window
        qtc.QTimer.singleShot(200, self.fit_to_view)
        return
