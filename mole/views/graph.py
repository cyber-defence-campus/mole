from __future__ import annotations
from mole.core.data import Path
from typing import Any, Optional
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
        self.graph_wid = bnui.FlowGraphWidget(self, self._bv, bn.FlowGraph())
        # self.graph_wid.paintEvent = self.paint_event
        # In-path
        self.in_path_only = qtw.QCheckBox("In-Path Only")
        self.in_path_only.setChecked(True)
        self.in_path_only.toggled.connect(self.load_path)
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
        toolbar.addAction(
            qtui.QAction("Fit to View ⤢", self, triggered=self.fit_to_window)
        )
        toolbar.addSeparator()
        toolbar.addWidget(self.in_path_only)
        toolbar.addSeparator()
        toolbar.addWidget(spacer)
        toolbar.addWidget(legend)
        # Layout
        self.layout = qtw.QVBoxLayout()
        self.layout.addWidget(self.graph_wid)
        self.layout.addWidget(toolbar)
        self.setLayout(self.layout)
        return

    def fit_to_window(self) -> None:
        """TODO
        Fit the flowgraph to window
        """
        self.graph_wid.enableInitialSizeToFit()
        self.graph_wid.zoomToScale(1.0)
        return

    def load_path(
        self,
        bv: Optional[bn.BinaryView] = None,
        path: Optional[Path] = None,
        path_id: Optional[int] = None,
    ) -> None:
        """
        This method creates a new Binary Ninja flow graph for the given path's call graph and loads
        it into the graph view.
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
        # Create flow graph
        flow_graph = bn.FlowGraph()
        nodes_map = {}
        for node, node_attrs in self._path.call_graph.nodes(data=True):
            # Skip nodes that are not in-path (depending on checkbox)
            if self.in_path_only.isChecked() and not node_attrs["in_path"]:
                continue
            # Create node
            flow_graph_node = bn.FlowGraphNode(flow_graph)
            flow_graph_node.lines = [
                bn.function.DisassemblyTextLine(
                    node.source_function.type_tokens, address=node.source_function.start
                )
            ]
            # Set node's color
            if "snk" in node_attrs:
                flow_graph_node.highlight = (
                    bn.enums.HighlightStandardColor.RedHighlightColor
                )
            elif "src" in node_attrs:
                flow_graph_node.highlight = (
                    bn.enums.HighlightStandardColor.GreenHighlightColor
                )
            elif node_attrs["in_path"]:
                flow_graph_node.highlight = (
                    bn.enums.HighlightStandardColor.BlueHighlightColor
                )
            # Add node to flow graph
            flow_graph.append(flow_graph_node)
            nodes_map[node] = flow_graph_node
        # Add edges to flow graph
        for from_node, to_node in self._path.call_graph.edges():
            if from_node in nodes_map and to_node in nodes_map:
                nodes_map[from_node].add_outgoing_edge(
                    bn.enums.BranchType.UnconditionalBranch, nodes_map[to_node]
                )
        # Update graph widget
        self.layout.removeWidget(self.graph_wid)
        self.graph_wid = bnui.FlowGraphWidget(self, self._bv, flow_graph)
        self.layout.insertWidget(0, self.graph_wid)
        # Fit graph to window
        qtc.QTimer.singleShot(200, self.fit_to_window)
        return


class GraphWidget(qtw.QWidget):
    """TODO:
    - Should we call it flow graph?
    - Can we remove bv?
    This class implements a view to display flow graphs.
    """

    def __init__(self) -> None:
        """
        This method initializes the flow graph view.
        """
        super().__init__()
        self._bv = None
        self._path = None
        self._path_id = None

        self.flowgraph_widget = bnui.FlowGraphWidget(self, None)
        self.v_layout = qtw.QVBoxLayout(self)
        self.v_layout.addWidget(self.flowgraph_widget)

        # Prevent flowgraph's "No function selected" default message from showing
        self.flowgraph_widget_paintEvent = self.flowgraph_widget.paintEvent
        self.flowgraph_widget.paintEvent = self.helperPaintEvent

        self.toolbar = qtw.QToolBar("Graph Toolbar")
        self.addToolBarActions()
        self.v_layout.addWidget(self.toolbar)
        return

    def helperPaintEvent(self, event: Any) -> None:
        p = qtui.QPainter(self.flowgraph_widget.viewport())

        p.setFont(bnui.getApplicationFont(self.flowgraph_widget))
        p.setPen(
            self.flowgraph_widget.palette().color(qtui.QPalette.ColorRole.WindowText)
        )

        text = "Right-click on a path and select 'Show call graph'"

        text_rect = p.boundingRect(
            self.rect(),
            qtc.Qt.AlignmentFlag.AlignCenter | qtc.Qt.TextFlag.TextWordWrap,
            text,
        )
        p.drawText(
            text_rect,
            qtc.Qt.AlignmentFlag.AlignCenter | qtc.Qt.TextFlag.TextWordWrap,
            text,
        )
        return

    def addToolBarActions(self) -> None:
        fit_action = qtui.QAction("Fit to View ⤢", self)
        fit_action.triggered.connect(self.fit_to_window)
        self.toolbar.addAction(fit_action)

        self.toolbar.addSeparator()

        self._show_in_path_checkbox = qtw.QCheckBox("In-Path Only")
        self._show_in_path_checkbox.setChecked(True)
        self._show_in_path_checkbox.toggled.connect(self.on_checkbox_toggled)
        self.toolbar.addWidget(self._show_in_path_checkbox)

        self.toolbar.addSeparator()

        # Add a spacer to push the legend to the right
        spacer = qtw.QWidget()
        spacer.setSizePolicy(
            qtw.QSizePolicy.Policy.Expanding, qtw.QSizePolicy.Policy.Preferred
        )
        self.toolbar.addWidget(spacer)

        # Add colored legend
        red = bnui.getThemeColor(bn.enums.ThemeColor.RedStandardHighlightColor).name()
        green = bnui.getThemeColor(
            bn.enums.ThemeColor.GreenStandardHighlightColor
        ).name()
        blue = bnui.getThemeColor(bn.enums.ThemeColor.BlueStandardHighlightColor).name()
        legend_text = (
            f'<span style="color: {str(red):s};">Sink</span> | '
            f'<span style="color: {str(green):s};">Source</span> | '
            f'<span style="color: {str(blue):s};">Off-path</span>'
        )
        self.toolbar.addWidget(qtw.QLabel(legend_text))
        return

    def load_path(self, bv: bn.BinaryView, path: Path, path_id: int) -> None:
        """Load a new graph into the flowgraph
        Args:
            bv (bn.BinaryView): The BinaryView object
            path (Path): A Path object
            path_id (int): The path's row in the tree
        """
        self._bv = bv
        self._path = path
        self._path_id = path_id
        self.setToolTip(f"Path {path_id:d}")

        # Only recreate the widget if the binary view has changed
        # Couldn't find a proper API on FlowGraphWidget to avoid this
        if self.flowgraph_widget.getData() != bv:
            # Remove the old widget from layout
            self.v_layout.removeWidget(self.flowgraph_widget)
            self.flowgraph_widget.setParent(None)

            # Create new widget with the updated binary view
            self.flowgraph_widget = bnui.FlowGraphWidget(self, bv)
            self.v_layout.insertWidget(0, self.flowgraph_widget)

            # Store the original paint event for later restoration
            self.flowgraph_widget_paintEvent = self.flowgraph_widget.paintEvent

        # Clear previous nodes mapping
        nodes_map = {}
        call_graph = path.call_graph

        # Create a new flowgraph
        flowgraph = bn.FlowGraph()
        for node in call_graph:
            if (
                self._show_in_path_checkbox.isChecked()
                and not call_graph.nodes[node]["in_path"]
            ):
                continue

            new_node = bn.FlowGraphNode(flowgraph)
            new_node.lines = [
                bn.function.DisassemblyTextLine(
                    node.source_function.type_tokens, address=node.source_function.start
                )
            ]

            # Set node color based on type
            node_data = call_graph.nodes[node]
            if "snk" in node_data:
                # Red for sink nodes
                new_node.highlight = bn.enums.HighlightStandardColor.RedHighlightColor
            elif "src" in node_data:
                # Green for source nodes
                new_node.highlight = bn.enums.HighlightStandardColor.GreenHighlightColor
            elif not node_data.get("in_path", False):
                # Blue for other nodes
                new_node.highlight = bn.enums.HighlightStandardColor.BlueHighlightColor

            flowgraph.append(new_node)
            nodes_map[node] = new_node

        for source_node, dest_node in call_graph.edges:
            if source_node in nodes_map and dest_node in nodes_map:
                nodes_map[source_node].add_outgoing_edge(
                    bn.enums.BranchType.UnconditionalBranch, nodes_map[dest_node]
                )

        self.flowgraph_widget.setGraph(flowgraph)

        # Restore the original paint event so the graph is actually displayed
        self.flowgraph_widget.paintEvent = self.flowgraph_widget_paintEvent

        # Fit the graph to window after loading
        qtc.QTimer.singleShot(200, self.fit_to_window)
        return

    def fit_to_window(self) -> None:
        """Fit the flowgraph to window"""
        # Enable initial size to fit for better auto-sizing
        self.flowgraph_widget.enableInitialSizeToFit()

        # Reset zoom to default scale
        # The zoom-to-scale calculation seems to ignore the actual viewport size and instead uses absolute values.
        self.flowgraph_widget.zoomToScale(1.0)
        return

    def on_checkbox_toggled(self, _: bool) -> None:
        # Reload the graph with the new filter state if a graph was loaded
        if self._bv and self._path is not None and self._path_id is not None:
            self.load_path(self._bv, self._path, self._path_id)
        return
