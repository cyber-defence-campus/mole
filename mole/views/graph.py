from __future__ import annotations
from mole.core.data import Path
import binaryninja as bn
import math as math

from binaryninjaui import FlowGraphWidget, getApplicationFont, getThemeColor
from binaryninja import FlowGraph, FlowGraphNode
from binaryninja.function import DisassemblyTextLine
from binaryninja.enums import BranchType, HighlightStandardColor, ThemeColor

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QToolBar,
    QCheckBox,
    QLabel,
    QSizePolicy,
)
from PySide6.QtGui import QPalette, QPainter, QAction
from PySide6.QtCore import Qt, QTimer

tag = "Mole.Graph"


class ColoredLegendLabel(QLabel):
    """A label that displays colored text for the legend using actual Binary Ninja theme colors"""

    def __init__(self, parent=None):
        super().__init__(parent)

        red_color = getThemeColor(ThemeColor.RedStandardHighlightColor)
        green_color = getThemeColor(ThemeColor.GreenStandardHighlightColor)
        html_text = (
            f'<span style="color: {red_color.name()};">Sink</span> | '
            f'<span style="color: {green_color.name()};">Source</span>'
        )

        self.setText(html_text)


class GraphWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._bv = None
        self._path = None
        self._path_id = None
        self._nodes_map = {}

        self.flowgraph_widget = FlowGraphWidget(self, None)
        self.v_layout = QVBoxLayout(self)
        self.v_layout.addWidget(self.flowgraph_widget)

        # Prevent flowgraph's "No function selected" default message from showing
        self.flowgraph_widget_paintEvent = self.flowgraph_widget.paintEvent
        self.flowgraph_widget.paintEvent = self.helperPaintEvent

        self.toolbar = QToolBar("Graph Toolbar")
        self.addToolBarActions()
        self.v_layout.addWidget(self.toolbar)
        return

    def helperPaintEvent(self, event):
        p = QPainter(self.flowgraph_widget.viewport())

        p.setFont(getApplicationFont(self.flowgraph_widget))
        p.setPen(self.flowgraph_widget.palette().color(QPalette.ColorRole.WindowText))

        text = "Right-click on a path and select 'Show call graph'"

        text_rect = p.boundingRect(
            self.rect(), Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap, text
        )
        p.drawText(
            text_rect, Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap, text
        )

    def addToolBarActions(self) -> None:
        fit_action = QAction("Fit to View ⤢", self)
        fit_action.triggered.connect(self.fit_to_window)
        self.toolbar.addAction(fit_action)

        self.toolbar.addSeparator()

        self._show_in_path_checkbox = QCheckBox("In-Path Only")
        self._show_in_path_checkbox.setChecked(True)
        self._show_in_path_checkbox.toggled.connect(self.on_checkbox_toggled)
        self.toolbar.addWidget(self._show_in_path_checkbox)

        self.toolbar.addSeparator()

        # Add a spacer to push the legend to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.toolbar.addWidget(spacer)

        # Add the colored legend label (aligned to the right)
        legend_label = ColoredLegendLabel()
        self.toolbar.addWidget(legend_label)

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

        # Only recreate the widget if the binary view has changed
        if self.flowgraph_widget.getData() != bv:
            # Remove the old widget from layout
            self.v_layout.removeWidget(self.flowgraph_widget)
            self.flowgraph_widget.setParent(None)

            # Create new widget with the updated binary view
            self.flowgraph_widget = FlowGraphWidget(self, bv)
            self.v_layout.insertWidget(0, self.flowgraph_widget)

            # Store the original paint event for later restoration
            self.flowgraph_widget_paintEvent = self.flowgraph_widget.paintEvent

        # Clear previous nodes mapping
        self._nodes_map = {}

        # Create a new flowgraph
        flowgraph = FlowGraph()
        for node in path.call_graph:
            if (
                self._show_in_path_checkbox.isChecked()
                and not path.call_graph.nodes[node]["in_path"]
            ):
                continue

            new_node = FlowGraphNode(flowgraph)
            new_node.lines = [
                DisassemblyTextLine(
                    node.source_function.type_tokens, address=node.source_function.start
                )
            ]

            # Set node color based on type (sink/source)
            node_data = path.call_graph.nodes[node]
            if "snk" in node_data:
                # Red for sink nodes
                new_node.highlight = HighlightStandardColor.RedHighlightColor
            elif "src" in node_data:
                # Green for source nodes
                new_node.highlight = HighlightStandardColor.GreenHighlightColor
            elif node_data.get("in_path", False):
                # Yellow for nodes in path
                new_node.highlight = HighlightStandardColor.YellowHighlightColor
            else:
                # Blue for other nodes
                new_node.highlight = HighlightStandardColor.BlueHighlightColor

            flowgraph.append(new_node)
            self._nodes_map[node] = new_node

        for a, b in path.call_graph.edges:
            if a in self._nodes_map and b in self._nodes_map:
                source = self._nodes_map[a]
                dest = self._nodes_map[b]
                source.add_outgoing_edge(BranchType.UnconditionalBranch, dest)

        self.flowgraph_widget.setGraph(flowgraph)

        # Restore the original paint event so the graph is actually displayed
        self.flowgraph_widget.paintEvent = self.flowgraph_widget_paintEvent

        # Fit the graph to window after loading
        QTimer.singleShot(200, self.fit_to_window)

        return

    def fit_to_window(self) -> None:
        """Fit the flowgraph to window"""
        # Enable initial size to fit for better auto-sizing
        self.flowgraph_widget.enableInitialSizeToFit()

        # Reset zoom to default scale
        self.flowgraph_widget.zoomToScale()

        # Use a timer to zoom out after the graph has been rendered
        # This ensures the graph is fully laid out before we try to fit it
        def delayed_zoom():
            # Zoom out a few times to fit more content
            for _ in range(3):
                self.flowgraph_widget.zoom(False)

        # Schedule the zoom for after the current event processing
        QTimer.singleShot(100, delayed_zoom)

        return

    def clear_graph(self) -> None:
        """Clear the current graph and show the helper message"""
        self._bv = None
        self._path = None
        self._path_id = None
        self._nodes_map = {}

        # Override paint event to show helper message
        if hasattr(self, "flowgraph_widget_paintEvent"):
            self.flowgraph_widget.paintEvent = self.helperPaintEvent

        # Clear the graph
        empty_graph = FlowGraph()
        self.flowgraph_widget.setGraph(empty_graph)
        return

    def on_checkbox_toggled(self, _: bool) -> None:
        # Reload the graph with the new filter state if a graph was loaded
        if self._bv and self._path is not None and self._path_id is not None:
            self.load_path(self._bv, self._path, self._path_id)
        return
