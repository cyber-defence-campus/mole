from __future__ import annotations
from typing import cast
import binaryninja as bn
import binaryninjaui as bnui
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui
import PySide6.QtWidgets as qtw


class GraphView(qtw.QWidget):
    """
    This class implements a view for Mole's graph tab.
    """

    signal_show_graph_tab = qtc.Signal()
    signal_update_graph = qtc.Signal()

    def __init__(self) -> None:
        """
        This method initializes the graph view.
        """
        super().__init__()
        self._init_widgets()
        return

    def _init_widgets(self) -> None:
        """
        This method initializes the graph view's widgets.
        """
        # Graph widget
        self._flow_graph = bn.FlowGraph()
        self._graph_wid = bnui.FlowGraphWidget(self, None, self._flow_graph)  # type: ignore
        # Fit to view action
        fit_to_view_action = qtui.QAction("Fit to View", self)
        fit_to_view_action.triggered.connect(self._fit_to_view)
        # In-path only action
        self._in_path_only_action = qtui.QAction("In-Path Only", self)
        self._in_path_only_action.setCheckable(True)
        self._in_path_only_action.setChecked(True)
        self._in_path_only_action.triggered.connect(self.signal_update_graph.emit)
        # Spacer widget
        spacer_wid = qtw.QWidget()
        spacer_wid.setSizePolicy(
            qtw.QSizePolicy.Policy.Expanding, qtw.QSizePolicy.Policy.Preferred
        )
        # Legend widget
        self._legend_wid = qtw.QLabel()
        # Toolbar widget
        toolbar_wid = qtw.QToolBar("Graph Toolbar")
        toolbar_wid.addAction(fit_to_view_action)
        toolbar_wid.addAction(self._in_path_only_action)
        toolbar_wid.addWidget(spacer_wid)
        toolbar_wid.addWidget(self._legend_wid)
        # Tab layout
        tab_lay = qtw.QVBoxLayout()
        tab_lay.addWidget(self._graph_wid)
        tab_lay.addWidget(toolbar_wid)
        self.setLayout(tab_lay)
        return

    @property
    def in_path_only(self) -> bool:
        """
        This method returns whether or not the in-path only mode is enabled.
        """
        return self._in_path_only_action.isChecked()

    def _zoom_to_scale(self, scale: float | None = None) -> None:
        """
        This method zooms the graph to the given scale or the previous scale if none is given.
        """
        # Store scale
        if scale is not None:
            self._scale = scale
        # Zoom to scale
        if self._scale is not None:
            self._graph_wid.zoomToScale(self._scale)
        # Try to center the view
        try:
            self._graph_wid.showTopNode()
        except Exception:
            pass
        return

    def _fit_to_view(self, min_scale: float = 0.05, padding: int = 10) -> None:
        """
        This method fits the flow graph into the visible view.
        """
        # Get graph dimensions
        gw = max(self._flow_graph.width, 1)
        gh = max(self._flow_graph.height, 1)
        vw = max(self._graph_wid.width(), 1)
        vh = max(self._graph_wid.height(), 1)
        # Calculate scale
        scale_w = (vw - padding) / float(gw)
        scale_h = (vh - padding) / float(gh)
        max_scale = self._graph_wid.maxScale()
        scale = max(min_scale, min(scale_w, scale_h, max_scale))
        # Zoom to scale
        self._zoom_to_scale(scale)
        return

    def set_flow_graph(
        self,
        bv: bn.BinaryView,
        path_id: int,
        flow_graph: bn.FlowGraph,
        show_tab: bool = True,
    ) -> None:
        """
        This method displays the given flow graph.
        """
        # Set tooltip
        self.setToolTip(f"Path {path_id:d}")
        # Replace graph
        self._flow_graph = flow_graph
        tab_lay = cast(qtw.QVBoxLayout, self.layout())
        wid_idx = tab_lay.indexOf(self._graph_wid)
        tab_lay.removeWidget(self._graph_wid)
        self._graph_wid.deleteLater()
        self._graph_wid = bnui.FlowGraphWidget(self, bv, self._flow_graph)  # type: ignore
        tab_lay.insertWidget(wid_idx, self._graph_wid)
        # Switch to graph tab
        if show_tab:
            self.signal_show_graph_tab.emit()
            qtc.QTimer.singleShot(10, self._fit_to_view)
        else:
            self._zoom_to_scale()
        return

    def set_legend(
        self,
        src_color: bn.HighlightStandardColor,
        snk_color: bn.HighlightStandardColor,
        in_path_color: bn.HighlightStandardColor,
    ) -> None:
        """
        This method displays the flow graph legend with the given colors.
        """
        src_theme_color: qtui.QColor = bnui.getThemeHighlightColor(src_color)  # type: ignore
        snk_theme_color: qtui.QColor = bnui.getThemeHighlightColor(snk_color)  # type: ignore
        in_path_theme_color: qtui.QColor = bnui.getThemeHighlightColor(in_path_color)  # type: ignore
        self._legend_wid.setText(
            (
                f'<span style="color: {src_theme_color.name()};">Source</span> | '
                f'<span style="color: {snk_theme_color.name()};">Sink</span> | '
                f'<span style="color: {in_path_theme_color.name()};">In-Path</span>'
            )
        )
        return
