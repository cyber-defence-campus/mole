from __future__ import annotations
from mole.common.log import Logger
from mole.controllers.ai import AiController
from mole.controllers.config import ConfigController
from mole.controllers.graph import GraphController
from mole.controllers.path import PathController
from mole.controllers.sidebar import SidebarController
from mole.models.config import ConfigModel
from mole.models.path import PathProxyModel, PathTreeModel
from mole.services.ai import AiService
from mole.services.config import ConfigService
from mole.services.graph import GraphService
from mole.services.path import PathService
from mole.views.ai import AiView
from mole.views.config import ConfigDialog, ConfigView
from mole.views.graph import GraphView
from mole.views.path import PathTreeView, PathView
from typing import Dict
import binaryninja as bn
import binaryninjaui as bnui
import os
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui
import PySide6.QtWidgets as qtw


# BinaryView to SidebarController mapping
sidebar_ctrs: Dict[bn.BinaryView, SidebarController] = {}


class SidebarView(bnui.SidebarWidget):  # type: ignore
    """
    This class implements a view for Mole's sidebar.
    """

    def __init__(
        self,
        name: str,
        config_view: ConfigView,
        path_view: PathView,
        graph_view: GraphView,
        ai_view: AiView,
    ) -> None:
        """
        This method initializes the sidebar view.
        """
        super().__init__(name)
        self.bv: bn.BinaryView | None = None
        self._init_widgets(config_view, path_view, graph_view, ai_view)
        return

    def _init_widgets(
        self,
        config_view: ConfigView,
        path_view: PathView,
        graph_view: GraphView,
        ai_view: AiView,
    ) -> None:
        """
        This method initializes the sidebar view's widgets.
        """
        # Tabs widget
        self._tabs_wid = qtw.QTabWidget()
        self._tabs_wid.addTab(path_view, "Paths")
        self._tabs_wid.addTab(graph_view, "Graph")
        self._tabs_wid.addTab(ai_view, "AI Report")
        self._tabs_wid.addTab(config_view, "Config")
        # Scroll widget
        scroll_wid = qtw.QScrollArea()
        scroll_wid.setWidgetResizable(True)
        scroll_wid.setWidget(self._tabs_wid)
        # Sidebar layout
        sidebar_lay = qtw.QVBoxLayout()
        sidebar_lay.addWidget(scroll_wid)
        self.setLayout(sidebar_lay)
        return

    def show_tab(self, tab_name: str) -> None:
        """
        This method shows the sidebar's tab with the given name.
        """
        for tab_idx in range(self._tabs_wid.count()):
            tab_text = self._tabs_wid.tabText(tab_idx)
            if tab_text == tab_name:
                self._tabs_wid.setCurrentIndex(tab_idx)
                break
        return


class SidebarViewType(bnui.SidebarWidgetType):  # type: ignore
    """
    This class implements a view type for Mole's sidebar.
    """

    def __init__(self) -> None:
        """
        This method initializes the sidebar view type.
        """
        super().__init__(self._init_icon(), "Mole")
        return

    def _init_icon(self) -> qtui.QImage:
        """
        This method initializes the sidebar's icon.
        """
        icon = qtui.QImage(
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "../resources/icon.png"
            )
        )
        if icon.isNull():
            icon = qtui.QImage(56, 56, qtui.QImage.Format_RGB32)  # type: ignore
            icon.fill(0)
            p = qtui.QPainter()
            p.begin(icon)
            p.setFont(qtui.QFont("Open Sans", 12))
            p.setPen(qtui.QColor(255, 255, 255, 255))
            p.drawText(qtc.QRectF(0, 0, 56, 56), qtc.Qt.AlignCenter, "MOLE")  # type: ignore
            p.end()
        return icon

    def createWidget(self, frame: bnui.ViewFrame, bv: bn.BinaryView) -> SidebarView:  # type: ignore
        """
        This method creates the sidebar's widget.
        """
        # Logger
        log = Logger(bv)
        # Configuration components
        config_service = ConfigService(log)
        config_model = ConfigModel(config_service.load_config())
        config_view = ConfigView(config_model)
        config_dialog = ConfigDialog()
        config_ctr = ConfigController(
            bv, log, config_service, config_model, config_view, config_dialog
        )
        # Path components
        path_service = PathService(bv, log, config_model)
        path_proxy_model = PathProxyModel(PathTreeModel())
        path_view = PathView(PathTreeView(path_proxy_model))
        path_ctr = PathController(bv, log, path_service, path_proxy_model, path_view)
        # Graph components
        graph_service = GraphService(config_model)
        graph_view = GraphView()
        graph_ctr = GraphController(bv, graph_service, graph_view)
        # AI components
        ai_service = AiService(bv, log, config_model)
        ai_view = AiView()
        ai_ctr = AiController(bv, log, ai_service, ai_view)
        # Sidebar components
        sidebar_view = SidebarView("Mole", config_view, path_view, graph_view, ai_view)
        sidebar_ctr = SidebarController(
            bv, sidebar_view, config_ctr, path_ctr, graph_ctr, ai_ctr
        )
        # Store BinaryView to SidebarController mapping
        if bv not in sidebar_ctrs:
            sidebar_ctrs[bv] = sidebar_ctr
        return sidebar_view

    def defaultLocation(self) -> bnui.SidebarWidgetLocation:  # type: ignore
        """
        This method returns the sidebar's default location.
        """
        return bnui.SidebarWidgetLocation.RightContent  # type: ignore

    def contextSensitivity(self) -> bnui.SidebarContextSensitivity:  # type: ignore
        """
        This method returns the sidebar's context sensitivity.
        """
        return bnui.SidebarContextSensitivity.PerViewTypeSidebarContext  # type: ignore
