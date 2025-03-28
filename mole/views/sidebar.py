from __future__ import annotations
from mole.views.path import PathView
from typing import Any
import binaryninjaui as bnui
import os as os
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui


class MoleSidebar(bnui.SidebarWidgetType):
    """
    This class implements the view for the plugin's sidebar.
    """

    def __init__(self, sidebar_view: PathView) -> None:
        """
        This method initializes a view (MVC pattern).
        """
        super().__init__(self._init_icon(), "Mole")
        self._sidebar_view = sidebar_view
        return

    def _init_icon(self) -> qtui.QImage:
        """
        This method initializes the sidebar's icon.
        """
        icon = qtui.QImage(
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "../../resources/icon.png"
            )
        )
        if icon.isNull():
            icon = qtui.QImage(56, 56, qtui.QImage.Format_RGB32)
            icon.fill(0)
            p = qtui.QPainter()
            p.begin(icon)
            p.setFont(qtui.QFont("Open Sans", 12))
            p.setPen(qtui.QColor(255, 255, 255, 255))
            p.drawText(qtc.QRectF(0, 0, 56, 56), qtc.Qt.AlignCenter, "MOLE")
            p.end()
        return icon

    def init(self) -> PathView:
        """
        This method registers the sidebar with Binary Ninja.
        """
        bnui.Sidebar.addSidebarWidgetType(self)
        return self

    def createWidget(self, frame: Any, data: Any) -> PathView:
        """
        This method creates the sidebar's widget.
        """
        return self._sidebar_view

    def defaultLocation(self) -> bnui.SidebarWidgetLocation:
        """
        This method places the widget to the right sidebar.
        """
        return bnui.SidebarWidgetLocation.RightContent

    def contextSensitivity(self) -> bnui.SidebarContextSensitivity:
        """
        This method configures the widget to use a single instance that detects changes.
        """
        return bnui.SidebarContextSensitivity.SelfManagedSidebarContext
