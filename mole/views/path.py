from __future__ import annotations
from mole.views.graph import GraphWidget
from mole.views.path_tree import PathTreeView
from typing import Literal, Optional, Tuple, TYPE_CHECKING
import binaryninja as bn
import binaryninjaui as bnui
import os as os
import PySide6.QtCore as qtc
import PySide6.QtWidgets as qtw

if TYPE_CHECKING:
    from mole.controllers.path import PathController


class PathView(bnui.SidebarWidget):
    """
    This class implements the widget for the plugin's sidebar.
    """

    signal_find_paths = qtc.Signal()
    signal_load_paths = qtc.Signal()
    signal_save_paths = qtc.Signal()
    signal_setup_path_tree = qtc.Signal(object, object, object)

    def __init__(self) -> None:
        """
        This method initializes a sidebar widget.
        """
        # Initialization
        super().__init__("Mole")
        self._bv: Optional[bn.BinaryView] = None
        self._wid: Optional[qtw.QTabWidget] = None
        self.path_ctr: Optional[PathController] = None
        self.path_tree_view: Optional[PathTreeView] = None
        return

    def init(self, path_ctr: PathController) -> PathView:
        """
        This method sets the controller and initializes relevant UI widgets.
        """
        # Set controller
        self.path_ctr = path_ctr
        # Initialize UI widgets
        self._wid = qtw.QTabWidget()
        self._wid.addTab(*self._init_path_tab())
        self._wid.addTab(*self._init_graph_tab())
        self._wid.addTab(self.path_ctr.config_ctr.config_view, "Configure")
        scr = qtw.QScrollArea()
        scr.setWidget(self._wid)
        scr.setWidgetResizable(True)
        lay = qtw.QVBoxLayout()
        lay.addWidget(scr)
        self.setLayout(lay)
        self.signal_setup_path_tree.emit(self._bv, self.path_tree_view, self._wid)
        return self

    def _init_path_tab(self) -> Tuple[qtw.QWidget, str]:
        """
        This method initializes the tab `Path`.
        """
        # Create the path tree view
        self.path_tree_view = PathTreeView()

        # Create control buttons
        self._run_but = qtw.QPushButton("Find")
        self._run_but.clicked.connect(self.signal_find_paths.emit)
        self._load_but = qtw.QPushButton("Load")
        self._load_but.clicked.connect(self.signal_load_paths.emit)
        self._save_but = qtw.QPushButton("Save")
        self._save_but.clicked.connect(self.signal_save_paths.emit)

        # Set up button layout
        but_lay = qtw.QHBoxLayout()
        but_lay.addWidget(self._run_but)
        but_lay.addWidget(self._load_but)
        but_lay.addWidget(self._save_but)
        but_wid = qtw.QWidget()
        but_wid.setLayout(but_lay)

        # Set up main layout
        lay = qtw.QVBoxLayout()
        lay.addWidget(self.path_tree_view)
        lay.addWidget(but_wid)
        wid = qtw.QWidget()
        wid.setLayout(lay)

        return wid, "Paths"

    def _init_graph_tab(self) -> Tuple[qtw.QWidget, str]:
        return GraphWidget(), "Graph"

    def give_feedback(
        self,
        button_type: Optional[Literal["Find", "Load", "Save"]] = None,
        button_text: str = "",
        msec: int = 1000,
    ) -> None:
        """
        This method gives user feedback by temporarily changing a button's text.
        """
        match button_type:
            case "Find":
                button = self._run_but
            case "Load":
                button = self._load_but
            case "Save":
                button = self._save_but
            case _:
                return

        def restore(text: str) -> None:
            button.setText(text)
            button.setEnabled(True)
            return

        if button:
            button.setEnabled(False)
            old_text = button.text()
            button.setText(button_text)
            qtc.QTimer.singleShot(msec, lambda text=old_text: restore(text))
        return

    def notifyViewChanged(self, vf: bnui.ViewFrame) -> None:
        """
        This method is a callback invoked when the active view in the Binary UI changes.
        """
        new_bv = vf.getCurrentBinaryView() if vf else None
        if new_bv != self._bv:
            self._bv = new_bv
            self.signal_setup_path_tree.emit(new_bv, self.path_tree_view, self._wid)
        return
