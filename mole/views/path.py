from __future__ import annotations
from mole.views.graph import GraphWidget
from mole.views.path_tree import PathTreeView
from typing import Optional, Tuple, TYPE_CHECKING
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
    signal_find_paths_feedback = qtc.Signal(object, object, int)
    signal_load_paths = qtc.Signal()
    signal_load_paths_feedback = qtc.Signal(object, object, int)
    signal_save_paths = qtc.Signal()
    signal_save_paths_feedback = qtc.Signal(object, object, int)
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
        This method sets the controller and initializes relevant UI components.
        """
        # Set controller
        self.path_ctr = path_ctr
        # Tab widget
        self._wid = qtw.QTabWidget()
        self._wid.addTab(*self._init_path_tab())
        self._wid.addTab(*self._init_graph_tab())
        self._wid.addTab(self.path_ctr.ai_ctr.ai_view, "AI Report")
        self._wid.addTab(self.path_ctr.config_ctr.config_view, "Configure")

        # Scroll widget
        scr_wid = qtw.QScrollArea()
        scr_wid.setWidgetResizable(True)
        # We take into account the binary ninja sidebar
        # TODO: how to properly add margin only when docked?
        scr_wid.setViewportMargins(0, 0, self.SIDEBAR_RIGHT_MARGIN, 0)
        scr_wid.setWidget(self._wid)

        # Main layout
        main_lay = qtw.QVBoxLayout()
        main_lay.addWidget(scr_wid)
        self.setLayout(main_lay)
        # Setup path tree
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
        self.signal_find_paths_feedback.connect(
            lambda tmp_text, new_text, msec: self.give_feedback(
                self._run_but, tmp_text, new_text, msec
            )
        )
        self._load_but = qtw.QPushButton("Load")
        self._load_but.clicked.connect(self.signal_load_paths.emit)
        self.signal_load_paths_feedback.connect(
            lambda tmp_text, new_text, msec: self.give_feedback(
                self._load_but, tmp_text, new_text, msec
            )
        )
        self._save_but = qtw.QPushButton("Save")
        self._save_but.clicked.connect(self.signal_save_paths.emit)
        self.signal_save_paths_feedback.connect(
            lambda tmp_text, new_text, msec: self.give_feedback(
                self._save_but, tmp_text, new_text, msec
            )
        )

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

        # Connect signals
        self.path_tree_view.path_tree_model.signal_path_modified.connect(
            lambda: self.give_feedback(self._save_but, "Save*", "Save*", 0)
        )

        return wid, "Paths"

    def _init_graph_tab(self) -> Tuple[qtw.QWidget, str]:
        return GraphWidget(), "Graph"

    def give_feedback(
        self,
        button: qtw.QPushButton,
        tmp_text: str = None,
        new_text: str = None,
        msec: int = 1000,
    ) -> None:
        """
        This method changes `button`'s text to `tmp_text` for `msec` milliseconds and then back to
        `new_text`. If `tmp_text` is `None` or `msec` is less than or equal to 0, it directly sets
        the button's text to `new_text`. If `new_text` is `None`, it restores the current text of
        the button.
        """

        def restore(text: str) -> None:
            button.setText(text)
            button.setEnabled(True)
            return

        if button:
            if new_text is None:
                new_text = button.text()
            if tmp_text is not None and msec > 0:
                button.setEnabled(False)
                button.setText(tmp_text)
                qtc.QTimer.singleShot(msec, lambda text=new_text: restore(text))
            else:
                button.setText(new_text)
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

    def show_ai_report_tab(self) -> None:
        """
        This method switches to the AI Report tab.
        """
        for i in range(self._wid.count()):
            if self._wid.tabText(i) == "AI Report":
                self._wid.setCurrentIndex(i)
                break
        return
