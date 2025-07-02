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

    def show_ai_report_tab(self) -> None:
        """
        This method switches to the AI Report tab.
        """
        for i in range(self._wid.count()):
            if self._wid.tabText(i) == "AI Report":
                self._wid.setCurrentIndex(i)
                break
        return


class MyPopup(qtw.QDialog):
    """
    This class implements a popup dialog with a message.
    """

    def __init__(self, title: str, call_name: str, par_cnt: int, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(250)
        # Information layout
        ifo_lay = qtw.QGridLayout()
        ifo_lay.addWidget(qtw.QLabel("symbol_name:"), 0, 0)
        ifo_lay.addWidget(qtw.QLabel(call_name), 0, 1)
        ifo_lay.addWidget(qtw.QLabel("par_cnt:"), 1, 0)
        ifo_lay.addWidget(qtw.QLabel(str(par_cnt)), 1, 1)
        # Information widget
        ifo_wid = qtw.QGroupBox("Information:")
        ifo_wid.setLayout(ifo_lay)
        # Parameter slice widget
        par_slice_wid = qtw.QLineEdit("False")
        par_slice_wid.setToolTip(
            "Expression specifying which parameter 'i' to slice (e.g. 'i >= 1')"
        )
        all_code_xrefs_wid = qtw.QCheckBox()
        all_code_xrefs_wid.setToolTip("Include all symbol's code cross-references")
        # Configuration layout
        cnf_lay = qtw.QGridLayout()
        cnf_lay.addWidget(qtw.QLabel("par_slice:"), 0, 0)
        cnf_lay.addWidget(par_slice_wid, 0, 1)
        cnf_lay.addWidget(qtw.QLabel("all_code_xrefs:"), 1, 0)
        cnf_lay.addWidget(all_code_xrefs_wid, 1, 1)
        # Configuration widget
        cnf_wid = qtw.QGroupBox("Configuration:")
        cnf_wid.setLayout(cnf_lay)
        # Buttons
        find_but = qtw.QPushButton("Find")
        find_but.clicked.connect(self.accept)
        cancel_but = qtw.QPushButton("Cancel")
        cancel_but.clicked.connect(self.reject)
        # Button layout
        but_lay = qtw.QHBoxLayout()
        but_lay.addWidget(find_but)
        but_lay.addWidget(cancel_but)
        # Button widget
        but_wid = qtw.QWidget()
        but_wid.setLayout(but_lay)
        # Main layout
        main_lay = qtw.QVBoxLayout()
        main_lay.addWidget(ifo_wid)
        main_lay.addWidget(cnf_wid)
        main_lay.addWidget(but_wid)
        self.setLayout(main_lay)
        return
