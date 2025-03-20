from __future__     import annotations
from ..common.log   import Logger
from ..views.graph  import GraphWidget
from .path_tree     import PathTreeView
from typing         import Literal, Optional, Tuple, TYPE_CHECKING
import binaryninja       as bn
import binaryninjaui     as bnui
import os                as os
import PySide6.QtCore    as qtc
import PySide6.QtWidgets as qtw

if TYPE_CHECKING:
    from ..controllers.path import PathController


class PathView(bnui.SidebarWidget):
    """
    This class implements the widget for the plugin's sidebar.
    """

    signal_find_paths = qtc.Signal(object, object)
    signal_load_paths = qtc.Signal(object, object)
    signal_save_paths = qtc.Signal(object)
    signal_setup_path_tree = qtc.Signal(object, object, object)

    def __init__(
            self,
            tag: str,
            log: Logger
        ) -> None:
        """
        This method initializes a sidebar widget.
        """
        # Initialization
        super().__init__("Mole")
        self._bv: Optional[bn.BinaryView] = None
        self._wid: Optional[qtw.QTabWidget] = None
        self.path_ctr: Optional[PathController] = None
        self.path_tree_view: Optional[PathTreeView] = None
        # Logging
        self._tag: str = tag
        self._log: Logger = log
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
        lay = qtw.QVBoxLayout()
        lay.addWidget(self._wid)
        self.setLayout(lay)
        return self
    
    def _init_path_tab(self) -> Tuple[qtw.QWidget, str]:
        """
        This method initializes the tab `Path`.
        """
        # Create the path tree view
        self.path_tree_view = PathTreeView()
        
        # Create the layout for the tree
        res_lay = qtw.QVBoxLayout()
        res_lay.addWidget(self.path_tree_view)
        res_wid = qtw.QGroupBox("Interesting Paths:")
        res_wid.setLayout(res_lay)
        
        # Create control buttons
        self._run_but = qtw.QPushButton("Find")
        self._run_but.clicked.connect(
            lambda: self.signal_find_paths.emit(self._bv, self.path_tree_view)
        )
        self._load_but = qtw.QPushButton("Load")
        self._load_but.clicked.connect(
            lambda: self.signal_load_paths.emit(self._bv, self.path_tree_view)
        )
        self._save_but = qtw.QPushButton("Save")
        self._save_but.clicked.connect(
            lambda: self.signal_save_paths.emit(self._bv)
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
        lay.addWidget(res_wid)
        lay.addWidget(but_wid)
        wid = qtw.QWidget()
        wid.setLayout(lay)       
        
        return wid, "Path"
    
    def _init_graph_tab(self) -> Tuple[qtw.QWidget, str]:
        return GraphWidget(self._tag, self._log), "Graph"
    
    def give_feedback(
            self,
            button_type: Literal["Find", "Load", "Save"],
            text: str,
            msec: int = 1000
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

        def restore(text: str) -> None:
            button.setText(text)
            button.setEnabled(True)
            return

        if button:
            button.setEnabled(False)
            old_text = button.text()
            button.setText(text)
            qtc.QTimer.singleShot(msec, lambda text=old_text: restore(text))
        return
    
    def notifyViewChanged(self, vf: bnui.ViewFrame) -> None:
        """
        This method is a callback invoked when the active view in the Binary UI changes.
        """
        if vf:
            new_bv: bn.BinaryView = vf.getCurrentBinaryView()
            if new_bv != self._bv:
                self._bv = new_bv
                if self.path_tree_view and self._wid:
                    self.signal_setup_path_tree.emit(new_bv, self.path_tree_view, self._wid)
        else:
            self._bv = None
        return