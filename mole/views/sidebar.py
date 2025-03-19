from __future__     import annotations
from ..common.log   import Logger
from ..views.config import ConfigView
from ..views.graph  import GraphWidget
from .paths_tree    import PathsTreeView
from typing         import Any, Literal, Tuple, TYPE_CHECKING
import binaryninja       as bn
import binaryninjaui     as bnui
import os                as os
import PySide6.QtCore    as qtc
import PySide6.QtGui     as qtui
import PySide6.QtWidgets as qtw

if TYPE_CHECKING:
    from ..controllers.paths import PathController


class MoleSidebar(bnui.SidebarWidgetType):
    """
    This class implements the view for the plugin's sidebar.
    """

    def __init__(
            self,
            sidebar_view: SidebarView,
            tag: str,
            log: Logger
        ) -> None:
        """
        This method initializes a view (MVC pattern).
        """
        super().__init__(self._init_icon(), "Mole")
        self._sidebar_view = sidebar_view
        self._tag: str = tag
        self._log: Logger = log
    
    def _init_icon(self) -> qtui.QImage:
        """
        This method initializes the sidebar's icon.
        """
        icon = qtui.QImage(
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "../../images/icon.png"
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
    
    def init(self) -> SidebarView:
        """
        This method registers the sidebar with Binary Ninja.
        """
        bnui.Sidebar.addSidebarWidgetType(self)
        return self
    
    def createWidget(self, frame: Any, data: Any) -> SidebarView:
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


class SidebarView(bnui.SidebarWidget):
    """
    This class implements the widget for the plugin's sidebar.
    """

    signal_find_paths = qtc.Signal(object, object)
    signal_load_paths = qtc.Signal(object, object)
    signal_save_paths = qtc.Signal(object)
    signal_setup_path_tree = qtc.Signal(object, object, object)

    def __init__(
            self,
            config_view: ConfigView,
            tag: str,
            log: Logger
        ) -> None:
        """
        This method initializes a sidebar widget.
        """
        super().__init__("Mole")
        self._config_view: ConfigView = config_view
        self._tag: str = tag
        self._log: Logger = log
        self._bv: bn.BinaryView = None
        self._wid: qtw.QTabWidget = None
        self._ctr: PathController = None
        self._paths_tree_view: PathsTreeView = None
        return
    
    def init(self, ctr: PathController) -> SidebarView:
        """
        This method sets the controller, connects relevant signals and initializes all UI widgets.
        """
        # Set controller
        self._ctr = ctr
        # Connect signals
        self._ctr.connect_signal_setup_paths_tree(self._ctr.setup_paths_tree)
        self._ctr.connect_signal_find_paths(self._ctr.find_paths)
        self._ctr.connect_signal_load_paths(self._ctr.load_paths)
        self._ctr.connect_signal_save_paths(self._ctr.save_paths)
        # Initialize UI widgets
        self._wid = qtw.QTabWidget()
        self._wid.addTab(*self._init_run_tab())
        self._wid.addTab(*self._init_graph_tab())
        self._wid.addTab(self._config_view, "Configure")
        lay = qtw.QVBoxLayout()
        lay.addWidget(self._wid)
        self.setLayout(lay)
        return self
    
    # def _change_bv(self, bv: bn.BinaryView) -> None:
    #     """
    #     This method handles changes in the binary view.
    #     """
    #     if self._wid and self._ctr and self._paths_tree_view:
    #         self._ctr.setup_paths_tree(bv, self._paths_tree_view, self._wid)
    #     return
    
    def _init_run_tab(self) -> Tuple[qtw.QWidget, str]:
        """
        This method initializes the tab `Run`.
        """
        # Create the path tree view
        self._paths_tree_view = PathsTreeView()
        
        # Create the layout for the tree
        res_lay = qtw.QVBoxLayout()
        res_lay.addWidget(self._paths_tree_view)
        res_wid = qtw.QGroupBox("Interesting Paths:")
        res_wid.setLayout(res_lay)
        
        # Create control buttons
        self._run_but = qtw.QPushButton("Find")
        self._run_but.clicked.connect(
            lambda: self.signal_find_paths.emit(self._bv, self._paths_tree_view)
        )
        self._load_but = qtw.QPushButton("Load")
        self._load_but.clicked.connect(
            lambda: self.signal_load_paths.emit(self._bv, self._paths_tree_view)
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
        
        return wid, "Run"
    
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
    
    def _init_graph_tab(self) -> Tuple[qtw.QWidget, str]:
        return GraphWidget(self._tag, self._log), "Graph"
    
    def notifyViewChanged(self, vf: bnui.ViewFrame) -> None:
        """
        This method is a callback invoked when the active view in the Binary UI changes.
        """
        if vf:
            new_bv: bn.BinaryView = vf.getCurrentBinaryView()
            if new_bv != self._bv:
                self._bv = new_bv
                # TODO: Maybe do renaming
                # TODO: Do we need to add `if self._paths_tree_view and self._wid:`
                self.signal_setup_path_tree.emit(new_bv, self._paths_tree_view, self._wid)
        else:
            self._bv = None
        return