from __future__   import annotations
from ..common.log import Logger
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..main       import Controller
from ..ui.graph   import GraphWidget
from .data        import SpinboxSetting
from typing       import Any, Literal, Tuple
import binaryninja       as bn
import binaryninjaui     as bnui
import os                as os
import PySide6.QtCore    as qtc
import PySide6.QtGui     as qtui
import PySide6.QtWidgets as qtw
from ..controllers.config import ConfigController
from ..models.config import ConfigModel
from ..views.config import ConfigView


class SidebarView(bnui.SidebarWidgetType):
    """
    This class implements the view for the plugin's sidebar.
    """

    def __init__(
            self,
            tag: str,
            log: Logger
        ) -> None:
        """
        This method initializes a view (MVC pattern).
        """
        super().__init__(self._init_icon(), "Mole")
        self._ctr: Controller = None
        self._tag: str = tag
        self._log: Logger = log
        return
    
    def set_controller(self, ctr: Controller) -> None:
        """
        This method sets the controller for the model.
        """
        self._ctr = ctr
        return
    
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
        return SidebarWidget(self._ctr, self._tag, self._log).init()
    
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


class SidebarWidget(bnui.SidebarWidget):
    """
    This class implements the widget for the plugin's sidebar.
    """

    def __init__(
            self,
            ctr: Controller,
            tag: str,
            log: Logger
        ) -> None:
        """
        This method initializes a sidebar widget.
        """
        super().__init__("Mole")
        self._ctr: Controller = ctr
        self._tag: str = tag
        self._log: Logger = log
        self._bv: bn.BinaryView = None
        self._wid: qtw.QTabWidget = None
        
        # Initialize config components
        self._config_model = ConfigModel()
        self._config_controller = ConfigController(self._config_model, self._ctr, self._log)
        self._config_view = ConfigView(self._config_controller, self._tag, self._log)
        return
    
    def init(self) -> SidebarWidget:
        """
        This method initializes the main widget.
        """
        self._config_controller.load_custom_conf_files()
        self._config_controller.load_main_conf_file()

        self._wid = qtw.QTabWidget()
        self._wid.addTab(*self._init_run_tab())
        self._wid.addTab(*self._init_graph_tab())
        self._wid.addTab(*self._config_view.get_tab())
        lay = qtw.QVBoxLayout()
        lay.addWidget(self._wid)
        self.setLayout(lay)
        return self
    
    def _init_run_tab(self) -> Tuple[qtw.QWidget, str]:
        """
        This method initializes the tab `Run`.
        """

        def _navigate(bv: bn.BinaryView, tbl: qtw.QTableWidget, row: int, col: int) -> None:
            """
            This method navigate in the view frame.
            """
            ctx = bnui.UIContext.activeContext()
            if not ctx: return
            vf = ctx.getCurrentViewFrame()
            if not vf: return
            if not tbl: return
            if col in [1, 2]:
                vf.navigate(bv, int(tbl.item(row, 1).text(), 16))
            elif col in [3, 4, 5]:
                vf.navigate(bv, int(tbl.item(row, 3).text(), 16))            
            return
        
        def _show_context_menu(tbl: qtw.QTableWidget, pos: qtc.QPoint) -> None:
            """
            This method shows a custom context menu.
            """
            if tbl is None: return
            rows = list({index.row() for index in tbl.selectionModel().selectedIndexes()})
            row = tbl.indexAt(pos).row()
            col = tbl.indexAt(pos).column()

            menu = qtw.QMenu(tbl)
            menu_action_log_path = menu.addAction("Log instructions")
            menu_action_log_path_reversed = menu.addAction("Log instructions (reversed)")
            if len(rows) != 1:
                menu_action_log_path.setEnabled(False)
                menu_action_log_path_reversed.setEnabled(False)

            menu_action_log_path_diff = menu.addAction("Log instruction difference")
            if len(rows) != 2:
                menu_action_log_path_diff.setEnabled(False)
            menu.addSeparator()
            menu_action_highlight_path = menu.addAction("Un-/highlight instructions")
            menu_action_show_call_graph = menu.addAction("Show call graph")
            if len(rows) != 1:
                menu_action_highlight_path.setEnabled(False)
                menu_action_show_call_graph.setEnabled(False)
            menu.addSeparator()
            menu_action_import_paths = menu.addAction("Import from file")
            menu_action_export_paths = menu.addAction("Export to file")
            if tbl.rowCount() <= 0:
                menu_action_export_paths.setEnabled(False)
            menu.addSeparator()
            menu_action_remove_selected_path = menu.addAction("Remove selected")
            if len(rows) <= 0:
                menu_action_remove_selected_path.setEnabled(False)
            menu_action_remove_all_paths = menu.addAction("Remove all")
            if tbl.rowCount() <= 0:
                menu_action_remove_all_paths.setEnabled(False)

            menu_action = menu.exec(tbl.mapToGlobal(pos))
            if not menu_action: return
            if menu_action == menu_action_log_path:
                self._ctr.log_path(tbl, rows, False)
            elif menu_action == menu_action_log_path_reversed:
                self._ctr.log_path(tbl, rows, True)
            elif menu_action == menu_action_log_path_diff:
                self._ctr.log_path_diff(tbl, rows)
            elif menu_action == menu_action_highlight_path:
                self._ctr.highlight_path(self._bv, tbl, rows)
            elif menu_action == menu_action_show_call_graph:
                self._ctr.show_call_graph(self._bv, tbl, rows, self._wid)
            elif menu_action == menu_action_import_paths:
                self._ctr.import_paths(self._bv, tbl)
            elif menu_action == menu_action_export_paths:
                self._ctr.export_paths(self._bv, tbl, rows)
            elif menu_action == menu_action_remove_selected_path:
                self._ctr.remove_selected_paths(tbl, rows)
            elif menu_action == menu_action_remove_all_paths:
                self._ctr.remove_all_paths(tbl)
            return

        res_tbl = qtw.QTableWidget()
        res_tbl.setSelectionMode(qtw.QAbstractItemView.SelectionMode.ExtendedSelection)
        res_tbl.setSelectionBehavior(qtw.QAbstractItemView.SelectionBehavior.SelectRows)
        res_tbl.setSortingEnabled(True)
        res_tbl.verticalHeader().setVisible(False)
        res_tbl.setContextMenuPolicy(qtc.Qt.ContextMenuPolicy.CustomContextMenu)
        res_tbl.customContextMenuRequested.connect(
            lambda pos: _show_context_menu(res_tbl, pos)
        )
        res_tbl.setColumnCount(10)
        res_tbl.setHorizontalHeaderLabels(["Index", "Src Addr", "Src Func", "Snk Addr", "Snk Func", "Snk Parm", "Insts", "Phis", "Branches", "Comment"])
        res_tbl.cellDoubleClicked.connect(
            lambda row, col: _navigate(self._bv, res_tbl, row, col)
        )
        res_lay = qtw.QVBoxLayout()
        res_lay.addWidget(res_tbl)
        res_wid = qtw.QGroupBox("Interesting Paths:")
        res_wid.setLayout(res_lay)
        run_but = qtw.QPushButton("Find")
        run_but.clicked.connect(
            lambda: self._ctr.find_paths(bv=self._bv, but=run_but, tbl=res_tbl)
        )
        lod_but = qtw.QPushButton("Load")
        lod_but.clicked.connect(
            lambda: self._ctr.load_paths(bv=self._bv, but=lod_but, tbl=res_tbl)
        )
        sav_but = qtw.QPushButton("Save")
        sav_but.clicked.connect(
            lambda: self._ctr.save_paths(bv=self._bv, but=sav_but, tbl=res_tbl)
        )
        but_lay = qtw.QHBoxLayout()
        but_lay.addWidget(run_but)
        but_lay.addWidget(lod_but)
        but_lay.addWidget(sav_but)
        but_wid = qtw.QWidget()
        but_wid.setLayout(but_lay)
        lay = qtw.QVBoxLayout()
        lay.addWidget(res_wid)
        lay.addWidget(but_wid)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid, "Run"
    
    def _init_graph_tab(self) -> Tuple[qtw.QWidget, str]:
        return GraphWidget(self._tag, self._log), "Graph"
    
    def notifyViewChanged(self, vf: bnui.ViewFrame) -> None:
        """
        This method is a callback invoked when the active view in the Binary UI changes.
        """
        if vf:
            self._bv = vf.getCurrentBinaryView()
        else:
            self._bv = None
        return