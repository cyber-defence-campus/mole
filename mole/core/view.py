from __future__   import annotations
from ..common.log import Logger
from ..main       import Controller
from ..ui.graph   import GraphWidget
from typing       import Any, Literal, Tuple
import binaryninja       as bn
import binaryninjaui     as bnui
import os                as os
import PySide6.QtCore    as qtc
import PySide6.QtGui     as qtui
import PySide6.QtWidgets as qtw


class SidebarView(bnui.SidebarWidgetType):
    """
    This class implements the view for the plugin's sidebar.
    """

    def __init__(
            self,
            ctr: Controller,
            tag: str,
            log: Logger
        ) -> None:
        """
        This method initializes a view (MVC pattern).
        """
        super().__init__(self._init_icon(), "Mole")
        self._ctr: Controller = ctr
        self._tag: str = tag
        self._log: Logger = log
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
        return
    
    def init(self) -> SidebarWidget:
        """
        This method initializes the main widget.
        """
        self._wid = qtw.QTabWidget()
        self._wid.addTab(*self._init_run_tab())
        self._wid.addTab(*self._init_graph_tab())
        self._wid.addTab(*self._init_cnf_tab())
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
                self._ctr.log_path(tbl, rows)
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
    
    def _init_cnf_tab(self) -> Tuple[qtw.QWidget, str]:
        """
        This method initializes the tab `Configure`.
        """
        tab = qtw.QTabWidget()
        tab.addTab(*self._init_cnf_fun_tab("Sources"))
        tab.addTab(*self._init_cnf_fun_tab("Sinks"))
        tab.addTab(*self._init_cnf_set_tab())
        but = self._init_cnf_but()
        lay = qtw.QVBoxLayout()
        lay.addWidget(tab)
        lay.addWidget(but)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid, "Configure"

    def _init_cnf_fun_tab(self, tab_name: Literal["Sources", "Sinks"]) -> Tuple[qtw.QWidget, str]:
        """
        This method initializes the tabs `Sources` and `Sinks`.
        """
        tab_wid = qtw.QTabWidget()
        for lib in self._ctr.get_libraries(tab_name).values():
            lib_lay = qtw.QVBoxLayout()
            lib_wid = qtw.QWidget()
            lib_wid.setLayout(lib_lay)
            for cat in lib.categories.values():
                # Function widget
                fun_lay = qtw.QFormLayout()
                for fun in cat.functions.values():
                    fun.checkbox = qtw.QCheckBox(fun.name)
                    fun.checkbox.setChecked(fun.enabled)
                    fun.checkbox.setToolTip(fun.synopsis)
                    fun.checkbox.clicked.connect(
                        lambda _, fun=fun: self._ctr.checkbox_toggle(fun)
                    )
                    fun_lay.addRow(fun.checkbox)
                fun_wid = qtw.QWidget()
                fun_wid.setLayout(fun_lay)
                # Button widget
                sel_but = qtw.QPushButton("Select All")
                sel_but.clicked.connect(
                    lambda _, cat=cat, checked=True: self._ctr.checkboxes_check(cat, checked)
                )
                dsl_but = qtw.QPushButton("Deselect All")
                dsl_but.clicked.connect(
                    lambda _, cat=cat, checked=False: self._ctr.checkboxes_check(cat, checked)
                )
                but_lay = qtw.QHBoxLayout()
                but_lay.addWidget(sel_but)
                but_lay.addWidget(dsl_but)
                but_wid = qtw.QWidget()
                but_wid.setLayout(but_lay)
                # Box widget
                box_lay = qtw.QVBoxLayout()
                box_lay.addWidget(fun_wid)
                box_lay.addWidget(but_wid)
                box_wid = qtw.QGroupBox(f"{cat.name:s}:")
                box_wid.setLayout(box_lay)
                lib_lay.addWidget(box_wid)
            scr_wid = qtw.QScrollArea()
            scr_wid.setWidget(lib_wid)
            scr_wid.setWidgetResizable(True)
            tab_wid.addTab(scr_wid, lib.name)
        lay = qtw.QVBoxLayout()
        lay.addWidget(tab_wid)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid, tab_name
    
    def _init_cnf_set_tab(self) -> Tuple[qtw.QWidget, str]:
        """
        This method initializes the tab `Settings`.
        """
        settings = self._ctr.get_settings()
        com_wid = qtw.QWidget()
        com_lay = qtw.QFormLayout()
        mcl_name = "max_call_level"
        mcl = settings.get(mcl_name, None)
        if mcl:
            mcl.widget = qtw.QSpinBox()
            mcl.widget.setRange(mcl.min_value, mcl.max_value)
            mcl.widget.setValue(mcl.value)
            mcl.widget.setToolTip(mcl.help)
            mcl.widget.valueChanged.connect(
                lambda value, setting=mcl: self._ctr.spinbox_change_value(setting, value)
            )
            mcl_lbl = qtw.QLabel(f"{mcl_name:s}:")
            mcl_lbl.setToolTip(mcl.help)
            com_lay.addRow(mcl_lbl, mcl.widget)
        msd_name = "max_slice_depth"
        msd = settings.get(msd_name, None)
        if msd:
            msd.widget = qtw.QSpinBox()
            msd.widget.setRange(msd.min_value, msd.max_value)
            msd.widget.setValue(msd.value)
            msd.widget.setToolTip(msd.help)
            msd.widget.valueChanged.connect(
                lambda value, setting=msd: self._ctr.spinbox_change_value(setting, value)
            )
            msd_lbl = qtw.QLabel(f"{msd_name:s}:")
            msd_lbl.setToolTip(msd.help)
            com_lay.addRow(msd_lbl, msd.widget)
        com_wid.setLayout(com_lay)
        com_box_lay = qtw.QVBoxLayout()
        com_box_lay.addWidget(com_wid)
        com_box_wid = qtw.QGroupBox("Common:")
        com_box_wid.setLayout(com_box_lay)
        pth_wid = qtw.QWidget()
        pth_lay = qtw.QFormLayout()
        col_name = "highlight_color"
        col = settings.get(col_name, None)
        if col:
            col.widget = qtw.QComboBox()
            col.widget.addItems(col.items)
            if col.value in col.items:
                col.widget.setCurrentText(col.value)
            col.widget.setToolTip(col.help)
            col.widget.currentTextChanged.connect(
                lambda value, setting=col: self._ctr.combobox_change_value(setting, value)
            )
            col_lbl = qtw.QLabel(f"{col_name:s}:")
            pth_lay.addRow(col_lbl, col.widget)
        pth_wid.setLayout(pth_lay)
        pth_box_lay = qtw.QVBoxLayout()
        pth_box_lay.addWidget(pth_wid)
        pth_box_wid = qtw.QGroupBox("Path Identification:")
        pth_box_wid.setLayout(pth_box_lay)
        lay = qtw.QVBoxLayout()
        lay.addWidget(com_box_wid)
        lay.addWidget(pth_box_wid)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid, "Settings"
    
    def _init_cnf_but(self) -> qtw.QWidget:
        """
        This method initializes the buttons.
        """
        sav_but = qtw.QPushButton("Save")
        sav_but.clicked.connect(
            lambda _=None,
            button=sav_but: self._ctr.store_main_conf_file(button)
        )
        rst_but = qtw.QPushButton("Reset")
        rst_but.clicked.connect(
            lambda _=None,
            button=rst_but: self._ctr.reset_conf(button)
        )
        lay = qtw.QHBoxLayout()
        lay.addWidget(sav_but)
        lay.addWidget(rst_but)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid
    
    def notifyViewChanged(self, vf: bnui.ViewFrame) -> None:
        """
        This method is a callback invoked when the active view in the Binary UI changes.
        """
        if vf:
            self._bv = vf.getCurrentBinaryView()
        else:
            self._bv = None
        return