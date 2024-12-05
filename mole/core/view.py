from __future__   import annotations
from ..common.log import Logger
from ..main       import Controller
from typing       import Any, Literal, Tuple
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
            tag: str = "Sidebar",
            log: Logger = Logger()
        ) -> None:
        super().__init__(self._init_icon(), "Mole")
        self._ctr = ctr
        self._tag = tag
        self._log = log
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
            tag: str = "Sidebar",
            log: Logger = Logger()
        ) -> None:
        super().__init__("Mole")
        self._ctr = ctr
        self._tag = tag
        self._log = log
        self._bv = None
        return
    
    def init(self) -> SidebarWidget:
        """
        This method initiliazes the main widget.
        """
        tab = qtw.QTabWidget()
        tab.addTab(*self._init_cnf_tab())
        tab.addTab(*self._init_run_tab())
        lay = qtw.QVBoxLayout()
        lay.addWidget(tab)
        self.setLayout(lay)
        return self
    
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
        for _, lib in self._ctr.get_libraries(tab_name).items():
            lib_lay = qtw.QVBoxLayout()
            lib_wid = qtw.QWidget()
            lib_wid.setLayout(lib_lay)
            for _, cat in lib.categories.items():
                # Function widget
                fun_lay = qtw.QFormLayout()
                for _, fun in cat.functions.items():
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
        com_wid = qtw.QWidget()
        com_lay = qtw.QFormLayout()
        settings = self._ctr.get_settings()
        mfd_name = "max_func_depth"
        mfd = settings.get(mfd_name, None)
        if mfd:
            mfd.widget = qtw.QSpinBox()
            mfd.widget.setRange(mfd.min_value, mfd.max_value)
            mfd.widget.setValue(mfd.value)
            mfd.widget.setToolTip(mfd.help)
            mfd.widget.valueChanged.connect(
                lambda value, setting=mfd: self._ctr.spinbox_change_value(setting, value)
            )
            mfd_lbl = qtw.QLabel(mfd_name)
            mfd_lbl.setToolTip(mfd.help)
            com_lay.addRow(mfd.widget, mfd_lbl)
        com_wid.setLayout(com_lay)
        com_box_lay = qtw.QVBoxLayout()
        com_box_lay.addWidget(com_wid)
        com_box_wid = qtw.QGroupBox("Common:")
        com_box_wid.setLayout(com_box_lay)
        lay = qtw.QVBoxLayout()
        lay.addWidget(com_box_wid)
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
    
    def _init_run_tab(self) -> Tuple[qtw.QWidget, str]:
        """
        This method initializes the tab `Run`.
        """
        run_but = qtw.QPushButton("Run")
        run_but.clicked.connect(
            lambda _, but=run_but: self._ctr.analyze_binary(bv=self._bv, button=but)
        )
        run_box_lay = qtw.QVBoxLayout()
        run_box_lay.addWidget(run_but)
        run_box_wid = qtw.QGroupBox("Analyze Binary:")
        run_box_wid.setLayout(run_box_lay)
        lay = qtw.QVBoxLayout()
        lay.addWidget(run_box_wid)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid, "Run"
    
    def notifyViewChanged(self, vf: bnui.ViewFrame) -> None:
        """
        This method is a callback invoked when the active view in the Binary UI changes.
        """
        if vf:
            self._bv = vf.getCurrentBinaryView()
        else:
            self._bv = None
        return