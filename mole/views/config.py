from __future__ import annotations
import PySide6.QtWidgets as qtw
from typing import TYPE_CHECKING, Literal, Tuple

from ..common.log import Logger
if TYPE_CHECKING:
    from ..controllers.config import ConfigController



class ConfigView:
    """
    This class implements the view for the plugin's configuration tab.
    """

    def __init__(self, controller: ConfigController, tag: str, log: Logger) -> None:
        """
        This method initializes the configuration view.
        """
        self._controller = controller
        self._tag = tag
        self._log = log
        return

    def get_tab(self) -> Tuple[qtw.QWidget, str]:
        """
        This method returns the configuration tab.
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
        for lib in self._controller.get_libraries(tab_name).values():
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
                        lambda _, fun=fun: self._controller.checkbox_toggle(fun)
                    )
                    fun_lay.addRow(fun.checkbox)
                fun_wid = qtw.QWidget()
                fun_wid.setLayout(fun_lay)
                # Button widget
                sel_but = qtw.QPushButton("Select All")
                sel_but.clicked.connect(
                    lambda _, cat=cat, checked=True: self._controller.checkboxes_check(cat, checked)
                )
                dsl_but = qtw.QPushButton("Deselect All")
                dsl_but.clicked.connect(
                    lambda _, cat=cat, checked=False: self._controller.checkboxes_check(cat, checked)
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
        settings = self._controller.get_settings()
        for name in ["max_workers", "max_call_level", "max_slice_depth"]:
            setting = settings.get(name, None)
            if not setting:
                continue
            setting.widget = qtw.QSpinBox()
            setting.widget.setRange(setting.min_value, setting.max_value)
            setting.widget.setValue(setting.value)
            setting.widget.setToolTip(setting.help)
            setting.widget.valueChanged.connect(
                lambda value, setting=setting: self._controller.spinbox_change_value(setting, value)
            )
            label = qtw.QLabel(f"{name:s}:")
            label.setToolTip(setting.help)
            com_lay.addRow(label, setting.widget)
        com_wid.setLayout(com_lay)
        com_box_lay = qtw.QVBoxLayout()
        com_box_lay.addWidget(com_wid)
        com_box_wid = qtw.QGroupBox("Finding Paths:")
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
                lambda value, setting=col: self._controller.combobox_change_value(setting, value)
            )
            col_lbl = qtw.QLabel(f"{col_name:s}:")
            pth_lay.addRow(col_lbl, col.widget)
        pth_wid.setLayout(pth_lay)
        pth_box_lay = qtw.QVBoxLayout()
        pth_box_lay.addWidget(pth_wid)
        pth_box_wid = qtw.QGroupBox("Analyzing Path:")
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
            button=sav_but: self._controller.store_main_conf_file(button)
        )
        rst_but = qtw.QPushButton("Reset")
        rst_but.clicked.connect(
            lambda _=None,
            button=rst_but: self._controller.reset_conf(button)
        )
        lay = qtw.QHBoxLayout()
        lay.addWidget(sav_but)
        lay.addWidget(rst_but)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid
