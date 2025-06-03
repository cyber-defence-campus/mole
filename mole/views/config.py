from __future__ import annotations
from typing import Literal, Optional, TYPE_CHECKING
import os
import PySide6.QtCore as qtc
import PySide6.QtWidgets as qtw

if TYPE_CHECKING:
    from mole.controllers.config import ConfigController
    from mole.core.data import ComboboxSetting, SpinboxSetting, TextSetting


class ConfigView(qtw.QWidget):
    """
    This class implements a view to handle Mole's configuration.
    """

    signal_save_config = qtc.Signal()
    signal_reset_config = qtc.Signal()
    signal_check_functions = qtc.Signal(object, object, object, object, object)
    signal_change_setting = qtc.Signal(object, object)
    signal_change_path_grouping = qtc.Signal(object)

    def __init__(self) -> None:
        """
        This method initializes the configuration view.
        """
        super().__init__()
        self.config_ctr: Optional[ConfigController] = None
        self._save_but: Optional[qtw.QPushButton] = None
        self._reset_but: Optional[qtw.QPushButton] = None
        return

    def init(self, config_ctr: ConfigController) -> ConfigView:
        """
        This method sets the controller and initializes relevant UI components.
        """
        # Set controller
        self.config_ctr = config_ctr
        # Tab widget
        tab_wid = qtw.QTabWidget()
        tab_wid.addTab(self._init_cnf_fun_tab("Sources"), "Sources")
        tab_wid.addTab(self._init_cnf_fun_tab("Sinks"), "Sinks")
        tab_wid.addTab(self._init_cnf_set_tab(), "Settings")
        # Script widget
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_dir = os.path.abspath(os.path.join(script_dir, "../conf/"))
        script_wid = FullSelectLineEdit(script_dir)
        script_wid.setReadOnly(True)
        script_wid.setStyleSheet("background-color: transparent; border: none;")
        # Directory layout
        dir_lay = qtw.QHBoxLayout()
        dir_lay.addWidget(qtw.QLabel("Config Dir:"))
        dir_lay.addWidget(script_wid)
        # Directory widget
        dir_wid = qtw.QWidget()
        dir_wid.setLayout(dir_lay)
        # Button widget
        but_wid = self._init_cnf_but()
        # Main layout
        main_lay = qtw.QVBoxLayout()
        main_lay.addWidget(tab_wid)
        main_lay.addWidget(dir_wid)
        main_lay.addWidget(but_wid)
        self.setLayout(main_lay)
        return self

    def _init_cnf_fun_tab(self, tab_name: Literal["Sources", "Sinks"]) -> qtw.QWidget:
        """
        This method initializes the tabs `Sources` and `Sinks`.
        """
        tab_wid = qtw.QTabWidget()
        for lib in self.config_ctr.get_libraries(tab_name).values():
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
                        lambda checked,
                        lib_name=lib.name,
                        cat_name=cat.name,
                        fun_name=fun.name,
                        fun_type=tab_name: self.signal_check_functions.emit(
                            lib_name, cat_name, fun_name, fun_type, checked
                        )
                    )
                    fun_lay.addRow(fun.checkbox)
                fun_wid = qtw.QWidget()
                fun_wid.setLayout(fun_lay)
                # Button widget
                sel_but = qtw.QPushButton("Select All")
                sel_but.clicked.connect(
                    lambda _,
                    lib_name=lib.name,
                    cat_name=cat.name,
                    fun_name=None,
                    fun_type=tab_name: self.signal_check_functions.emit(
                        lib_name, cat_name, fun_name, fun_type, True
                    )
                )
                dsl_but = qtw.QPushButton("Deselect All")
                dsl_but.clicked.connect(
                    lambda _,
                    lib_name=lib.name,
                    cat_name=cat.name,
                    fun_name=None,
                    fun_type=tab_name: self.signal_check_functions.emit(
                        lib_name, cat_name, fun_name, fun_type, False
                    )
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
            scr_wid.setWidgetResizable(True)
            scr_wid.setWidget(lib_wid)
            tab_wid.addTab(scr_wid, lib.name)
        lay = qtw.QVBoxLayout()
        lay.addWidget(tab_wid)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid

    def _init_cnf_set_tab(self) -> qtw.QWidget:
        """
        This method initializes the tab `Settings`.
        """
        # General layout
        gen_lay = qtw.QGridLayout()
        for i, name in enumerate(["max_workers"]):
            setting: SpinboxSetting = self.config_ctr.get_setting(name)
            if not setting:
                continue
            setting_lbl = qtw.QLabel(f"{name:s}:")
            setting_lbl.setToolTip(setting.help)
            gen_lay.addWidget(setting_lbl, i, 0)
            setting.widget = qtw.QSpinBox()
            setting.widget.setRange(setting.min_value, setting.max_value)
            setting.widget.setValue(setting.value)
            setting.widget.setToolTip(setting.help)
            setting.widget.valueChanged.connect(
                lambda value, name=name: self.signal_change_setting.emit(name, value)
            )
            gen_lay.addWidget(setting.widget, i, 1)
        # General widget
        gen_wid = qtw.QGroupBox("General:")
        gen_wid.setLayout(gen_lay)
        # Find layout
        fnd_lay = qtw.QGridLayout()
        for i, name in enumerate(["max_call_level", "max_slice_depth"]):
            setting: SpinboxSetting = self.config_ctr.get_setting(name)
            if not setting:
                continue
            setting_lbl = qtw.QLabel(f"{name:s}:")
            setting_lbl.setToolTip(setting.help)
            fnd_lay.addWidget(setting_lbl, i, 0)
            setting.widget = qtw.QSpinBox()
            setting.widget.setRange(setting.min_value, setting.max_value)
            setting.widget.setValue(setting.value)
            setting.widget.setToolTip(setting.help)
            setting.widget.valueChanged.connect(
                lambda value, name=name: self.signal_change_setting.emit(name, value)
            )
            fnd_lay.addWidget(setting.widget, i, 1)
        # Find widget
        fnd_wid = qtw.QGroupBox("Finding Paths:")
        fnd_wid.setLayout(fnd_lay)
        # Inspecting layout
        ins_lay = qtw.QGridLayout()
        for i, name in enumerate(
            ["src_highlight_color", "snk_highlight_color", "path_grouping"]
        ):
            setting: ComboboxSetting = self.config_ctr.get_setting(name)
            if not setting:
                continue
            setting_lbl = qtw.QLabel(f"{name:s}:")
            setting_lbl.setToolTip(setting.help)
            ins_lay.addWidget(setting_lbl, i, 0)
            setting.widget = qtw.QComboBox()
            setting.widget.addItems(setting.items)
            if setting.value in setting.items:
                setting.widget.setCurrentText(setting.value)
            setting.widget.setToolTip(setting.help)
            setting.widget.currentTextChanged.connect(
                lambda value, name=name: self.signal_change_setting.emit(name, value)
            )
            if name == "path_grouping":
                setting.widget.currentTextChanged.connect(
                    lambda value: self.signal_change_path_grouping.emit(value)
                )
            ins_lay.addWidget(setting.widget, i, 1)
        # Inspecting widget
        ins_wid = qtw.QGroupBox("Inspecting Path:")
        ins_wid.setLayout(ins_lay)
        # Analyzing layout
        aia_lay = qtw.QGridLayout()
        row_cnt = 0
        for name in ["openai_base_url", "openai_api_key", "openai_model"]:
            setting: TextSetting = self.config_ctr.get_setting(name)
            if not setting:
                continue
            setting_lbl = qtw.QLabel(f"{name:s}:")
            setting_lbl.setToolTip(setting.help)
            aia_lay.addWidget(setting_lbl, row_cnt, 0)
            setting.widget = qtw.QLineEdit()
            if name == "openai_api_key":
                setting.widget.setEchoMode(qtw.QLineEdit.EchoMode.Password)
            setting.widget.setText(setting.value)
            setting.widget.setToolTip(setting.help)
            setting.widget.textChanged.connect(
                lambda value, name=name: self.signal_change_setting.emit(name, value)
            )
            aia_lay.addWidget(setting.widget, row_cnt, 1)
            row_cnt += 1
        for name in ["max_turns"]:
            setting: SpinboxSetting = self.config_ctr.get_setting(name)
            if not setting:
                continue
            setting_lbl = qtw.QLabel(f"{name:s}:")
            setting_lbl.setToolTip(setting.help)
            aia_lay.addWidget(setting_lbl, row_cnt, 0)
            setting.widget = qtw.QSpinBox()
            setting.widget.setRange(setting.min_value, setting.max_value)
            setting.widget.setValue(setting.value)
            setting.widget.setToolTip(setting.help)
            setting.widget.valueChanged.connect(
                lambda value, name=name: self.signal_change_setting.emit(name, value)
            )
            aia_lay.addWidget(setting.widget, row_cnt, 1)
            row_cnt += 1
        # Analyzing widget
        aia_wid = qtw.QGroupBox("Analyzing Path with AI:")
        aia_wid.setLayout(aia_lay)
        # Setting layout
        set_lay = qtw.QVBoxLayout()
        set_lay.addWidget(gen_wid)
        set_lay.addWidget(fnd_wid)
        set_lay.addWidget(ins_wid)
        set_lay.addWidget(aia_wid)
        # Setting widget
        set_wid = qtw.QWidget()
        set_wid.setLayout(set_lay)
        # Scroll widget
        scr_wid = qtw.QScrollArea()
        scr_wid.setWidgetResizable(True)
        scr_wid.setWidget(set_wid)
        return scr_wid

    def _init_cnf_but(self) -> qtw.QWidget:
        """
        This method initializes the buttons.
        """
        self._save_but = qtw.QPushButton("Save")
        self._save_but.clicked.connect(lambda _=None: self.signal_save_config.emit())
        self._reset_but = qtw.QPushButton("Reset")
        self._reset_but.clicked.connect(lambda _=None: self.signal_reset_config.emit())
        lay = qtw.QHBoxLayout()
        lay.addWidget(self._save_but)
        lay.addWidget(self._reset_but)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid

    def give_feedback(
        self, button_type: Literal["Save", "Reset"], text: str, msec: int = 1000
    ) -> None:
        """
        This method gives user feedback by temporarily changing a button's text.
        """
        match button_type:
            case "Save":
                button = self._save_but
            case "Reset":
                button = self._reset_but

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


class FullSelectLineEdit(qtw.QLineEdit):
    """
    This class implements a `qtw.QLineEdit` that selects all its text when
    double-clicked.
    """

    def mouseDoubleClickEvent(self, event: any) -> None:
        return self.selectAll()
