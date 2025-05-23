from __future__ import annotations
from typing import Literal, Optional, TYPE_CHECKING
import os
import PySide6.QtCore as qtc
import PySide6.QtWidgets as qtw

if TYPE_CHECKING:
    from mole.controllers.config import ConfigController
    from mole.core.data import ComboboxSetting, SpinboxSetting


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
        com_wid = qtw.QWidget()
        com_lay = qtw.QFormLayout()
        for name in ["max_workers", "max_call_level", "max_slice_depth"]:
            setting: SpinboxSetting = self.config_ctr.get_setting(name)
            if not setting:
                continue
            setting.widget = qtw.QSpinBox()
            setting.widget.setRange(setting.min_value, setting.max_value)
            setting.widget.setValue(setting.value)
            setting.widget.setToolTip(setting.help)
            setting.widget.valueChanged.connect(
                lambda value, name=name: self.signal_change_setting.emit(name, value)
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

        for name in ["src_highlight_color", "snk_highlight_color", "path_grouping"]:
            setting: ComboboxSetting = self.config_ctr.get_setting(name)
            if not setting:
                continue
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
            setting_lbl = qtw.QLabel(f"{name:s}:")
            pth_lay.addRow(setting_lbl, setting.widget)

        pth_wid.setLayout(pth_lay)
        pth_box_lay = qtw.QVBoxLayout()
        pth_box_lay.addWidget(pth_wid)
        pth_box_wid = qtw.QGroupBox("Analyzing Path:")
        pth_box_wid.setLayout(pth_box_lay)

        # --- AI Group ---
        ai_wid = qtw.QWidget()
        ai_lay = qtw.QFormLayout()

        # API URL field
        ai_api_url_setting = self.config_ctr.get_setting("ai_api_url")
        ai_api_url_edit = qtw.QLineEdit()
        ai_api_url_edit.setPlaceholderText("Enter AI API URL")
        if ai_api_url_setting:
            ai_api_url_edit.setText(ai_api_url_setting.value)
            ai_api_url_edit.setToolTip(ai_api_url_setting.help)
            ai_api_url_setting.widget = ai_api_url_edit
            ai_api_url_edit.textChanged.connect(
                lambda value, name="ai_api_url": self.signal_change_setting.emit(
                    name, value
                )
            )
        ai_api_url_label = qtw.QLabel("API URL:")
        ai_lay.addRow(ai_api_url_label, ai_api_url_edit)

        # API Key field
        ai_api_key_setting = self.config_ctr.get_setting("ai_api_key")
        ai_api_key_edit = qtw.QLineEdit()
        ai_api_key_edit.setEchoMode(qtw.QLineEdit.EchoMode.Password)  # Mask the key
        ai_api_key_edit.setPlaceholderText("Enter AI API Key")
        if ai_api_key_setting:
            ai_api_key_edit.setText(ai_api_key_setting.value)
            ai_api_key_edit.setToolTip(ai_api_key_setting.help)
            ai_api_key_setting.widget = ai_api_key_edit
            ai_api_key_edit.textChanged.connect(
                lambda value, name="ai_api_key": self.signal_change_setting.emit(
                    name, value
                )
            )

        ai_api_key_label = qtw.QLabel("API Key:")
        ai_lay.addRow(ai_api_key_label, ai_api_key_edit)

        # AI Model field
        ai_model_setting = self.config_ctr.get_setting("ai_model")
        ai_model_edit = qtw.QLineEdit()
        ai_model_edit.setPlaceholderText("Enter AI Model")
        if ai_model_setting:
            ai_model_edit.setText(ai_model_setting.value)
            ai_model_edit.setToolTip(ai_model_setting.help)
            ai_model_setting.widget = ai_model_edit
            ai_model_edit.textChanged.connect(
                lambda value, name="ai_model": self.signal_change_setting.emit(
                    name, value
                )
            )
        ai_model_label = qtw.QLabel("AI Model:")
        ai_lay.addRow(ai_model_label, ai_model_edit)

        ai_wid.setLayout(ai_lay)
        ai_box_lay = qtw.QVBoxLayout()
        ai_box_lay.addWidget(ai_wid)
        ai_box_wid = qtw.QGroupBox("AI:")
        ai_box_wid.setLayout(ai_box_lay)

        lay = qtw.QVBoxLayout()
        lay.addWidget(com_box_wid)
        lay.addWidget(pth_box_wid)
        lay.addWidget(ai_box_wid)
        wid = qtw.QWidget()
        wid.setLayout(lay)

        scr = qtw.QScrollArea()
        scr.setWidgetResizable(True)
        scr.setWidget(wid)
        return scr

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
