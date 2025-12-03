from __future__ import annotations
from typing import Literal, Optional, TYPE_CHECKING
import binaryninja as bn
import os
import PySide6.QtCore as qtc
import PySide6.QtWidgets as qtw

if TYPE_CHECKING:
    from mole.controllers.config import ConfigController
    from mole.core.data import (
        CheckboxSetting,
        ComboboxSetting,
        DoubleSpinboxSetting,
        SpinboxSetting,
        TextSetting,
    )


class ConfigView(qtw.QWidget):
    """
    This class implements a view to handle Mole's configuration.
    """

    signal_save_config = qtc.Signal()
    signal_reset_config = qtc.Signal()
    signal_import_config = qtc.Signal()
    signal_export_config = qtc.Signal()
    signal_check_functions = qtc.Signal(object, object, object, object, object)
    signal_clear_manual_functions = qtc.Signal(object, object)
    signal_change_setting = qtc.Signal(object, object)
    signal_change_path_grouping = qtc.Signal()

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
        self.tab_wid = qtw.QTabWidget()
        self.tab_wid.addTab(self._init_cnf_fun_tab("Sources"), "Sources")
        self.tab_wid.addTab(self._init_cnf_fun_tab("Sinks"), "Sinks")
        self.tab_wid.addTab(self._init_cnf_set_tab(), "Settings")
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
        main_lay.addWidget(self.tab_wid)
        main_lay.addWidget(dir_wid)
        main_lay.addWidget(but_wid)
        self.setLayout(main_lay)
        return self

    def _init_cnf_fun_tab(self, tab_name: Literal["Sources", "Sinks"]) -> qtw.QWidget:
        """
        This method initializes the tabs `Sources` and `Sinks`.
        """
        tab_wid = qtw.QTabWidget()
        for lib_name, lib in self.config_ctr.get_libraries(tab_name).items():
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
                clr_but = qtw.QPushButton("Clear All")
                clr_but.clicked.connect(
                    lambda _,
                    cat_name=cat.name,
                    fun_type=tab_name: self.signal_clear_manual_functions.emit(
                        cat_name, fun_type
                    )
                )
                but_lay = qtw.QHBoxLayout()
                but_lay.addWidget(sel_but)
                but_lay.addWidget(dsl_but)
                if lib_name == "manual":
                    but_lay.addWidget(clr_but)
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
        row_cnt = 0
        for name in ["max_workers"]:
            sb_set: SpinboxSetting = self.config_ctr.get_setting(name)
            if not sb_set:
                continue
            sb_set_lbl = qtw.QLabel(f"{name:s}:")
            sb_set_lbl.setToolTip(sb_set.help)
            gen_lay.addWidget(sb_set_lbl, row_cnt, 0)
            sb_set.widget = qtw.QSpinBox()
            sb_set.widget.setRange(sb_set.min_value, sb_set.max_value)
            sb_set.widget.setValue(sb_set.value)
            sb_set.widget.setToolTip(sb_set.help)
            sb_set.widget.valueChanged.connect(
                lambda value, name=name: self.signal_change_setting.emit(name, value)
            )
            gen_lay.addWidget(sb_set.widget, row_cnt, 1)
            row_cnt += 1
        for name in ["fix_func_type"]:
            cb_set: CheckboxSetting = self.config_ctr.get_setting("fix_func_type")
            if not cb_set:
                continue
            cb_set_lbl = qtw.QLabel("fix_func_type:")
            cb_set_lbl.setToolTip(cb_set.help)
            gen_lay.addWidget(cb_set_lbl, row_cnt, 0)
            cb_set.widget = qtw.QCheckBox()
            cb_set.widget.setChecked(cb_set.value)
            cb_set.widget.setToolTip(cb_set.help)
            cb_set.widget.toggled.connect(
                lambda value, name="fix_func_type": self.signal_change_setting.emit(
                    name, value
                )
            )
            gen_lay.addWidget(cb_set.widget, row_cnt, 1)
            row_cnt += 1
        # General widget
        gen_wid = qtw.QGroupBox("General:")
        gen_wid.setLayout(gen_lay)
        # Find layout
        fnd_lay = qtw.QGridLayout()
        for i, name in enumerate(
            ["max_call_level", "max_slice_depth", "max_memory_slice_depth"]
        ):
            sb_set: SpinboxSetting = self.config_ctr.get_setting(name)
            if not sb_set:
                continue
            sb_set_lbl = qtw.QLabel(f"{name:s}:")
            sb_set_lbl.setToolTip(sb_set.help)
            fnd_lay.addWidget(sb_set_lbl, i, 0)
            sb_set.widget = qtw.QSpinBox()
            sb_set.widget.setRange(sb_set.min_value, sb_set.max_value)
            sb_set.widget.setValue(sb_set.value)
            sb_set.widget.setToolTip(sb_set.help)
            sb_set.widget.valueChanged.connect(
                lambda value, name=name: self.signal_change_setting.emit(name, value)
            )
            fnd_lay.addWidget(sb_set.widget, i, 1)
        # Find widget
        fnd_wid = qtw.QGroupBox("Finding Paths:")
        fnd_wid.setLayout(fnd_lay)
        # Inspecting layout
        ins_lay = qtw.QGridLayout()
        for i, name in enumerate(
            ["src_highlight_color", "snk_highlight_color", "path_grouping"]
        ):
            co_set: ComboboxSetting = self.config_ctr.get_setting(name)
            if not co_set:
                continue
            co_set_lbl = qtw.QLabel(f"{name:s}:")
            co_set_lbl.setToolTip(co_set.help)
            ins_lay.addWidget(co_set_lbl, i, 0)
            co_set.widget = qtw.QComboBox()
            co_set.widget.addItems(co_set.items)
            if co_set.value in co_set.items:
                co_set.widget.setCurrentText(co_set.value)
            co_set.widget.setToolTip(co_set.help)
            co_set.widget.currentTextChanged.connect(
                lambda value, name=name: self.signal_change_setting.emit(name, value)
            )
            if name == "path_grouping":
                co_set.widget.currentTextChanged.connect(
                    self.signal_change_path_grouping
                )
            ins_lay.addWidget(co_set.widget, i, 1)
        # Inspecting widget
        ins_wid = qtw.QGroupBox("Inspecting Path:")
        ins_wid.setLayout(ins_lay)
        # Analyzing layout
        aia_lay = qtw.QGridLayout()
        row_cnt = 0
        for name in ["openai_base_url", "openai_api_key", "openai_model"]:
            tt_set: TextSetting = self.config_ctr.get_setting(name)
            if not tt_set:
                continue
            tt_set_lbl = qtw.QLabel(f"{name:s}:")
            tt_set_lbl.setToolTip(tt_set.help)
            aia_lay.addWidget(tt_set_lbl, row_cnt, 0)
            tt_set.widget = qtw.QLineEdit()
            if name == "openai_api_key":
                tt_set.widget.setEchoMode(qtw.QLineEdit.EchoMode.Password)
            tt_set.widget.setText(tt_set.value)
            tt_set.widget.setToolTip(tt_set.help)
            tt_set.widget.textChanged.connect(
                lambda value, name=name: self.signal_change_setting.emit(name, value)
            )
            aia_lay.addWidget(tt_set.widget, row_cnt, 1)
            row_cnt += 1
        for name in ["max_turns", "max_completion_tokens"]:
            sb_set: SpinboxSetting = self.config_ctr.get_setting(name)
            if not sb_set:
                continue
            sb_set_lbl = qtw.QLabel(f"{name:s}:")
            sb_set_lbl.setToolTip(sb_set.help)
            aia_lay.addWidget(sb_set_lbl, row_cnt, 0)
            sb_set.widget = qtw.QSpinBox()
            sb_set.widget.setRange(sb_set.min_value, sb_set.max_value)
            sb_set.widget.setValue(sb_set.value)
            sb_set.widget.setToolTip(sb_set.help)
            sb_set.widget.valueChanged.connect(
                lambda value, name=name: self.signal_change_setting.emit(name, value)
            )
            aia_lay.addWidget(sb_set.widget, row_cnt, 1)
            row_cnt += 1
        for name in ["temperature"]:
            ds_set: DoubleSpinboxSetting = self.config_ctr.get_setting(name)
            if not ds_set:
                continue
            ds_set_lbl = qtw.QLabel(f"{name:s}:")
            ds_set_lbl.setToolTip(ds_set.help)
            aia_lay.addWidget(ds_set_lbl, row_cnt, 0)
            ds_set.widget = qtw.QDoubleSpinBox()
            ds_set.widget.setDecimals(1)
            ds_set.widget.setSingleStep(0.1)
            ds_set.widget.setRange(ds_set.min_value, ds_set.max_value)
            ds_set.widget.setValue(ds_set.value)
            ds_set.widget.setToolTip(ds_set.help)
            ds_set.widget.valueChanged.connect(
                lambda value, name=name: self.signal_change_setting.emit(name, value)
            )
            aia_lay.addWidget(ds_set.widget, row_cnt, 1)
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
        self._import_but = qtw.QPushButton("Import")
        self._import_but.clicked.connect(
            lambda _=None: self.signal_import_config.emit()
        )
        self._export_but = qtw.QPushButton("Export")
        self._export_but.clicked.connect(
            lambda _=None: self.signal_export_config.emit()
        )
        lay = qtw.QHBoxLayout()
        lay.addWidget(self._save_but)
        lay.addWidget(self._reset_but)
        lay.addWidget(self._import_but)
        lay.addWidget(self._export_but)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid

    def give_feedback(
        self,
        button_type: Literal["Save", "Reset", "Export", "Import"],
        tmp_text: str,
        new_text: str,
        msec: int = 1000,
    ) -> None:
        """
        This method changes a button's text to `tmp_text` for `msec` milliseconds and then back to
        `new_text`. If `msec` is less than or equal to 0, the button's text is permanently changed
        to `new_text`.
        """
        match button_type:
            case "Save":
                button = self._save_but
            case "Reset":
                button = self._reset_but
            case "Export":
                button = self._export_but
            case "Import":
                button = self._import_but

        def restore(text: str) -> None:
            button.setText(text)
            button.setEnabled(True)
            return

        if button:
            if msec > 0:
                button.setEnabled(False)
                button.setText(tmp_text)
                qtc.QTimer.singleShot(msec, lambda text=new_text: restore(text))
            else:
                button.setText(new_text)
        return

    def refresh_tabs(self, index: int = -1) -> None:
        """
        This method reinitializes the tabs and sets the current tab to the one at
        `index`. If `index` is less than 0, the current tab is not changed.
        """

        def _refresh_tabs() -> None:
            if not self.tab_wid:
                return
            self.tab_wid.clear()
            self.tab_wid.addTab(self._init_cnf_fun_tab("Sources"), "Sources")
            self.tab_wid.addTab(self._init_cnf_fun_tab("Sinks"), "Sinks")
            self.tab_wid.addTab(self._init_cnf_set_tab(), "Settings")
            if 0 <= index < self.tab_wid.count():
                self.tab_wid.setCurrentIndex(index)
            self.tab_wid.repaint()
            self.tab_wid.update()

        bn.execute_on_main_thread(_refresh_tabs)
        return


class FullSelectLineEdit(qtw.QLineEdit):
    """
    This class implements a `qtw.QLineEdit` that selects all its text when
    double-clicked.
    """

    def mouseDoubleClickEvent(self, event: any) -> None:
        return self.selectAll()


class ManualConfigDialog(qtw.QDialog):
    """
    This class implements a popup dialog that allows to configure manual sources / sinks.
    """

    signal_find = qtc.Signal(str, str, str, bool)
    signal_find_feedback = qtc.Signal(str)
    signal_add = qtc.Signal(str, str, str, str)
    signal_add_feedback = qtc.Signal(str)

    def __init__(
        self,
        is_src: bool,
        is_from_manual_func: bool,
        synopsis: str,
        category: str,
        par_cnt: str,
    ) -> None:
        super().__init__()
        self.setWindowTitle(f"Manual {'Source' if is_src else 'Sink'}")
        self.setMinimumWidth(450)
        # Metadata widgets
        self.syn_wid = qtw.QLineEdit(synopsis)
        self.syn_wid.setToolTip(
            "human-readable function signature (for reference only)"
        )
        self.cat_wid = qtw.QLineEdit(category)
        self.cat_wid.setToolTip("category of the function (for reference only)")
        # Metadata group layout
        met_lay = qtw.QGridLayout()
        met_lay.addWidget(qtw.QLabel("synopsis:"), 0, 0)
        met_lay.addWidget(self.syn_wid, 0, 1)
        met_lay.addWidget(qtw.QLabel("category:"), 1, 0)
        met_lay.addWidget(self.cat_wid, 1, 1)
        # Metadata group widget
        met_wid = qtw.QGroupBox("Metadata:")
        met_wid.setLayout(met_lay)
        # Parameter widgets
        self.par_cnt_wid = qtw.QLineEdit(par_cnt)
        self.par_cnt_wid.setToolTip(
            "expression specifying the number of parameters (e.g. 'i >= 1')"
        )
        self.par_slice_wid = qtw.QLineEdit("False")
        self.par_slice_wid.setToolTip(
            "expression specifying which parameter 'i' to slice (e.g. 'i >= 1')"
        )
        self.all_code_xrefs_wid = qtw.QCheckBox()
        self.all_code_xrefs_wid.setToolTip("include all symbol's code cross-references")
        # Configuration layout
        cnf_lay = qtw.QGridLayout()
        cnf_lay.addWidget(qtw.QLabel("par_cnt:"), 0, 0)
        cnf_lay.addWidget(self.par_cnt_wid, 0, 1)
        cnf_lay.addWidget(qtw.QLabel("par_slice:"), 1, 0)
        cnf_lay.addWidget(self.par_slice_wid, 1, 1)
        cnf_lay.addWidget(qtw.QLabel("all_code_xrefs:"), 2, 0)
        cnf_lay.addWidget(self.all_code_xrefs_wid, 2, 1)
        # Configuration widget
        cnf_wid = qtw.QGroupBox("Configuration:")
        cnf_wid.setLayout(cnf_lay)
        # Buttons
        find_but = qtw.QPushButton("Find")
        find_but.clicked.connect(
            lambda: self.signal_find.emit(
                self.syn_wid.text().strip(),
                self.par_cnt_wid.text().strip(),
                self.par_slice_wid.text().strip() if self.par_slice_wid else "False",
                self.all_code_xrefs_wid.isChecked()
                if self.all_code_xrefs_wid
                else True,
            )
        )
        self.signal_find_feedback.connect(
            lambda text: self.give_feedback(find_but, text)
        )
        add_but = qtw.QPushButton("Add")
        add_but.clicked.connect(
            lambda: self.signal_add.emit(
                self.cat_wid.text().strip(),
                self.syn_wid.text().strip(),
                self.par_cnt_wid.text().strip(),
                self.par_slice_wid.text().strip() if self.par_slice_wid else "False",
            )
        )
        self.signal_add_feedback.connect(lambda text: self.give_feedback(add_but, text))
        cancel_but = qtw.QPushButton("Cancel")
        cancel_but.clicked.connect(self.reject)
        # Button layout
        but_lay = qtw.QHBoxLayout()
        but_lay.addWidget(find_but)
        but_lay.addWidget(add_but)
        but_lay.addWidget(cancel_but)
        # Button widget
        but_wid = qtw.QWidget()
        but_wid.setLayout(but_lay)
        # Main layout
        main_lay = qtw.QVBoxLayout()
        main_lay.addWidget(met_wid)
        main_lay.addWidget(cnf_wid)
        main_lay.addWidget(but_wid)
        self.setLayout(main_lay)
        return

    def give_feedback(self, button: qtw.QPushButton, text: str) -> None:
        def restore(text: str) -> None:
            button.setText(text)
            button.setEnabled(True)
            return

        if button:
            old_text = button.text()
            button.setEnabled(False)
            button.setText(text)
            qtc.QTimer.singleShot(1000, lambda: restore(old_text))
        return
