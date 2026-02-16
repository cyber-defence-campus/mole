from __future__ import annotations
from mole.core.data import (
    CheckboxSetting,
    ComboboxSetting,
    DoubleSpinboxSetting,
    SpinboxSetting,
    TextSetting,
)
from mole.models.config import ConfigModel
from typing import Literal
import binaryninja as bn
import os
import PySide6.QtCore as qtc
import PySide6.QtWidgets as qtw


class ConfigView(qtw.QWidget):
    """
    This class implements a view for Mole's configuration tab.
    """

    signal_save_config = qtc.Signal()
    signal_save_config_feedback = qtc.Signal(str, str, int)
    signal_reset_config = qtc.Signal()
    signal_reset_config_feedback = qtc.Signal(str, str, int)
    signal_import_config = qtc.Signal()
    signal_import_config_feedback = qtc.Signal(str, str, int)
    signal_export_config = qtc.Signal()
    signal_export_config_feedback = qtc.Signal(str, str, int)
    signal_check_functions = qtc.Signal(object, object, object, object, object)
    signal_clear_manual_functions = qtc.Signal(object, object)
    signal_change_setting = qtc.Signal(object, object)
    signal_change_highlight_color = qtc.Signal()
    signal_change_path_grouping = qtc.Signal()

    def __init__(self, config_model: ConfigModel) -> None:
        """
        This method initializes the configuration view.
        """
        super().__init__()
        self._config_model = config_model
        self._init_widgets()
        return

    def _init_widgets(self) -> None:
        """
        This method initializes the config view's widgets.
        """
        # Subtabs widget
        self.tab_wid = qtw.QTabWidget()
        self.tab_wid.addTab(self._init_cnf_fun_tab("Sources"), "Sources")
        self.tab_wid.addTab(self._init_cnf_fun_tab("Sinks"), "Sinks")
        self.tab_wid.addTab(self._init_cnf_set_tab(), "Settings")
        # Script widget
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_dir = os.path.abspath(os.path.join(script_dir, "../conf/"))
        script_wid = qtw.QLineEdit(script_dir)
        script_wid.setReadOnly(True)
        script_wid.setStyleSheet("background-color: transparent; border: none;")
        script_wid.mouseDoubleClickEvent = lambda _: script_wid.selectAll()
        # Directory layout
        dir_lay = qtw.QHBoxLayout()
        dir_lay.addWidget(qtw.QLabel("Config Dir:"))
        dir_lay.addWidget(script_wid)
        # Directory widget
        dir_wid = qtw.QWidget()
        dir_wid.setLayout(dir_lay)
        # Save button widget
        save_but_wid = qtw.QPushButton("Save")
        save_but_wid.clicked.connect(self.signal_save_config.emit)
        self.signal_save_config_feedback.connect(
            lambda tmp_text, new_text, msec: self._give_feedback(
                save_but_wid, tmp_text, new_text, msec
            )
        )
        # Reset button widget
        reset_but_wid = qtw.QPushButton("Reset")
        reset_but_wid.clicked.connect(self.signal_reset_config.emit)
        self.signal_reset_config_feedback.connect(
            lambda tmp_text, new_text, msec: self._give_feedback(
                reset_but_wid, tmp_text, new_text, msec
            )
        )
        # Import button widget
        import_but_wid = qtw.QPushButton("Import")
        import_but_wid.clicked.connect(self.signal_import_config.emit)
        self.signal_import_config_feedback.connect(
            lambda tmp_text, new_text, msec: self._give_feedback(
                import_but_wid, tmp_text, new_text, msec
            )
        )
        # Export button widget
        export_but_wid = qtw.QPushButton("Export")
        export_but_wid.clicked.connect(self.signal_export_config.emit)
        self.signal_export_config_feedback.connect(
            lambda tmp_text, new_text, msec: self._give_feedback(
                export_but_wid, tmp_text, new_text, msec
            )
        )
        # Buttons layout
        but_lay = qtw.QHBoxLayout()
        but_lay.addWidget(save_but_wid)
        but_lay.addWidget(reset_but_wid)
        but_lay.addWidget(import_but_wid)
        but_lay.addWidget(export_but_wid)
        # Buttons widget
        but_wid = qtw.QWidget()
        but_wid.setLayout(but_lay)
        # Tab layout
        tab_lay = qtw.QVBoxLayout()
        tab_lay.addWidget(self.tab_wid)
        tab_lay.addWidget(dir_wid)
        tab_lay.addWidget(but_wid)
        self.setLayout(tab_lay)
        pass

    def _init_cnf_fun_tab(self, tab_name: Literal["Sources", "Sinks"]) -> qtw.QWidget:
        """
        This method initializes the tabs `Sources` and `Sinks`.
        """
        tab_wid = qtw.QTabWidget()
        for lib_name, lib in self.model().get_libraries(tab_name).items():
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
        model = self.model()
        for name in ["max_workers"]:
            sb_set = model.get_setting(name)
            if not isinstance(sb_set, SpinboxSetting):
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
            cb_set = model.get_setting("fix_func_type")
            if not isinstance(cb_set, CheckboxSetting):
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
            sb_set = model.get_setting(name)
            if not isinstance(sb_set, SpinboxSetting):
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
            co_set = model.get_setting(name)
            if not isinstance(co_set, ComboboxSetting):
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
            if name in ["src_highlight_color", "snk_highlight_color"]:
                co_set.widget.currentTextChanged.connect(
                    self.signal_change_highlight_color
                )
            elif name == "path_grouping":
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
            tt_set = model.get_setting(name)
            if not isinstance(tt_set, TextSetting):
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
            sb_set = model.get_setting(name)
            if not isinstance(sb_set, SpinboxSetting):
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
            ds_set = model.get_setting(name)
            if not isinstance(ds_set, DoubleSpinboxSetting):
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

    def _give_feedback(
        self,
        button: qtw.QPushButton,
        tmp_text: str = "",
        new_text: str = "",
        msec: int = 1000,
    ) -> None:
        """
        This method changes `button`'s text to `tmp_text` for `msec` milliseconds and then back to
        `new_text`. If `tmp_text` is empty or `msec` is less than or equal to 0, it directly sets
        the button's text to `new_text`. If `new_text` is empty, it restores the current text of
        the button.
        """

        def restore(text: str) -> None:
            button.setText(text)
            button.setEnabled(True)
            return

        if button:
            if not new_text:
                new_text = button.text()
            if tmp_text and msec > 0:
                button.setEnabled(False)
                button.setText(tmp_text)
                qtc.QTimer.singleShot(msec, lambda text=new_text: restore(text))
            else:
                button.setText(new_text)
        return

    def model(self) -> ConfigModel:
        """
        This method returns the model for the config view.
        """
        return self._config_model

    def refresh_tabs(self, index: int = -1) -> None:
        """
        This method reinitializes the tabs and sets the current tab to the one at `index`. If
        `index` is less than 0, the current tab is not changed.
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


class ConfigDialog(qtw.QDialog):
    """
    This class implements a popup dialog that allows to configure manual sources / sinks.
    """

    signal_find = qtc.Signal(object, bool, bool, str, str, str, str)
    signal_find_feedback = qtc.Signal(str, str, int)
    signal_add = qtc.Signal(bool, str, str, str, str, str)
    signal_add_feedback = qtc.Signal(str, str, int)

    def __init__(self) -> None:
        """
        This method initializes the manual config dialog.
        """
        super().__init__()
        self.setWindowTitle("Manual Source/Sink")
        self.setMinimumWidth(450)
        self._init_widgets()
        return

    def _init_widgets(self) -> None:
        """
        This method initializes the widgets for the manual config dialog.
        """
        # Metadata widgets
        self.syn_wid = qtw.QLineEdit()
        self.syn_wid.setToolTip(
            "human-readable function signature (for reference only)"
        )
        self.cat_wid = qtw.QLineEdit("Default")
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
        self.par_cnt_wid = qtw.QLineEdit()
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
        # Find button widget
        find_but = qtw.QPushButton("Find")
        find_but.clicked.connect(
            lambda: self.signal_find.emit(
                self.inst,
                self.is_src,
                self.all_code_xrefs_wid.isChecked()
                if self.all_code_xrefs_wid
                else True,
                self.symbol,
                self.syn_wid.text().strip(),
                self.par_cnt_wid.text().strip(),
                self.par_slice_wid.text().strip() if self.par_slice_wid else "False",
            )
        )
        self.signal_find_feedback.connect(
            lambda tmp_text, new_text, msec: self._give_feedback(
                find_but, tmp_text, new_text, msec
            )
        )
        # Add button widget
        add_but = qtw.QPushButton("Add")
        add_but.clicked.connect(
            lambda: self.signal_add.emit(
                self.is_src,
                self.symbol,
                self.cat_wid.text().strip(),
                self.syn_wid.text().strip(),
                self.par_cnt_wid.text().strip(),
                self.par_slice_wid.text().strip() if self.par_slice_wid else "False",
            )
        )
        self.signal_add_feedback.connect(
            lambda tmp_text, new_text, msec: self._give_feedback(
                add_but, tmp_text, new_text, msec
            )
        )
        # Cancel button widget
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
        # Dialog layout
        dialog_lay = qtw.QVBoxLayout()
        dialog_lay.addWidget(met_wid)
        dialog_lay.addWidget(cnf_wid)
        dialog_lay.addWidget(but_wid)
        self.setLayout(dialog_lay)
        return

    def set_fields(
        self,
        inst: bn.MediumLevelILCall
        | bn.MediumLevelILCallSsa
        | bn.MediumLevelILCallUntyped
        | bn.MediumLevelILCallUntypedSsa
        | bn.MediumLevelILTailcall
        | bn.MediumLevelILTailcallSsa
        | bn.MediumLevelILTailcallUntyped
        | bn.MediumLevelILTailcallUntypedSsa,
        is_src: bool,
        symbol: str,
        synopsis: str,
        par_cnt: str,
        par_slice: str,
        all_code_xrefs: bool,
    ) -> None:
        """
        This method sets the dialog's fields according to the given parameters.
        """
        self.setWindowTitle(f"Manual {'Source' if is_src else 'Sink'}")
        self.inst = inst
        self.is_src = is_src
        self.symbol = symbol
        self.syn_wid.setText(synopsis)
        self.par_cnt_wid.setText(par_cnt)
        self.par_slice_wid.setText(par_slice)
        self.all_code_xrefs_wid.setChecked(all_code_xrefs)
        return

    def _give_feedback(
        self,
        button: qtw.QPushButton,
        tmp_text: str = "",
        new_text: str = "",
        msec: int = 1000,
    ) -> None:
        """
        This method changes `button`'s text to `tmp_text` for `msec` milliseconds and then back to
        `new_text`. If `tmp_text` is empty or `msec` is less than or equal to 0, it directly sets
        the button's text to `new_text`. If `new_text` is empty, it restores the current text of
        the button.
        """

        def restore(text: str) -> None:
            button.setText(text)
            button.setEnabled(True)
            return

        if button:
            if not new_text:
                new_text = button.text()
            if tmp_text and msec > 0:
                button.setEnabled(False)
                button.setText(tmp_text)
                qtc.QTimer.singleShot(msec, lambda text=new_text: restore(text))
            else:
                button.setText(new_text)
        return
