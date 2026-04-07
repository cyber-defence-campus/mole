from __future__ import annotations
from mole.common.helper.ui import give_feedback
from mole.data.config import (
    CheckboxSetting,
    ComboboxSetting,
    DoubleSpinboxSetting,
    Function,
    SpinboxSetting,
    TextSetting,
)
from mole.models.config import ConfigModel, TaintModelColumns
import binaryninja as bn
import os
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui
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
    signal_change_setting = qtc.Signal(str, object)
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
        self.tab_wid.addTab(self._init_cnf_mod_tab(), "Taint Model")
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
            lambda tmp_text, new_text, msec: give_feedback(
                save_but_wid, tmp_text, new_text, msec
            )
        )
        # Reset button widget
        reset_but_wid = qtw.QPushButton("Reset")
        reset_but_wid.clicked.connect(self.signal_reset_config.emit)
        self.signal_reset_config_feedback.connect(
            lambda tmp_text, new_text, msec: give_feedback(
                reset_but_wid, tmp_text, new_text, msec
            )
        )
        # Import button widget
        import_but_wid = qtw.QPushButton("Import")
        import_but_wid.clicked.connect(self.signal_import_config.emit)
        self.signal_import_config_feedback.connect(
            lambda tmp_text, new_text, msec: give_feedback(
                import_but_wid, tmp_text, new_text, msec
            )
        )
        # Export button widget
        export_but_wid = qtw.QPushButton("Export")
        export_but_wid.clicked.connect(self.signal_export_config.emit)
        self.signal_export_config_feedback.connect(
            lambda tmp_text, new_text, msec: give_feedback(
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

    def _init_cnf_mod_tab(self, save_config_feedback: bool = True) -> qtw.QWidget:
        """
        This method initializes the tab `Taint Model`.
        """
        updating = False
        checkable_column_states = {
            TaintModelColumns.SOURCE.value: qtc.Qt.CheckState.Unchecked,
            TaintModelColumns.SINK.value: qtc.Qt.CheckState.Unchecked,
            TaintModelColumns.FIX.value: qtc.Qt.CheckState.Unchecked,
        }

        def set_state(
            item: qtw.QTreeWidgetItem, column: int, state: qtc.Qt.CheckState
        ) -> None:
            # Update model
            data = item.data(TaintModelColumns.FUNCTION.value, qtc.Qt.UserRole)  # type: ignore
            if isinstance(data, Function):
                match column:
                    case TaintModelColumns.SOURCE.value:
                        data.src_enabled = state == qtc.Qt.CheckState.Checked
                    case TaintModelColumns.SINK.value:
                        data.snk_enabled = state == qtc.Qt.CheckState.Checked
                    case TaintModelColumns.FIX.value:
                        data.fix_enabled = state == qtc.Qt.CheckState.Checked
            # Update view
            item.setCheckState(column, state)
            if save_config_feedback:
                self.signal_save_config_feedback.emit("Save*", "Save*", 0)
            return

        def all_items_expanded(tree: qtw.QTreeWidget) -> bool:
            # Check if item and all its children are expanded
            def is_expanded(item: qtw.QTreeWidgetItem) -> bool:
                # Check if item is expanded
                if not item.isExpanded():
                    return False
                # Check if all item's children are expanded
                for i in range(item.childCount()):
                    child = item.child(i)
                    if not is_expanded(child):
                        return False
                return True

            # Check if root's children are expanded
            root = tree.invisibleRootItem()
            for i in range(root.childCount()):
                child = root.child(i)
                if not is_expanded(child):
                    return False
            return True

        def handle_header_double_clicked(column: int) -> None:
            nonlocal updating
            # Collase/expand tree if clicking the function column
            if column == TaintModelColumns.FUNCTION.value:
                if all_items_expanded(tree):
                    tree.collapseAll()
                else:
                    tree.expandAll()
                return
            # Toggle column state if clicking a checkable column
            if not updating and column in checkable_column_states:
                updating = True
                new_state = (
                    qtc.Qt.CheckState.Checked
                    if checkable_column_states[column] == qtc.Qt.CheckState.Unchecked
                    else qtc.Qt.CheckState.Unchecked
                )
                checkable_column_states[column] = new_state
                # Set new state for all items in the column
                root = tree.invisibleRootItem()
                for i in range(root.childCount()):
                    child = root.child(i)
                    set_state(child, column, new_state)
                    propagate_state_down(child, column, new_state)
                updating = False
            return

        def propagate_state_down(
            item: qtw.QTreeWidgetItem, column: int, state: qtc.Qt.CheckState
        ) -> None:
            for i in range(item.childCount()):
                child = item.child(i)
                set_state(child, column, state)
                propagate_state_down(child, column, state)
            return

        def propagate_state_up(item: qtw.QTreeWidgetItem, column: int) -> None:
            # Get parent
            parent = item.parent()
            if not parent:
                # Count checks of the root's children
                cnt_checked = 0
                cnt_unchecked = 0
                root = tree.invisibleRootItem()
                for i in range(root.childCount()):
                    state = root.child(i).checkState(column)
                    if state == qtc.Qt.CheckState.Checked:
                        cnt_checked += 1
                    elif state == qtc.Qt.CheckState.Unchecked:
                        cnt_unchecked += 1
                # Check the root if all chlidren are checked
                if cnt_checked == root.childCount():
                    checkable_column_states[column] = qtc.Qt.CheckState.Checked
                # Uncheck the root if all children are unchecked
                elif cnt_unchecked == root.childCount():
                    checkable_column_states[column] = qtc.Qt.CheckState.Unchecked
                # Partially check the root otherwise
                else:
                    checkable_column_states[column] = qtc.Qt.CheckState.PartiallyChecked
                return
            # Count checks of the parent's children
            cnt_checked = 0
            cnt_unchecked = 0
            for i in range(parent.childCount()):
                state = parent.child(i).checkState(column)
                if state == qtc.Qt.CheckState.Checked:
                    cnt_checked += 1
                elif state == qtc.Qt.CheckState.Unchecked:
                    cnt_unchecked += 1
            # Check the parent if all chlidren are checked
            if cnt_checked == parent.childCount():
                parent.setCheckState(column, qtc.Qt.CheckState.Checked)
            # Uncheck the parent if all children are unchecked
            elif cnt_unchecked == parent.childCount():
                parent.setCheckState(column, qtc.Qt.CheckState.Unchecked)
            # Partially check the parent otherwise
            else:
                parent.setCheckState(column, qtc.Qt.CheckState.PartiallyChecked)
            # Propagate upwards
            propagate_state_up(parent, column)
            return

        def handle_item_changed(item: qtw.QTreeWidgetItem, column: int) -> None:
            nonlocal updating
            if updating:
                return
            updating = True

            # Update and propagate state of checkable columns
            if column in checkable_column_states:
                state = item.checkState(column)
                set_state(item, column, state)
                propagate_state_down(item, column, state)
                propagate_state_up(item, column)

            updating = False
            return

        # Styling
        font = qtui.QFont()
        font.setItalic(True)
        color = qtui.QBrush(qtui.QColor(255, 239, 213))
        # Tree widget
        tree = qtw.QTreeWidget()
        tree.setColumnCount(4)
        tree.setHeaderLabels(
            [
                TaintModelColumns.FUNCTION.label,
                TaintModelColumns.SOURCE.label,
                TaintModelColumns.SINK.label,
                TaintModelColumns.FIX.label,
            ]
        )
        tree.header().sectionDoubleClicked.connect(
            lambda column: handle_header_double_clicked(column)
        )
        tree.itemChanged.connect(handle_item_changed)
        # Tree widget items
        taint_model = self.model().get_taint_model()
        for lib_name, lib in taint_model.items():
            lib_item = qtw.QTreeWidgetItem(tree, [lib_name])
            lib_item.setData(TaintModelColumns.FUNCTION.value, qtc.Qt.UserRole, lib)  # type: ignore
            lib_item.setExpanded(True)
            for column in range(tree.columnCount()):
                lib_item.setFont(column, font)
                lib_item.setForeground(column, color)
            for cat_name, cat in lib.categories.items():
                cat_item = qtw.QTreeWidgetItem(lib_item, [cat_name])
                cat_item.setData(TaintModelColumns.FUNCTION.value, qtc.Qt.UserRole, cat)  # type: ignore
                for column in range(tree.columnCount()):
                    cat_item.setFont(column, font)
                    cat_item.setForeground(column, color)
                for fun_name, fun in cat.functions.items():
                    fun_item = qtw.QTreeWidgetItem(cat_item, [fun_name])
                    fun_item.setData(
                        TaintModelColumns.FUNCTION.value,
                        qtc.Qt.UserRole,  # type: ignore
                        fun,
                    )
                    fun_item.setToolTip(TaintModelColumns.FUNCTION.value, fun.synopsis)
                    fun_item.setCheckState(
                        TaintModelColumns.SOURCE.value,
                        qtc.Qt.Checked if fun.src_enabled else qtc.Qt.Unchecked,  # type: ignore
                    )
                    fun_item.setCheckState(
                        TaintModelColumns.SINK.value,
                        qtc.Qt.Checked if fun.snk_enabled else qtc.Qt.Unchecked,  # type: ignore
                    )
                    fun_item.setCheckState(
                        TaintModelColumns.FIX.value,
                        qtc.Qt.Checked if fun.fix_enabled else qtc.Qt.Unchecked,  # type: ignore
                    )
        # Resize columns
        for column in range(tree.columnCount()):
            tree.resizeColumnToContents(column)
        return tree

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
        for name in ["base_url", "api_key", "model"]:
            tt_set = model.get_setting(name)
            if not isinstance(tt_set, TextSetting):
                continue
            tt_set_lbl = qtw.QLabel(f"{name:s}:")
            tt_set_lbl.setToolTip(tt_set.help)
            aia_lay.addWidget(tt_set_lbl, row_cnt, 0)
            tt_set.widget = qtw.QLineEdit()
            if name == "api_key":
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
            self.tab_wid.addTab(
                self._init_cnf_mod_tab(save_config_feedback=False), "Taint Model"
            )
            self.tab_wid.addTab(self._init_cnf_set_tab(), "Settings")
            if 0 <= index < self.tab_wid.count():
                self.tab_wid.setCurrentIndex(index)
            self.tab_wid.repaint()
            self.tab_wid.update()

        bn.execute_on_main_thread(_refresh_tabs)
        return


class ConfigDialog(qtw.QDialog):
    """
    This class implements a popup dialog that allows to configure manual functions.
    """

    signal_find = qtc.Signal(object, bool, str, str, bool, str, bool, str, bool)
    signal_find_feedback = qtc.Signal(str, str, int)
    signal_add = qtc.Signal(str, str, str, bool, str, bool, str, bool)
    signal_add_feedback = qtc.Signal(str, str, int)

    def __init__(self) -> None:
        """
        This method initializes the config dialog.
        """
        super().__init__()
        self.setWindowTitle("Taint Model")
        self.setMinimumWidth(450)
        self._init_widgets()
        return

    def _init_widgets(self) -> None:
        """
        This method initializes the widgets for the config dialog.
        """
        # Widgets
        self.syn_wid = qtw.QLineEdit()
        self.syn_wid.setToolTip("function signature")
        self.src_par_slice_wid = qtw.QLineEdit("False")
        self.src_par_slice_wid.setToolTip(
            "expression specifying which parameter 'i' to slice (e.g. 'i >= 1')"
        )
        self.snk_par_slice_wid = qtw.QLineEdit("False")
        self.snk_par_slice_wid.setToolTip(
            "expression specifying which parameter 'i' to slice (e.g. 'i >= 1')"
        )
        self.src_enabled_wid = qtw.QCheckBox()
        self.src_enabled_wid.setToolTip("use as source function")
        self.snk_enabled_wid = qtw.QCheckBox()
        self.snk_enabled_wid.setToolTip("use as sink function")
        self.fix_enabled_wid = qtw.QCheckBox()
        self.fix_enabled_wid.setToolTip("fix function's type signature")
        self.cat_wid = qtw.QLineEdit("Default")
        self.cat_wid.setToolTip("category of the function (for UI grouping only)")
        # Function layout
        fun_lay = qtw.QGridLayout()
        fun_lay.addWidget(qtw.QLabel("Category:"), 0, 0)
        fun_lay.addWidget(self.cat_wid, 0, 1, 1, 3)
        fun_lay.addWidget(qtw.QLabel("Synopsis:"), 1, 0)
        fun_lay.addWidget(self.syn_wid, 1, 1, 1, 3)
        fun_lay.addWidget(qtw.QLabel("Src Enabled:"), 2, 0)
        fun_lay.addWidget(self.src_enabled_wid, 2, 1)
        fun_lay.addWidget(qtw.QLabel("Src Par Slice:"), 2, 2)
        fun_lay.addWidget(self.src_par_slice_wid, 2, 3)
        fun_lay.addWidget(qtw.QLabel("Snk Enabled:"), 3, 0)
        fun_lay.addWidget(self.snk_enabled_wid, 3, 1)
        fun_lay.addWidget(qtw.QLabel("Snk Par Slice:"), 3, 2)
        fun_lay.addWidget(self.snk_par_slice_wid, 3, 3)
        fun_lay.addWidget(qtw.QLabel("Fix Enabled:"), 4, 0)
        fun_lay.addWidget(self.fix_enabled_wid, 4, 1, 1, 3)
        # Function widget
        fun_wid = qtw.QGroupBox("Function:")
        fun_wid.setLayout(fun_lay)
        # Find button widget
        find_but = qtw.QPushButton("Find")
        find_but.clicked.connect(
            lambda: self.signal_find.emit(
                self.inst,
                self.all_callsites,
                self.name,
                self.syn_wid.text().strip(),
                self.src_enabled_wid.isChecked(),
                self.src_par_slice_wid.text().strip(),
                self.snk_enabled_wid.isChecked(),
                self.snk_par_slice_wid.text().strip(),
                self.fix_enabled_wid.isChecked(),
            )
        )
        self.signal_find_feedback.connect(
            lambda tmp_text, new_text, msec: give_feedback(
                find_but, tmp_text, new_text, msec
            )
        )
        # Add button widget
        add_but = qtw.QPushButton("Add")
        add_but.clicked.connect(
            lambda: self.signal_add.emit(
                self.name,
                self.cat_wid.text().strip(),
                self.syn_wid.text().strip(),
                self.src_enabled_wid.isChecked(),
                self.src_par_slice_wid.text().strip(),
                self.snk_enabled_wid.isChecked(),
                self.snk_par_slice_wid.text().strip(),
                self.fix_enabled_wid.isChecked(),
            )
        )
        self.signal_add_feedback.connect(
            lambda tmp_text, new_text, msec: give_feedback(
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
        dialog_lay.addWidget(fun_wid)
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
        all_callsites: bool,
        name: str,
        synopsis: str,
    ) -> None:
        """
        This method sets the dialog's fields according to the given parameters.
        """
        self.inst = inst
        self.all_callsites = all_callsites
        self.name = name
        self.syn_wid.setText(synopsis)
        self.src_enabled_wid.setChecked(False)
        self.src_par_slice_wid.setText("False")
        self.snk_enabled_wid.setChecked(False)
        self.snk_par_slice_wid.setText("False")
        self.fix_enabled_wid.setChecked(False)
        return
