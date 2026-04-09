from __future__ import annotations
from mole.common.helper.ui import give_feedback
from mole.data.config import (
    Category,
    CheckboxSetting,
    ComboboxSetting,
    DoubleSpinboxSetting,
    Function,
    Library,
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
        self.fun_add_dialog = FunctionAddDialog()
        self.fun_edit_dialog = FunctionEditDialog()
        self._init_widgets()
        return

    def _init_widgets(self) -> None:
        """
        This method initializes the config view's widgets.
        """
        # Subtabs widget
        self._tab_wid = qtw.QTabWidget()
        self._tab_wid.addTab(self._init_cnf_mod_tab(), "Taint Model")
        self._tab_wid.addTab(self._init_cnf_set_tab(), "Settings")
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
        tab_lay.addWidget(self._tab_wid)
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
                if all_items_expanded(self._tree):
                    self._tree.collapseAll()
                else:
                    self._tree.expandAll()
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
                root = self._tree.invisibleRootItem()
                for i in range(root.childCount()):
                    child = root.child(i)
                    self._set_state(child, column, new_state, save_config_feedback)
                    propagate_state_down(child, column, new_state)
                updating = False
            return

        def propagate_state_down(
            item: qtw.QTreeWidgetItem, column: int, state: qtc.Qt.CheckState
        ) -> None:
            for i in range(item.childCount()):
                child = item.child(i)
                self._set_state(child, column, state, save_config_feedback)
                propagate_state_down(child, column, state)
            return

        def propagate_state_up(item: qtw.QTreeWidgetItem, column: int) -> None:
            # Get parent
            parent = item.parent()
            if not parent:
                # Count checks of the root's children
                cnt_checked = 0
                cnt_unchecked = 0
                root = self._tree.invisibleRootItem()
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
                self._set_state(item, column, state)
                propagate_state_down(item, column, state)
                propagate_state_up(item, column)

            updating = False
            return

        def handle_item_double_clicked(item: qtw.QTreeWidgetItem, column: int) -> None:
            # Get function associated with the item
            fun = item.data(TaintModelColumns.FUNCTION.value, qtc.Qt.UserRole)  # type: ignore
            # Ignore double clicks on non-function items and on checkable columns
            if column in checkable_column_states or not isinstance(fun, Function):
                return
            # Execute dialog
            self.fun_edit_dialog.exec(item)
            return

        # Tree widget
        self._tree = qtw.QTreeWidget()
        self._tree.setColumnCount(4)
        self._tree.setHeaderLabels(
            [
                TaintModelColumns.FUNCTION.label,
                TaintModelColumns.SOURCE.label,
                TaintModelColumns.SINK.label,
                TaintModelColumns.FIX.label,
            ]
        )
        self._tree.header().sectionDoubleClicked.connect(
            lambda column: handle_header_double_clicked(column)
        )
        self._tree.itemChanged.connect(handle_item_changed)
        self._tree.itemDoubleClicked.connect(handle_item_double_clicked)
        # Tree widget items
        taint_model = self.model().get_taint_model()
        for _, lib in taint_model.items():
            lib_item = self._add_lib_item(lib)
            for _, cat in lib.categories.items():
                cat_item = self._add_cat_item(lib_item, cat)
                for _, fun in cat.functions.items():
                    self._add_fun_item(cat_item, fun)
        # Resize columns
        for column in range(self._tree.columnCount()):
            self._tree.resizeColumnToContents(column)
        return self._tree

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

    def _set_state(
        self,
        item: qtw.QTreeWidgetItem,
        column: int,
        state: qtc.Qt.CheckState,
        save_config_feedback: bool = True,
    ) -> None:
        # Update model
        fun = item.data(TaintModelColumns.FUNCTION.value, qtc.Qt.UserRole)  # type: ignore
        if isinstance(fun, Function):
            match column:
                case TaintModelColumns.SOURCE.value:
                    fun.src_enabled = state == qtc.Qt.CheckState.Checked
                case TaintModelColumns.SINK.value:
                    fun.snk_enabled = state == qtc.Qt.CheckState.Checked
                case TaintModelColumns.FIX.value:
                    fun.fix_enabled = state == qtc.Qt.CheckState.Checked
        # Update view
        item.setCheckState(column, state)
        if save_config_feedback:
            self.signal_save_config_feedback.emit("Save*", "Save*", 0)
        return

    def _find_child_item(
        self, item: qtw.QTreeWidgetItem, text: str
    ) -> qtw.QTreeWidgetItem | None:
        for i in range(item.childCount()):
            child = item.child(i)
            if child.text(0) == text:
                return child
        return None

    def _add_lib_item(
        self,
        lib: Library,
        font: qtui.QFont = qtui.QFont(qtui.QFont().defaultFamily(), italic=True),
        color: qtui.QBrush = qtui.QBrush(qtui.QColor(255, 239, 213)),
    ) -> qtw.QTreeWidgetItem:
        """
        This method adds a new (or updates the existing) library item to the root item.
        """
        # Get item (create if it does not exist)
        root = self._tree.invisibleRootItem()
        lib_item = self._find_child_item(root, lib.name)
        if lib_item is None:
            lib_item = qtw.QTreeWidgetItem(self._tree, [lib.name])
        # Set item data
        lib_item.setData(TaintModelColumns.FUNCTION.value, qtc.Qt.UserRole, lib)  # type: ignore
        lib_item.setExpanded(True)
        for column in range(self._tree.columnCount()):
            lib_item.setFont(column, font)
            lib_item.setForeground(column, color)
        return lib_item

    def _add_cat_item(
        self,
        lib_item: qtw.QTreeWidgetItem,
        cat: Category,
        font: qtui.QFont = qtui.QFont(qtui.QFont().defaultFamily(), italic=True),
        color: qtui.QBrush = qtui.QBrush(qtui.QColor(255, 239, 213)),
    ) -> qtw.QTreeWidgetItem:
        """
        This method adds a new (or updates the existing) category item to the library item
        `lib_item`.
        """
        # Get item (create if it does not exist)
        cat_item = self._find_child_item(lib_item, cat.name)
        if cat_item is None:
            cat_item = qtw.QTreeWidgetItem(lib_item, [cat.name])
        # Set item data
        cat_item.setData(TaintModelColumns.FUNCTION.value, qtc.Qt.UserRole, cat)  # type: ignore
        for column in range(self._tree.columnCount()):
            cat_item.setFont(column, font)
            cat_item.setForeground(column, color)
        return cat_item

    def _add_fun_item(
        self, cat_item: qtw.QTreeWidgetItem, fun: Function
    ) -> qtw.QTreeWidgetItem:
        """
        This method adds a new (or updates the existing) function item to the category item
        `cat_item`.
        """
        # Get item (create if it does not exist)
        fun_item = self._find_child_item(cat_item, fun.name)
        if fun_item is None:
            fun_item = qtw.QTreeWidgetItem(cat_item, [fun.name])
        # Set item data
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
        return fun_item

    def add_fun(self, lib: Library, cat: Category, fun: Function) -> None:
        """
        This method adds a new (or updates the existing) function under the specified library and
        category.
        """
        lib_item = self._add_lib_item(lib)
        cat_item = self._add_cat_item(lib_item, cat)
        self._add_fun_item(cat_item, fun)
        return

    def refresh_tabs(self, index: int = -1) -> None:
        """
        This method reinitializes the tabs and sets the current tab to the one at `index`. If
        `index` is less than 0, the current tab is not changed.
        """

        def _refresh_tabs() -> None:
            if not self._tab_wid:
                return
            self._tab_wid.clear()
            self._tab_wid.addTab(
                self._init_cnf_mod_tab(save_config_feedback=False), "Taint Model"
            )
            self._tab_wid.addTab(self._init_cnf_set_tab(), "Settings")
            if 0 <= index < self._tab_wid.count():
                self._tab_wid.setCurrentIndex(index)
            self._tab_wid.repaint()
            self._tab_wid.update()

        bn.execute_on_main_thread(_refresh_tabs)
        return


class FunctionConfigDialog(qtw.QDialog):
    """
    This class implements a popup dialog that allows to configure functions.
    """

    def __init__(self) -> None:
        """
        This method initializes the dialog.
        """
        super().__init__()
        self.setWindowTitle("Taint Model")
        self.setMinimumWidth(450)
        # Function
        self.syn_wid = qtw.QLineEdit()
        self.syn_wid.setToolTip("function signature")
        self.ali_wid = qtw.QPlainTextEdit()
        fun_lay = qtw.QGridLayout()
        fun_lay.addWidget(qtw.QLabel("Synopsis:"), 0, 0)
        fun_lay.addWidget(self.syn_wid, 0, 1)
        fun_lay.addWidget(qtw.QLabel("Aliases:"), 1, 0)
        fun_lay.addWidget(self.ali_wid, 1, 1)
        fun_wid = qtw.QGroupBox("Function:")
        fun_wid.setLayout(fun_lay)
        # Role
        self.src_enabled_wid = qtw.QCheckBox()
        self.src_enabled_wid.setToolTip("use as source function")
        self.src_par_slice_wid = qtw.QLineEdit("False")
        self.src_par_slice_wid.setToolTip(
            "expression specifying which parameter 'i' to slice (e.g. 'i >= 1')"
        )
        self.snk_enabled_wid = qtw.QCheckBox()
        self.snk_enabled_wid.setToolTip("use as sink function")
        self.snk_par_slice_wid = qtw.QLineEdit("False")
        self.snk_par_slice_wid.setToolTip(
            "expression specifying which parameter 'i' to slice (e.g. 'i >= 1')"
        )
        self.fix_enabled_wid = qtw.QCheckBox()
        self.fix_enabled_wid.setToolTip("fix function's type signature")
        rol_lay = qtw.QGridLayout()
        rol_lay.addWidget(qtw.QLabel("Src Enabled:"), 0, 0)
        rol_lay.addWidget(self.src_enabled_wid, 0, 1)
        rol_lay.addWidget(qtw.QLabel("Src Par Slice:"), 0, 2)
        rol_lay.addWidget(self.src_par_slice_wid, 0, 3)
        rol_lay.addWidget(qtw.QLabel("Snk Enabled:"), 1, 0)
        rol_lay.addWidget(self.snk_enabled_wid, 1, 1)
        rol_lay.addWidget(qtw.QLabel("Snk Par Slice:"), 1, 2)
        rol_lay.addWidget(self.snk_par_slice_wid, 1, 3)
        rol_lay.addWidget(qtw.QLabel("Fix Enabled:"), 2, 0)
        rol_lay.addWidget(self.fix_enabled_wid, 2, 1, 1, 3)
        rol_wid = qtw.QGroupBox("Role:")
        rol_wid.setLayout(rol_lay)
        # Main
        main_lay = qtw.QVBoxLayout()
        main_lay.addWidget(fun_wid)
        main_lay.addWidget(rol_wid)
        self.setLayout(main_lay)
        return


class FunctionEditDialog(FunctionConfigDialog):
    """
    This class implements a popup dialog that allows to edit functions.
    """

    signal_edit = qtc.Signal(str, str, str, str, list, bool, str, bool, str, bool)
    signal_edit_feedback = qtc.Signal(str, str, int)

    def __init__(self) -> None:
        """
        This method initializes the dialog.
        """
        super().__init__()
        self.item: qtw.QTreeWidgetItem | None = None
        # Get layout
        main_lay = self.layout()
        if not isinstance(main_lay, qtw.QVBoxLayout):
            return
        # Add button widget
        edit_but = qtw.QPushButton("OK")
        edit_but.clicked.connect(self._update)
        self.signal_edit_feedback.connect(
            lambda tmp_text, new_text, msec: give_feedback(
                edit_but, tmp_text, new_text, msec
            )
        )
        cancel_but = qtw.QPushButton("Cancel")
        cancel_but.clicked.connect(self.reject)
        but_lay = qtw.QHBoxLayout()
        but_lay.addWidget(edit_but)
        but_lay.addWidget(cancel_but)
        but_wid = qtw.QWidget()
        but_wid.setLayout(but_lay)
        main_lay.addWidget(but_wid)
        return

    def _update(self) -> None:
        """
        This method emits a signal to update the function associated with the dialog's item.
        """
        # Get library and category names
        if self.item is None:
            return
        fun_name = self.item.text(0)
        parent = self.item.parent()
        if not parent:
            return
        cat_name = parent.text(0)
        grandparent = parent.parent()
        if not grandparent:
            return
        lib_name = grandparent.text(0)
        # Get function properties
        synopsis = self.syn_wid.text().strip()
        aliases = []
        for line in self.ali_wid.toPlainText().splitlines():
            line = line.strip()
            if line:
                aliases.append(line)
        src_enabled = self.src_enabled_wid.isChecked()
        src_par_slice = self.src_par_slice_wid.text().strip()
        snk_enabled = self.snk_enabled_wid.isChecked()
        snk_par_slice = self.snk_par_slice_wid.text().strip()
        fix_enabled = self.fix_enabled_wid.isChecked()
        # Emit signal
        self.signal_edit.emit(
            lib_name,
            cat_name,
            fun_name,
            synopsis,
            aliases,
            src_enabled,
            src_par_slice,
            snk_enabled,
            snk_par_slice,
            fix_enabled,
        )
        return

    def exec(self, item: qtw.QTreeWidgetItem) -> int:
        """
        This method executes the dialog and dynamically sets its values according to the given item.
        """
        # Store item
        self.item = item
        # Get function associated with the item
        fun = self.item.data(TaintModelColumns.FUNCTION.value, qtc.Qt.UserRole)  # type: ignore
        if isinstance(fun, Function):
            # Set dialog values
            self.syn_wid.setText(fun.synopsis)
            self.ali_wid.setPlainText(
                "\n".join(
                    [symbol for symbol in fun.symbols if symbol and symbol != fun.name]
                )
            )
            self.src_enabled_wid.setChecked(fun.src_enabled)
            self.src_par_slice_wid.setText(fun.src_par_slice)
            self.snk_enabled_wid.setChecked(fun.snk_enabled)
            self.snk_par_slice_wid.setText(fun.snk_par_slice)
            self.fix_enabled_wid.setChecked(fun.fix_enabled)
            return super().exec()
        return qtw.QDialog.Rejected  # type: ignore


class FunctionAddDialog(FunctionConfigDialog):
    """
    This class implements a popup dialog that allows to manually add functions.
    """

    signal_find = qtc.Signal(object, bool, str, str, list, bool, str, bool, str, bool)
    signal_find_feedback = qtc.Signal(str, str, int)
    signal_add = qtc.Signal(str, str, str, list, bool, str, bool, str, bool)
    signal_add_feedback = qtc.Signal(str, str, int)

    def __init__(self) -> None:
        """
        This method initializes the dialog.
        """
        super().__init__()
        self.inst: bn.MediumLevelILInstruction | None = None
        self.all_callsites: bool = False
        self.name: str = ""
        # Get layout
        main_lay = self.layout()
        if not isinstance(main_lay, qtw.QVBoxLayout):
            return
        # Add metadata widget
        self.cat_wid = qtw.QLineEdit("Default")
        self.cat_wid.setToolTip("category of the function (for UI grouping only)")
        met_lay = qtw.QGridLayout()
        met_lay.addWidget(qtw.QLabel("Category:"), 0, 0)
        met_lay.addWidget(self.cat_wid, 0, 1)
        met_wid = qtw.QGroupBox("Metadata:")
        met_wid.setLayout(met_lay)
        main_lay.insertWidget(0, met_wid)
        # Add button widget
        find_but = qtw.QPushButton("Find")
        find_but.clicked.connect(
            lambda: self.signal_find.emit(
                self.inst,
                self.all_callsites,
                self.name,
                self.syn_wid.text().strip(),
                self.ali_wid.toPlainText().splitlines(),
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
        add_but = qtw.QPushButton("Add")
        add_but.clicked.connect(
            lambda: self.signal_add.emit(
                self.cat_wid.text().strip(),
                self.name,
                self.syn_wid.text().strip(),
                self.ali_wid.toPlainText().splitlines(),
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
        cancel_but = qtw.QPushButton("Cancel")
        cancel_but.clicked.connect(self.reject)
        but_lay = qtw.QHBoxLayout()
        but_lay.addWidget(find_but)
        but_lay.addWidget(add_but)
        but_lay.addWidget(cancel_but)
        but_wid = qtw.QWidget()
        but_wid.setLayout(but_lay)
        main_lay.addWidget(but_wid)
        return

    def exec(
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
    ) -> int:
        """
        This method executes the dialog and dynamically sets its values.
        """
        self.inst = inst
        self.all_callsites = all_callsites
        self.name = name
        self.syn_wid.setText(synopsis)
        self.ali_wid.setPlainText("")
        self.src_enabled_wid.setChecked(False)
        self.src_par_slice_wid.setText("False")
        self.snk_enabled_wid.setChecked(False)
        self.snk_par_slice_wid.setText("False")
        self.fix_enabled_wid.setChecked(False)
        return super().exec()
