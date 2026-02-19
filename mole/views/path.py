from __future__ import annotations
from mole.common.helper.ui import give_feedback
from mole.models.path import PathColumn, PathProxyModel, PathTreeModel
from typing import Callable, cast, List, Tuple, TYPE_CHECKING
import binaryninjaui as bnui
import PySide6.QtCore as qtc
import PySide6.QtWidgets as qtw

if TYPE_CHECKING:
    from mole.data.path import Path


class PathView(qtw.QWidget):
    """
    This class implements a view for Mole's path tab.
    """

    signal_find_paths = qtc.Signal()
    signal_find_paths_feedback = qtc.Signal(str, str, int)
    signal_load_paths = qtc.Signal()
    signal_load_paths_feedback = qtc.Signal(str, str, int)
    signal_save_paths = qtc.Signal()
    signal_save_paths_feedback = qtc.Signal(str, str, int)
    signal_auto_update_paths = qtc.Signal(bool)

    def __init__(self, path_tree_view: PathTreeView) -> None:
        """
        This method initializes the path view.
        """
        super().__init__()
        self.path_tree_view = path_tree_view
        self._init_widgets()
        return

    def _init_widgets(self) -> None:
        """
        This method initializes the path view's widgets.
        """
        # Find button widget
        find_but_wid = qtw.QPushButton("Find")
        find_but_wid.clicked.connect(self.signal_find_paths.emit)
        self.signal_find_paths_feedback.connect(
            lambda tmp_text, new_text, msec: give_feedback(
                find_but_wid, tmp_text, new_text, msec
            )
        )
        # Load button widget
        load_but_wid = qtw.QPushButton("Load")
        load_but_wid.clicked.connect(self.signal_load_paths.emit)
        self.signal_load_paths_feedback.connect(
            lambda tmp_text, new_text, msec: give_feedback(
                load_but_wid, tmp_text, new_text, msec
            )
        )
        # Save button widget
        save_but_wid = qtw.QPushButton("Save")
        save_but_wid.clicked.connect(self.signal_save_paths.emit)
        self.signal_save_paths_feedback.connect(
            lambda tmp_text, new_text, msec: give_feedback(
                save_but_wid, tmp_text, new_text, msec
            )
        )
        # Auto-update button widget
        update_but_wid = qtw.QPushButton("Auto-Update")
        update_but_wid.setCheckable(True)
        update_but_wid.setChecked(True)
        update_but_wid.toggled.connect(
            lambda checked: self.signal_auto_update_paths.emit(checked)
        )
        # Buttons layout
        but_lay = qtw.QHBoxLayout()
        but_lay.addWidget(find_but_wid)
        but_lay.addWidget(load_but_wid)
        but_lay.addWidget(save_but_wid)
        but_lay.addWidget(update_but_wid)
        # Buttons widget
        but_wid = qtw.QWidget()
        but_wid.setLayout(but_lay)
        # Tab layout
        tab_lay = qtw.QVBoxLayout()
        tab_lay.addWidget(self.path_tree_view)
        tab_lay.addWidget(but_wid)
        self.setLayout(tab_lay)
        return


class PathTreeView(qtw.QTreeView):
    """
    This class implements a view for Mole's path tree.
    """

    signal_show_ai_report = qtc.Signal(object)

    def __init__(self, path_proxy_model: PathProxyModel) -> None:
        """
        This method initializes the path tree view.
        """
        super().__init__()
        self.setSelectionMode(qtw.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setSelectionBehavior(qtw.QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSortingEnabled(True)
        self.setUniformRowHeights(True)
        self.setExpandsOnDoubleClick(False)
        self.setContextMenuPolicy(qtc.Qt.ContextMenuPolicy.CustomContextMenu)
        self.header().setSectionResizeMode(qtw.QHeaderView.ResizeMode.Interactive)
        self.header().setStretchLastSection(True)
        self.setModel(path_proxy_model)
        return

    def navigate(self, proxy_index: qtc.QModelIndex) -> None:
        # Get context, view frame and binary view
        ctx = bnui.UIContext.activeContext()  # type: ignore
        if ctx is None:
            return
        vf = ctx.getCurrentViewFrame()
        if vf is None:
            return
        bv = vf.getCurrentBinaryView()
        if bv is None:
            return
        # Get the models
        path_proxy_model = cast(PathProxyModel, self.model())
        path_tree_model = cast(PathTreeModel, path_proxy_model.sourceModel())
        # Map to tree model index
        tree_index = path_proxy_model.mapToSource(proxy_index)
        # Only navigate on path items (not group headers)
        path_id = path_tree_model.get_path_id(tree_index)
        if path_id is None:
            return
        # Only navigate on valid paths
        path = path_tree_model.get_path(path_id)
        if path is not None:
            column = proxy_index.column()
            # Navigate to source address
            if column in [
                PathColumn.SRC_ADDR.index,
                PathColumn.SRC_FUNC.index,
                PathColumn.SRC_PARM.index,
            ]:
                vf.navigate(bv, path.src_sym_addr)
            # Navigate to sink address
            elif column in [
                PathColumn.SNK_ADDR.index,
                PathColumn.SNK_FUNC.index,
                PathColumn.SNK_PARM.index,
            ]:
                vf.navigate(bv, path.snk_sym_addr)
            # Navigate to AI-generated vulnerability report
            elif column == PathColumn.AI_SEVERITY.index:
                self.signal_show_ai_report.emit(path)
        return

    def _resize_columns_to_contents(self) -> None:
        """
        This method resizes all columns to fit their contents.
        """
        # Get the model
        path_proxy_model = cast(PathProxyModel, self.model())
        # Resize all columns to fit contents
        for column in range(path_proxy_model.columnCount()):
            self.resizeColumnToContents(column)
        return

    def _apply_spanning(
        self,
        parent_proxy_index: qtc.QModelIndex
        | qtc.QPersistentModelIndex = qtc.QModelIndex(),
    ) -> None:
        """
        This method iterates over all children of the given parent. If a child is a group header, it
        spans its first column and then recursively processes its children to apply spanning in them
        where needed. If no parent is given, the root item is used instead.
        """
        # Get the models
        path_proxy_model = cast(PathProxyModel, self.model())
        path_tree_model = cast(PathTreeModel, path_proxy_model.sourceModel())
        # Iterate over all children of the given parent
        for child_proxy_row in range(path_proxy_model.rowCount(parent_proxy_index)):
            # Get the child's indexes
            child_proxy_index = path_proxy_model.index(
                child_proxy_row, 0, parent_proxy_index
            )
            child_tree_index = path_proxy_model.mapToSource(child_proxy_index)
            # Get the child's path ID
            path_id = path_tree_model.get_path_id(child_tree_index)
            # If the child is a group header, span its first column and recursively process its
            # children
            if path_id is None:
                self.setFirstColumnSpanned(child_proxy_row, parent_proxy_index, True)
                self._apply_spanning(child_proxy_index)
        return

    def refresh_view(self) -> None:
        """
        This method refreshes the view by expanding all items and resizing columns. It is called
        when new paths are added to ensure proper display.
        """
        self._resize_columns_to_contents()
        self._apply_spanning()
        self.expandAll()
        return

    def handle_comment_edit(
        self,
        topLeft: qtc.QModelIndex,
        bottomRight: qtc.QModelIndex,
        roles: List[qtc.Qt.ItemDataRole],
    ) -> None:
        """
        This method handles comment edits in the view and updates the underlying model's comment.
        """
        # Check if this edit includes the display or edit role
        if all(role not in roles for role in (qtc.Qt.DisplayRole, qtc.Qt.EditRole)):  # type: ignore
            return
        # Check if this edit spans the comment column
        if topLeft.column() <= PathColumn.COMMENT.index <= bottomRight.column():
            # Get the models
            path_proxy_model = cast(PathProxyModel, self.model())
            path_tree_model = cast(PathTreeModel, path_proxy_model.sourceModel())
            # Process each row in the changed range
            for proxy_row in range(topLeft.row(), bottomRight.row() + 1):
                # Get the comment's indexes
                comment_proxy_index = path_proxy_model.index(
                    proxy_row, PathColumn.COMMENT.index, topLeft.parent()
                )
                comment_tree_index = path_proxy_model.mapToSource(comment_proxy_index)
                # Update the comment
                path_id = path_tree_model.get_path_id(comment_tree_index)
                if path_id is not None:
                    path = path_tree_model.get_path(path_id)
                    if path is not None:
                        new_comment = str(comment_tree_index.data(qtc.Qt.DisplayRole))  # type: ignore
                        path.comment = new_comment
        return

    def _get_selected_paths(self) -> List[int]:
        """
        This method returns a sorted list of unique path IDs corresponding to the selected rows in
        the view.
        """
        # Get the models
        path_proxy_model = cast(PathProxyModel, self.model())
        path_tree_model = cast(PathTreeModel, path_proxy_model.sourceModel())
        # Get selected path IDs
        path_ids = set()
        for proxy_index in self.selectionModel().selectedIndexes():
            # Process only once per row
            if proxy_index.column() != 0:
                continue
            # Get tree index
            tree_index = path_proxy_model.mapToSource(proxy_index)
            # Get the path ID
            path_id = path_tree_model.get_path_id(tree_index)
            # Store path ID if it is not a group header
            if path_id is not None:
                path_ids.add(path_id)
        return sorted(path_ids)

    def _get_child_paths(
        self,
        parent_proxy_index: qtc.QModelIndex
        | qtc.QPersistentModelIndex = qtc.QModelIndex(),
        path_ids: List[int] = [],
    ) -> List[int]:
        """
        This method recursively collects all path IDs under the given parent.
        """
        # Get the models
        path_proxy_model = cast(PathProxyModel, self.model())
        path_tree_model = cast(PathTreeModel, path_proxy_model.sourceModel())
        # Iterate over all children of the given parent
        for child_proxy_row in range(path_proxy_model.rowCount(parent_proxy_index)):
            # Get the child's indexes
            child_proxy_index = path_proxy_model.index(
                child_proxy_row, 0, parent_proxy_index
            )
            child_tree_index = path_proxy_model.mapToSource(child_proxy_index)
            # Get the child's path ID
            path_id = path_tree_model.get_path_id(child_tree_index)
            # Group header
            if path_id is None:
                self._get_child_paths(child_proxy_index, path_ids)
            # Path item
            else:
                if path_id not in path_ids:
                    path_ids.append(path_id)
        return path_ids

    def _get_expanded_paths(self, pos: qtc.QPoint, path_ids: List[int]) -> List[int]:
        """
        This method adds all collapsed child paths under a clicked group header to the given list of
        path IDs.
        """
        # Get the models
        path_proxy_model = cast(PathProxyModel, self.model())
        path_tree_model = cast(PathTreeModel, path_proxy_model.sourceModel())
        # Copy the given path IDs
        expanded_path_ids = path_ids.copy()
        # Get the indexes (of the clicked position)
        proxy_index = self.indexAt(pos)
        if not proxy_index.isValid():
            return sorted(expanded_path_ids)
        tree_index = path_proxy_model.mapToSource(proxy_index)
        # Get the path ID (of the clicked position)
        path_id = path_tree_model.get_path_id(tree_index)
        # Add the path ID to the list if a path item is clicked
        if path_id is not None:
            if path_id not in expanded_path_ids:
                expanded_path_ids.append(path_id)
            return sorted(expanded_path_ids)
        # Get all children path IDs recursively if a group header is clicked
        child_path_ids = self._get_child_paths(proxy_index, [])
        for child_path_id in child_path_ids:
            if child_path_id is not None and child_path_id not in expanded_path_ids:
                expanded_path_ids.append(child_path_id)
        return sorted(expanded_path_ids)

    def setup_context_menu(
        self,
        pos: qtc.QPoint,
        on_log_path: Callable[[int | None, bool], None],
        on_log_path_diff: Callable[[List[int]], None],
        on_log_call: Callable[[List[int], bool], None],
        on_highlight_path: Callable[[List[int]], None],
        on_show_call_graph: Callable[[int | None, Path | None], None],
        on_import_paths: Callable[[], None],
        on_export_paths: Callable[[List[int]], None],
        on_update_paths: Callable[[], None],
        on_remove_paths: Callable[[List[int]], None],
        on_clear_paths: Callable[[], None],
        is_ai_analysis_alive: Callable[[], bool],
        on_start_ai_analysis: Callable[[List[Tuple[int, Path]]], None],
        on_cancel_ai_analysis: Callable[[], None],
        on_show_ai_report: Callable[[Path | None], None],
    ) -> None:
        """
        This method sets up a context menu for the path tree view.
        """
        # Get the models
        path_proxy_model = cast(PathProxyModel, self.model())
        path_tree_model = cast(PathTreeModel, path_proxy_model.sourceModel())
        # Get selected (expanded) paths
        selected_path_ids = self._get_selected_paths()
        expanded_path_ids = self._get_expanded_paths(pos, selected_path_ids)
        # Create context menu
        menu = qtw.QMenu(self)
        # Add instruction actions to the context menu
        log_path_action = menu.addAction("Log instructions (backward)")
        if len(expanded_path_ids) == 1:
            log_path_action.setEnabled(True)
            path_id = expanded_path_ids[0]
        else:
            log_path_action.setEnabled(False)
            path_id = None
        log_path_action.triggered.connect(lambda: on_log_path(path_id, False))
        log_path_reversed_action = menu.addAction("Log instructions (forward)")
        if len(expanded_path_ids) == 1:
            log_path_reversed_action.setEnabled(True)
            path_id = expanded_path_ids[0]
        else:
            log_path_reversed_action.setEnabled(False)
            path_id = None
        log_path_reversed_action.triggered.connect(lambda: on_log_path(path_id, True))
        log_path_diff_action = menu.addAction("Log instruction difference (backward)")
        log_path_diff_action.setEnabled(len(expanded_path_ids) == 2)
        log_path_diff_action.triggered.connect(
            lambda: on_log_path_diff(expanded_path_ids)
        )
        highlight_path_action = menu.addAction("Un-/highlight instructions")
        highlight_path_action.setEnabled(len(expanded_path_ids) == 1)
        highlight_path_action.triggered.connect(
            lambda: on_highlight_path(expanded_path_ids)
        )
        menu.addSeparator()
        # Add call actions to the context menu
        log_call_action = menu.addAction("Log calls (backward)")
        log_call_action.setEnabled(len(expanded_path_ids) == 1)
        log_call_action.triggered.connect(lambda: on_log_call(expanded_path_ids, False))
        log_call_reversed_action = menu.addAction("Log calls (forward)")
        log_call_reversed_action.setEnabled(len(expanded_path_ids) == 1)
        log_call_reversed_action.triggered.connect(
            lambda: on_log_call(expanded_path_ids, True)
        )
        show_call_graph_action = menu.addAction("Show call graph")
        if len(expanded_path_ids) == 1:
            show_call_graph_action.setEnabled(True)
            path_id = expanded_path_ids[0]
            path = path_tree_model.get_path(path_id)
        else:
            show_call_graph_action.setEnabled(False)
            path_id = None
            path = None
        show_call_graph_action.triggered.connect(
            lambda: on_show_call_graph(path_id, path)
        )
        menu.addSeparator()
        # Add AI-specific actions to the context menu
        start_ai_analysis_action = menu.addAction("Start AI analysis")
        paths: List[Tuple[int, Path]] = []
        if len(expanded_path_ids) >= 1 and not is_ai_analysis_alive():
            start_ai_analysis_action.setEnabled(True)
            for path_id in expanded_path_ids:
                path = path_tree_model.get_path(path_id)
                if path is not None:
                    paths.append((path_id, path))
        else:
            start_ai_analysis_action.setEnabled(False)
        start_ai_analysis_action.triggered.connect(lambda: on_start_ai_analysis(paths))
        cancel_ai_analysis_action = menu.addAction("Cancel AI analysis")
        if is_ai_analysis_alive():
            cancel_ai_analysis_action.setEnabled(True)
        else:
            cancel_ai_analysis_action.setEnabled(False)
        cancel_ai_analysis_action.triggered.connect(lambda: on_cancel_ai_analysis())
        show_ai_report_action = menu.addAction("Show AI report")
        show_ai_report_action.setEnabled(False)
        path = None
        if len(expanded_path_ids) == 1:
            path = path_tree_model.get_path(expanded_path_ids[0])
            if path is not None and path.ai_report is not None:
                show_ai_report_action.setEnabled(True)
        show_ai_report_action.triggered.connect(lambda: on_show_ai_report(path))
        menu.addSeparator()
        # Add tree-specific actions to the context menu
        expand_all_action = menu.addAction("Expand all")
        expand_all_action.setEnabled(len(path_tree_model.paths) > 0)
        expand_all_action.triggered.connect(self.expandAll)
        collapse_all_action = menu.addAction("Collapse all")
        collapse_all_action.setEnabled(len(path_tree_model.paths) > 0)
        collapse_all_action.triggered.connect(self.collapseAll)
        menu.addSeparator()
        # Add import/export actions to the context menu
        import_paths_action = menu.addAction("Import from file")
        import_paths_action.triggered.connect(on_import_paths)
        export_paths_action = menu.addAction("Export to file")
        export_paths_action.setEnabled(len(path_tree_model.paths) > 0)
        export_paths_action.triggered.connect(
            lambda: on_export_paths(expanded_path_ids)
        )
        menu.addSeparator()
        # Add update actions to the context menu
        update_paths_action = menu.addAction("Update paths")
        update_paths_action.setEnabled(len(path_tree_model.paths) > 0)
        update_paths_action.triggered.connect(on_update_paths)
        menu.addSeparator()
        # Add remove actions to the context menu
        remove_paths_action = menu.addAction("Remove selected")
        remove_paths_action.setEnabled(len(expanded_path_ids) > 0)
        remove_paths_action.triggered.connect(
            lambda: on_remove_paths(expanded_path_ids)
        )
        clear_paths_action = menu.addAction("Clear all")
        clear_paths_action.setEnabled(len(path_tree_model.paths) > 0)
        clear_paths_action.triggered.connect(on_clear_paths)
        # Execute context menu
        menu.exec(self.viewport().mapToGlobal(pos))
        return
