from __future__ import annotations
from mole.core.data import Path
from mole.grouping import PathGrouper
from mole.models.path import PathColumn, PathRole, PathSortProxyModel, PathTreeModel
from typing import Callable, List, Optional
import binaryninja as bn
import binaryninjaui as bnui
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui
import PySide6.QtWidgets as qtw


class PathTreeView(qtw.QTreeView):
    """
    This class implements a tree view for displaying paths grouped by source, sink and call graph.
    """

    signal_show_ai_report = qtc.Signal(list)

    def __init__(self, parent=None) -> None:
        """
        This method initializes the path tree view.
        """
        super().__init__(parent)
        self.path_tree_model = PathTreeModel()
        self.path_sort_proxy_model = PathSortProxyModel()
        self.path_sort_proxy_model.setSourceModel(self.path_tree_model)
        self.setModel(self.path_sort_proxy_model)

        # Configure view properties
        self.setSelectionMode(qtw.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setSelectionBehavior(qtw.QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSortingEnabled(True)
        self.setUniformRowHeights(True)  # Optimize performance for tree views
        self.setExpandsOnDoubleClick(
            False
        )  # Don't expand on double click since we use it for navigation
        self.setContextMenuPolicy(qtc.Qt.ContextMenuPolicy.CustomContextMenu)
        self.header().setSectionResizeMode(qtw.QHeaderView.ResizeMode.Interactive)
        self.header().setStretchLastSection(True)

        # Ensure the columns are appropriately sized initially
        for col in range(self.path_tree_model.columnCount()):
            self.resizeColumnToContents(col)

        # Track if signals are connected
        self._context_menu_connected = False
        self._navigation_connected = False
        self._context_menu_function = None

        # Connect only to proxy model signals for consistency
        self.path_sort_proxy_model.rowsInserted.connect(
            self._handle_rows_inserted_or_changed
        )
        self.path_sort_proxy_model.modelReset.connect(self.refresh_view)

        # Connect to proxy model data changed signal to capture comment edits
        self.path_sort_proxy_model.dataChanged.connect(self._handle_comment_edit)
        return

    def refresh_view(self) -> None:
        """
        This method refreshes the view by expanding all items and resizing columns. It is called
        when new paths are added to ensure proper display.
        """
        # Resize columns to fit content
        for col in range(self.path_tree_model.columnCount()):
            self.resizeColumnToContents(col)

        # Apply proper column spanning
        self._handle_spanning_for_all_items()

        # Expand all items for better visibility
        self.expandAll()
        return

    def _handle_rows_inserted_or_changed(self, *args) -> None:
        """
        This method is a generic handler for when rows are inserted or data changes. It replaces the
        separate handlers for each model's signals.
        """
        # Resize columns to fit content
        for col in range(self.path_tree_model.columnCount()):
            self.resizeColumnToContents(col)

        # Apply proper column spanning
        self._handle_spanning_for_all_items()

        # Expand all items for better visibility
        self.expandAll()
        return

    def _handle_spanning_for_all_items(self) -> None:
        """
        This method ensures all header items have column spanning set correctly. It is called after
        items are added to ensure proper spanning.
        """
        # Reset all spanning first
        self._apply_spanning_recursively(qtc.QModelIndex())
        return

    def _apply_spanning_recursively(
        self, proxy_parent_index: qtc.QModelIndex | qtc.QPersistentModelIndex
    ) -> None:
        """
        This method applies spanning to all items recursively.
        """
        for row in range(self.path_sort_proxy_model.rowCount(proxy_parent_index)):
            proxy_index = self.path_sort_proxy_model.index(row, 0, proxy_parent_index)
            source_index = self.path_sort_proxy_model.mapToSource(proxy_index)
            path_id = self.path_tree_model.data(source_index, PathRole.ID.index)
            if path_id is None:
                # Apply spanning to this item
                self.setFirstColumnSpanned(row, proxy_parent_index, True)
                # Recursively apply to children
                self._apply_spanning_recursively(proxy_index)
        return

    @property
    def model(self) -> PathTreeModel:
        """
        This method returns the underlying model.
        """
        return self.path_tree_model

    def clear_all_paths(self) -> int:
        """
        This method clears all paths from the model.
        """
        path_count = len(self.path_tree_model.paths)
        bn.execute_on_main_thread(self.path_tree_model.clear)
        return path_count

    def get_selected_rows(self) -> List[int]:
        """
        This method returns the currently selected path rows.
        """
        path_rows = set()
        for index in self.selectionModel().selectedIndexes():
            # Only process once per row
            if index.column() != 0:
                continue
            # Map proxy index to source model index
            source_index = self.path_sort_proxy_model.mapToSource(index)
            # Check if this is a path item (not a group header)
            path_id = self.path_tree_model.get_path_id_from_index(source_index)
            if path_id is not None:
                path_rows.add(path_id)
        return sorted(path_rows)

    def remove_selected_paths(self, path_ids: List[int]) -> int:
        """
        This method removes selected paths from the model.
        """
        return self.path_tree_model.remove_selected_paths(path_ids)

    def get_path(self, path_id: int) -> Optional[Path]:
        """
        This method returns the path with the specified ID from the model.
        """
        return self.path_tree_model.get_path(path_id)

    @property
    def paths(self) -> List[Path]:
        """
        This method returns all paths from the model.
        """
        return self.path_tree_model.paths

    def add_path(self, path: Path, path_grouper: Optional[PathGrouper]) -> None:
        """
        This method adds the given path to the path tree model.
        """
        bn.execute_on_main_thread(
            lambda: self.path_tree_model.add_path(path, path_grouper)
        )
        return

    def update_paths(
        self, bv: bn.BinaryView, path_grouper: Optional[PathGrouper]
    ) -> None:
        """
        This method updates all paths in the path tree model.
        """
        bn.execute_on_main_thread(
            lambda: self.path_tree_model.update_paths(bv, path_grouper)
        )
        return

    def regroup_paths(self, path_grouper: Optional[PathGrouper]) -> None:
        """
        This method regroups all paths in the path tree model.
        """
        bn.execute_on_main_thread(
            lambda: self.path_tree_model.regroup_paths(path_grouper)
        )
        return

    def setup_context_menu(
        self,
        on_log_path: Callable[[List[int], bool], None],
        on_log_path_diff: Callable[[List[int]], None],
        on_log_call: Callable[[List[int], bool], None],
        on_highlight_path: Callable[[List[int]], None],
        on_show_call_graph: Callable[[List[int]], None],
        on_import_paths: Callable[[], None],
        on_export_paths: Callable[[List[int]], None],
        on_update_paths: Callable[[], None],
        on_remove_selected: Callable[[List[int]], None],
        on_clear_all: Callable[[], None],
        on_analyze_paths: Callable[[List[int]], None],
        on_show_ai_report: Callable[[List[int]], None],
        bv: bn.BinaryView = None,
    ) -> None:
        """
        This method sets up the context menu for the view.
        """

        def show_context_menu(pos: qtc.QPoint) -> None:
            # Get selected rows and expanded export rows
            rows = self.get_selected_rows()
            export_rows = self._get_expanded_export_rows(pos, rows)
            has_single_row_and_bv = len(rows) == 1 and bv is not None

            # Create context menu
            menu = qtw.QMenu(self)

            # Instruction actions
            log_path_action = self._add_menu_action(
                menu, "Log instructions (backward)", len(rows) == 1
            )
            log_path_action.triggered.connect(lambda: on_log_path(rows, False))
            log_path_reversed_action = self._add_menu_action(
                menu, "Log instructions (forward)", len(rows) == 1
            )
            log_path_reversed_action.triggered.connect(lambda: on_log_path(rows, True))
            log_path_diff_action = self._add_menu_action(
                menu, "Log instruction difference (backward)", len(rows) == 2
            )
            log_path_diff_action.triggered.connect(lambda: on_log_path_diff(rows))
            highlight_path_action = self._add_menu_action(
                menu, "Un-/highlight instructions", has_single_row_and_bv
            )
            highlight_path_action.triggered.connect(lambda: on_highlight_path(rows))
            menu.addSeparator()
            # Call actions
            log_call_action = self._add_menu_action(
                menu, "Log calls (backward)", len(rows) == 1
            )
            log_call_action.triggered.connect(lambda: on_log_call(rows, False))
            log_call_reversed_action = self._add_menu_action(
                menu, "Log calls (forward)", len(rows) == 1
            )
            log_call_reversed_action.triggered.connect(lambda: on_log_call(rows, True))
            show_call_graph_action = self._add_menu_action(
                menu, "Show call graph", has_single_row_and_bv
            )
            show_call_graph_action.triggered.connect(lambda: on_show_call_graph(rows))
            menu.addSeparator()
            # AI-generated vulnerability report actions
            run_ai_analysis_action = self._add_menu_action(
                menu, "Run AI analysis", len(rows) >= 1
            )
            run_ai_analysis_action.triggered.connect(lambda: on_analyze_paths(rows))

            def enable_show_ai_report(rows: List[int]) -> bool:
                if len(rows) != 1:
                    return False
                path = self.path_tree_model.get_path(rows[0])
                if path and path.ai_report:
                    return True
                return False

            show_ai_report_action = self._add_menu_action(
                menu, "Show AI report", enable_show_ai_report(rows)
            )
            show_ai_report_action.triggered.connect(lambda: on_show_ai_report(rows))
            menu.addSeparator()
            # Tree-specific actions
            expand_all_action = menu.addAction("Expand all")
            expand_all_action.triggered.connect(self.expandAll)
            collapse_all_action = menu.addAction("Collapse all")
            collapse_all_action.triggered.connect(self.collapseAll)
            menu.addSeparator()
            # Import/export actions
            import_paths_action = menu.addAction("Import from file")
            import_paths_action.triggered.connect(on_import_paths)
            export_paths_action = self._add_menu_action(
                menu, "Export to file", len(self.path_tree_model.paths) > 0
            )
            export_paths_action.triggered.connect(lambda: on_export_paths(export_rows))
            menu.addSeparator()
            # Update actions
            update_paths_action = self._add_menu_action(
                menu, "Update view", len(self.path_tree_model.paths) > 0
            )
            update_paths_action.triggered.connect(on_update_paths)
            menu.addSeparator()
            # Remove actions
            remove_selected_action = self._add_menu_action(
                menu, "Remove selected", len(rows) > 0
            )
            remove_selected_action.triggered.connect(lambda: on_remove_selected(rows))
            clear_all_action = self._add_menu_action(
                menu, "Clear all", len(self.path_tree_model.paths) > 0
            )
            clear_all_action.triggered.connect(on_clear_all)

            # Execute menu
            menu.exec(self.viewport().mapToGlobal(pos))

        # Store the function reference to enable future disconnections if needed
        self._context_menu_function = show_context_menu

        # Disconnect any existing connections to prevent multiple triggers
        if self._context_menu_connected:
            self.customContextMenuRequested.disconnect()

        # Connect the signal and mark as connected
        self.customContextMenuRequested.connect(show_context_menu)
        self._context_menu_connected = True
        return

    def _add_menu_action(
        self, menu: qtw.QMenu, text: str, enabled: bool = True
    ) -> qtui.QAction:
        """
        This method is a helper to add a menu action with enabled state.
        """
        action = menu.addAction(text)
        action.setEnabled(enabled)
        return action

    def _get_expanded_export_rows(
        self, pos: qtc.QPoint, selected_rows: List[int]
    ) -> List[int]:
        """
        This method returns an expanded list of rows for export, including all child paths if a
        header is clicked.
        """
        export_rows = selected_rows.copy()

        # Get the index at the clicked position
        clicked_idx = self.indexAt(pos)
        if not clicked_idx.isValid():
            return export_rows

        clicked_source_idx = self.path_sort_proxy_model.mapToSource(clicked_idx)

        # Check if the clicked item is a group/header (not a path item)
        path_id = self.path_tree_model.data(clicked_source_idx, PathRole.ID.index)
        if path_id is not None:
            return export_rows

        # Recursively gather all path IDs under this group/header
        child_paths = []
        self._collect_child_paths(clicked_source_idx, child_paths)

        # Include all child paths for export operations
        if child_paths:
            # Ensure we only include valid path IDs
            valid_child_paths = []
            for path_id in child_paths:
                if path_id is not None and path_id in self.path_tree_model.path_map:
                    valid_child_paths.append(path_id)

            export_rows = sorted(set(export_rows + valid_child_paths))

        return export_rows

    def _collect_child_paths(self, parent_idx, path_list: List[int]) -> None:
        """
        This method recursively collects all path IDs under a parent index.
        """
        for row in range(self.path_tree_model.rowCount(parent_idx)):
            child_idx = self.path_tree_model.index(row, 0, parent_idx)
            path_id = self.path_tree_model.data(child_idx, PathRole.ID.index)
            # Header
            if path_id is None:
                self._collect_child_paths(child_idx, path_list)
            else:
                if path_id not in path_list:
                    path_list.append(path_id)
        return

    def setup_navigation(self, bv: bn.BinaryView = None) -> None:
        """
        This method sets up navigation for the view.
        """

        def navigate(index: qtc.QModelIndex) -> None:
            if not bv:
                return

            ctx = bnui.UIContext.activeContext()
            if not ctx:
                return

            vf = ctx.getCurrentViewFrame()
            if not vf:
                return

            # Map proxy index to source model index
            source_index = self.path_sort_proxy_model.mapToSource(index)

            # Check if this is a path item (not a group header)
            path_id = self.path_tree_model.get_path_id_from_index(source_index)
            if path_id is None:
                return

            col = index.column()

            # Navigate based on column
            path = self.get_path(path_id)
            if path:
                # Navigate to source address
                if col in [
                    PathColumn.SRC_ADDR.index,
                    PathColumn.SRC_FUNC.index,
                    PathColumn.SRC_PARM.index,
                ]:
                    vf.navigate(bv, path.src_sym_addr)
                # Navigate to sink address
                elif col in [
                    PathColumn.SNK_ADDR.index,
                    PathColumn.SNK_FUNC.index,
                    PathColumn.SNK_PARM.index,
                ]:
                    vf.navigate(bv, path.snk_sym_addr)
                # Navigate to AI-generated vulnerability report
                elif col == PathColumn.AI_SEVERITY.index:
                    self.signal_show_ai_report.emit([path_id])

        # Disconnect existing navigation signals to prevent multiple connections
        if self._navigation_connected:
            self.doubleClicked.disconnect()

        # Connect the cell double-clicked signal and mark as connected
        self.doubleClicked.connect(navigate)
        self._navigation_connected = True
        return

    def _handle_comment_edit(
        self,
        topLeft: qtc.QModelIndex,
        bottomRight: qtc.QModelIndex,
        roles: List[qtc.Qt.ItemDataRole],
    ) -> None:
        """
        This method handles comment edits in the view and updates the underlying model's comment.
        """
        # Only process if the data change includes the display role
        if qtc.Qt.DisplayRole not in roles and qtc.Qt.EditRole not in roles:
            return
        # Check if this edit spans the comment column
        if topLeft.column() <= PathColumn.COMMENT.index <= bottomRight.column():
            # Process each row in the changed range
            for row in range(topLeft.row(), bottomRight.row() + 1):
                # Get the index for the comment column in the current row
                comment_idx = self.path_sort_proxy_model.index(
                    row, PathColumn.COMMENT.index, topLeft.parent()
                )
                # Map to source index and get the path ID
                source_idx = self.path_sort_proxy_model.mapToSource(comment_idx)
                path_id = self.path_tree_model.get_path_id_from_index(source_idx)
                # If this is a valid path item, update its comment in the model
                if path_id is not None:
                    new_comment = comment_idx.data(qtc.Qt.DisplayRole)
                    self.path_tree_model.update_path_comment(path_id, new_comment)
        return
