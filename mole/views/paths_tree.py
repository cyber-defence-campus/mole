from __future__ import annotations
from typing import Callable, List, Optional
import binaryninja as bn
import binaryninjaui as bnui
import PySide6.QtCore as qtc
import PySide6.QtWidgets as qtw

from ..models.paths import (
    PathsTreeModel, PathsSortProxyModel,
    SRC_ADDR_COL, SRC_FUNC_COL, SNK_ADDR_COL, SNK_FUNC_COL, SNK_PARM_COL,
    IS_PATH_ITEM_ROLE, COMMENT_COL
)
from ..core.data import Path


class PathsTreeView(qtw.QTreeView):
    """
    This class implements a tree view for displaying paths grouped by source, sink, and call graph.
    """
    
    def __init__(self, parent=None):
        """
        Initialize the path tree view.
        """
        super().__init__(parent)
        self._model = PathsTreeModel()
        self._proxy_model = PathsSortProxyModel()
        self._proxy_model.setSourceModel(self._model)
        self.setModel(self._proxy_model)
        
        # Configure view properties
        self.setSelectionMode(qtw.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setSelectionBehavior(qtw.QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSortingEnabled(True)
        self.setUniformRowHeights(True)  # Optimize performance for tree views
        self.setExpandsOnDoubleClick(False)  # Don't expand on double click since we use it for navigation
        self.setContextMenuPolicy(qtc.Qt.ContextMenuPolicy.CustomContextMenu)
        self.header().setSectionResizeMode(qtw.QHeaderView.ResizeMode.Interactive)
        self.header().setStretchLastSection(True)
        
        # Ensure the columns are appropriately sized initially
        for col in range(self._model.columnCount()):
            self.resizeColumnToContents(col)
        
        # Track if signals are connected
        self._context_menu_connected = False
        self._navigation_connected = False
        self._context_menu_function = None
        
        # Connect only to proxy model signals for consistency
        self._proxy_model.rowsInserted.connect(self._handle_rows_inserted_or_changed)
        self._proxy_model.dataChanged.connect(self._handle_rows_inserted_or_changed)
        self._proxy_model.modelReset.connect(self.refresh_view)
        
        # Connect to proxy model data changed signal to capture comment edits
        self._proxy_model.dataChanged.connect(self._handle_comment_edit)
    
    def refresh_view(self):
        """
        Refresh the view by expanding all items and resizing columns.
        Called when new paths are added to ensure proper display.
        """
        # Resize columns to fit content
        for col in range(self._model.columnCount()):
            self.resizeColumnToContents(col)
            
        # Apply proper column spanning
        self._handle_spanning_for_all_items()
        
        # Expand all items for better visibility
        self.expandAll()
    
    def _handle_rows_inserted_or_changed(self, *args):
        """
        Generic handler for when rows are inserted or data changes.
        This replaces the separate handlers for each model's signals.
        """
        # Resize columns to fit content
        for col in range(self._model.columnCount()):
            self.resizeColumnToContents(col)
            
        # Apply proper column spanning
        self._handle_spanning_for_all_items()
        
        # Expand all items for better visibility
        self.expandAll()
    
    def _handle_spanning_for_all_items(self):
        """
        Ensure all header items have column spanning set correctly.
        Called after items are added to ensure proper spanning.
        """
        # Reset all spanning first
        self._apply_spanning_recursively(qtc.QModelIndex())
    
    def _apply_spanning_recursively(self, proxy_parent_index):
        """
        Apply spanning to all items recursively.
        """
        for row in range(self._proxy_model.rowCount(proxy_parent_index)):
            proxy_index = self._proxy_model.index(row, 0, proxy_parent_index)
            source_index = self._proxy_model.mapToSource(proxy_index)
            is_path_item = self._model.data(source_index, IS_PATH_ITEM_ROLE)
            
            if not is_path_item:
                # Apply spanning to this item
                self.setFirstColumnSpanned(row, proxy_parent_index, True)
                # Recursively apply to children
                self._apply_spanning_recursively(proxy_index)
    
    @property
    def model(self) -> PathsTreeModel:
        """
        Get the underlying model.
        """
        return self._model
    
    def clear(self):
        """
        Clear all paths from the view.
        """
        self._model.clear()
    
    def get_selected_rows(self) -> List[int]:
        """
        Get the currently selected path rows.
        """
        path_rows = []
        for index in self.selectionModel().selectedIndexes():
            if index.column() != 0:  # Only process once per row
                continue
                
            # Map proxy index to source model index
            source_index = self._proxy_model.mapToSource(index)
            
            # Check if this is a path item (not a group header)
            path_id = self._model.get_path_id_from_index(source_index)
            if path_id is not None:
                path_rows.append(path_id)
                
        return sorted(set(path_rows))
    
    def remove_paths_at_rows(self, rows: List[int]):
        """
        Remove the paths at the specified rows.
        """
        self._model.remove_paths_at_rows(rows)
    
    def path_at_row(self, row: int) -> Optional[Path]:
        """
        Get the path at the specified row.
        """
        return self._model.path_at_row(row)
    
    def get_all_paths(self) -> List[Path]:
        """
        Get all paths from the model.
        """
        return self._model.paths
    
    def setup_context_menu(self, 
                           on_log_path: Callable[[List[int], bool], None],
                           on_log_path_diff: Callable[[List[int]], None],
                           on_highlight_path: Callable[[List[int]], None],
                           on_show_call_graph: Callable[[List[int]], None],
                           on_import_paths: Callable[[], None],
                           on_export_paths: Callable[[List[int]], None],
                           on_remove_selected: Callable[[List[int]], None],
                           on_remove_all: Callable[[], None],
                           bv: bn.BinaryView = None):
        """
        Set up the context menu for the view.
        """
        
        def show_context_menu(pos: qtc.QPoint) -> None:
            # Get selected rows and expanded export rows
            rows = self.get_selected_rows()
            export_rows = self._get_expanded_export_rows(pos, rows)
            
            # Create context menu
            menu = qtw.QMenu(self)
            
            # Add menu actions with their enabled states and direct connections
            
            # Log actions
            log_path_action = self._add_menu_action(menu, "Log instructions", len(rows) == 1)
            log_path_action.triggered.connect(lambda: on_log_path(rows, False)) 
            log_path_reversed_action = self._add_menu_action(menu, "Log instructions (reversed)", len(rows) == 1)
            log_path_reversed_action.triggered.connect(lambda: on_log_path(rows, True))
            log_path_diff_action = self._add_menu_action(menu, "Log instruction difference", len(rows) == 2)
            log_path_diff_action.triggered.connect(lambda: on_log_path_diff(rows))
            
            menu.addSeparator()
            
            # Highlight and call graph actions
            has_single_row_and_bv = len(rows) == 1 and bv is not None
            highlight_path_action = self._add_menu_action(menu, "Un-/highlight instructions", has_single_row_and_bv)
            highlight_path_action.triggered.connect(lambda: on_highlight_path(rows))
            show_call_graph_action = self._add_menu_action(menu, "Show call graph", has_single_row_and_bv)
            show_call_graph_action.triggered.connect(lambda: on_show_call_graph(rows))
            
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
            export_paths_action = self._add_menu_action(menu, "Export to file", self._model.path_count > 0)
            export_paths_action.triggered.connect(lambda: on_export_paths(export_rows))
            
            menu.addSeparator()
            
            # Remove actions
            remove_selected_action = self._add_menu_action(menu, "Remove selected", len(rows) > 0)
            remove_selected_action.triggered.connect(lambda: on_remove_selected(rows))
            remove_all_action = self._add_menu_action(menu, "Remove all", self._model.path_count > 0)
            remove_all_action.triggered.connect(on_remove_all)

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
    
    def _add_menu_action(self, menu: qtw.QMenu, text: str, enabled: bool = True) -> qtw.QAction:
        """
        Helper method to add a menu action with enabled state.
        """
        action = menu.addAction(text)
        action.setEnabled(enabled)
        return action
    
    def _get_expanded_export_rows(self, pos: qtc.QPoint, selected_rows: List[int]) -> List[int]:
        """
        Get expanded list of rows for export, including all child paths if a header is clicked.
        """
        export_rows = selected_rows.copy()
        
        # Get the index at the clicked position
        clicked_idx = self.indexAt(pos)
        if not clicked_idx.isValid():
            return export_rows
            
        clicked_source_idx = self._proxy_model.mapToSource(clicked_idx)
        
        # Check if the clicked item is a group/header (not a path item)
        is_path_item = self._model.data(clicked_source_idx, IS_PATH_ITEM_ROLE)
        if is_path_item:
            return export_rows
        
        # Recursively gather all path IDs under this group/header
        child_paths = []
        self._collect_child_paths(clicked_source_idx, child_paths)
        
        # Include all child paths for export operations
        if child_paths:
            # Ensure we only include valid path IDs
            valid_child_paths = []
            for path_id in child_paths:
                if path_id is not None and 0 <= path_id < len(self._model.paths) and self._model.paths[path_id] is not None:
                    valid_child_paths.append(path_id)
            
            export_rows = sorted(set(export_rows + valid_child_paths))
            
        return export_rows
    
    def _collect_child_paths(self, parent_idx, path_list: List[int]):
        """
        Recursively collect all path IDs under a parent index.
        """
        for row in range(self._model.rowCount(parent_idx)):
            child_idx = self._model.index(row, 0, parent_idx)
            is_path_item = self._model.data(child_idx, IS_PATH_ITEM_ROLE)
            
            if is_path_item:
                path_id = self._model.get_path_id_from_index(child_idx)
                if path_id is not None and path_id not in path_list:
                    path_list.append(path_id)
            else:
                # This is a header item, so recurse into it
                self._collect_child_paths(child_idx, path_list)
    
    def setup_navigation(self, bv: bn.BinaryView = None):
        """
        Set up navigation for the view.
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
            source_index = self._proxy_model.mapToSource(index)
            
            # Check if this is a path item (not a group header)
            path_id = self._model.get_path_id_from_index(source_index)
            if path_id is None:
                return
                
            col = index.column()
            
            # Navigate based on column
            if col in [SRC_ADDR_COL, SRC_FUNC_COL]:
                # Get source address
                addr = self._model.data(
                    source_index, 
                    qtc.Qt.UserRole
                )
                if addr:
                    vf.navigate(bv, addr)
            elif col in [SNK_ADDR_COL, SNK_FUNC_COL, SNK_PARM_COL]:
                # Get sink address
                path = self.path_at_row(path_id)
                if path:
                    vf.navigate(bv, path.snk_sym_addr)
        
        # Disconnect existing navigation signals to prevent multiple connections
        if self._navigation_connected:
            self.doubleClicked.disconnect()
        
        # Connect the cell double-clicked signal and mark as connected
        self.doubleClicked.connect(navigate)
        self._navigation_connected = True
    
    def _handle_comment_edit(self, topLeft, bottomRight, roles):
        """
        Handle comment edits in the view and update the underlying model's path_comments dictionary.
        """
        # Only process if the data change includes the display role
        if qtc.Qt.DisplayRole not in roles and qtc.Qt.EditRole not in roles:
            return
            
        # Check if this edit spans the comment column
        if topLeft.column() <= COMMENT_COL <= bottomRight.column():
            # Process each row in the changed range
            for row in range(topLeft.row(), bottomRight.row() + 1):
                # Get the index for the comment column in the current row
                comment_idx = self._proxy_model.index(row, COMMENT_COL, topLeft.parent())
                
                # Map to source index and get the path ID
                source_idx = self._proxy_model.mapToSource(comment_idx)
                path_id = self._model.get_path_id_from_index(source_idx)
                
                # If this is a valid path item, update its comment in the model
                if path_id is not None:
                    new_comment = comment_idx.data(qtc.Qt.DisplayRole)
                    self._model.update_path_comment(path_id, new_comment)
