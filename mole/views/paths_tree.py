from __future__ import annotations
from typing import Callable, List, Optional
import binaryninja as bn
import binaryninjaui as bnui
import PySide6.QtCore as qtc
import PySide6.QtWidgets as qtw

from ..models.paths import (
    PathsTreeModel, PathsSortProxyModel,
    SRC_ADDR_COL, SRC_FUNC_COL, SNK_ADDR_COL, SNK_FUNC_COL, SNK_PARM_COL,
    ITEM_TYPE_ROLE, SOURCE_ITEM, SINK_ITEM, CALLGRAPH_ITEM, PATH_ITEM
)
from ..core.data import Path, ComboboxSetting


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
        
        # Connect to model signals to handle column spanning
        self._model.rowsInserted.connect(self._handle_rows_inserted)
        # Also connect to the proxy model's row inserted signal
        self._proxy_model.rowsInserted.connect(self._handle_proxy_rows_inserted)
    
    def _handle_proxy_rows_inserted(self, parent, first, last):
        """
        Handle proxy model rows inserted signal to map to source model and apply spanning.
        """
        # Map proxy index to source index
        source_parent = self._proxy_model.mapToSource(parent)
        for row in range(first, last + 1):
            proxy_index = self._proxy_model.index(row, 0, parent)
            source_index = self._proxy_model.mapToSource(proxy_index)
            item_type = source_index.data(ITEM_TYPE_ROLE)
            
            # Set all header items to span all columns
            if item_type in [SOURCE_ITEM, SINK_ITEM, CALLGRAPH_ITEM]:
                self.setFirstColumnSpanned(row, parent, True)
                # Process children immediately
                self._process_children_spanning(source_index, proxy_index)
    
    def _process_children_spanning(self, source_index, proxy_index):
        """
        Process children of an item to ensure they have proper column spanning.
        """
        for row in range(self._model.rowCount(source_index)):
            child_source_index = self._model.index(row, 0, source_index)
            child_type = self._model.data(child_source_index, ITEM_TYPE_ROLE)
            
            if child_type in [SOURCE_ITEM, SINK_ITEM, CALLGRAPH_ITEM]:
                # Map source index back to proxy index for setFirstColumnSpanned
                child_proxy_row = -1
                for i in range(self._proxy_model.rowCount(proxy_index)):
                    test_proxy_index = self._proxy_model.index(i, 0, proxy_index)
                    test_source_index = self._proxy_model.mapToSource(test_proxy_index)
                    if test_source_index.row() == child_source_index.row() and test_source_index.parent() == child_source_index.parent():
                        child_proxy_row = i
                        break
                
                if child_proxy_row >= 0:
                    self.setFirstColumnSpanned(child_proxy_row, proxy_index, True)
                    # Recursively process this child's children
                    child_proxy_index = self._proxy_model.index(child_proxy_row, 0, proxy_index)
                    self._process_children_spanning(child_source_index, child_proxy_index)
    
    def _handle_rows_inserted(self, parent, first, last):
        """
        Handle rows inserted signal to set column spanning for header items.
        """
        # Process the direct items
        for row in range(first, last + 1):
            source_index = self._model.index(row, 0, parent)
            item_type = self._model.data(source_index, ITEM_TYPE_ROLE)
            
            # Set all header items to span all columns in both model and view
            if item_type in [SOURCE_ITEM, SINK_ITEM, CALLGRAPH_ITEM]:
                # For the source model rows, we need to map them to proxy rows
                proxy_parent = self._proxy_model.mapFromSource(parent)
                
                # Find the corresponding row in the proxy model
                proxy_row = -1
                for i in range(self._proxy_model.rowCount(proxy_parent)):
                    proxy_index = self._proxy_model.index(i, 0, proxy_parent)
                    source_idx = self._proxy_model.mapToSource(proxy_index)
                    if source_idx.row() == row and source_idx.parent() == parent:
                        proxy_row = i
                        break
                
                if proxy_row >= 0:
                    # Apply spanning in the view
                    self.setFirstColumnSpanned(proxy_row, proxy_parent, True)
    
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
            item_type = self._model.data(source_index, ITEM_TYPE_ROLE)
            
            if item_type in [SOURCE_ITEM, SINK_ITEM, CALLGRAPH_ITEM]:
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
    
    def add_path(self, path: Path, comment: str = "", grouping_strategy: str = "Callgraph"):
        """
        Add a path to the view.
        
        Args:
            path: The path to add
            comment: Comment for the path
            grouping_strategy: How to group paths - 'None' or 'Callgraph'
        """
        self._model.add_path(path, comment, grouping_strategy)
        # Resize columns to fit content
        for col in range(self._model.columnCount()):
            self.resizeColumnToContents(col)
        # Expand the parent nodes for better visibility
        self.expandAll()
        
        # Make sure all header items span all columns
        self._handle_spanning_for_all_items()
    
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
            
            # Add menu actions with their enabled states
            actions = {}
            
            # Log actions
            actions["log_path"] = self._add_menu_action(menu, "Log instructions", len(rows) == 1)
            actions["log_path_reversed"] = self._add_menu_action(menu, "Log instructions (reversed)", len(rows) == 1)
            actions["log_path_diff"] = self._add_menu_action(menu, "Log instruction difference", len(rows) == 2)
            menu.addSeparator()
            
            # Highlight and call graph actions
            has_single_row_and_bv = len(rows) == 1 and bv is not None
            actions["highlight_path"] = self._add_menu_action(menu, "Un-/highlight instructions", has_single_row_and_bv)
            actions["show_call_graph"] = self._add_menu_action(menu, "Show call graph", has_single_row_and_bv)
            menu.addSeparator()
            
            # Tree-specific actions
            actions["expand_all"] = menu.addAction("Expand all")
            actions["collapse_all"] = menu.addAction("Collapse all")
            menu.addSeparator()
            
            # Import/export actions
            actions["import_paths"] = menu.addAction("Import from file")
            actions["export_paths"] = self._add_menu_action(menu, "Export to file", self._model.path_count > 0)
            menu.addSeparator()
            
            # Remove actions
            actions["remove_selected"] = self._add_menu_action(menu, "Remove selected", len(rows) > 0)
            actions["remove_all"] = self._add_menu_action(menu, "Remove all", self._model.path_count > 0)

            # Execute menu and handle selected action
            selected_action = menu.exec(self.viewport().mapToGlobal(pos))
            if not selected_action:
                return
            
            # Handle the selected action
            if selected_action == actions.get("log_path"):
                on_log_path(rows, False)
            elif selected_action == actions.get("log_path_reversed"):
                on_log_path(rows, True)
            elif selected_action == actions.get("log_path_diff"):
                on_log_path_diff(rows)
            elif selected_action == actions.get("highlight_path"):
                on_highlight_path(rows)
            elif selected_action == actions.get("show_call_graph"):
                on_show_call_graph(rows)
            elif selected_action == actions.get("expand_all"):
                self.expandAll()
            elif selected_action == actions.get("collapse_all"):
                self.collapseAll()
            elif selected_action == actions.get("import_paths"):
                on_import_paths()
            elif selected_action == actions.get("export_paths"):
                on_export_paths(export_rows)
            elif selected_action == actions.get("remove_selected"):
                on_remove_selected(rows)
            elif selected_action == actions.get("remove_all"):
                on_remove_all()
        
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
        
        # Check if the clicked item is a group/header
        item_type = self._model.data(clicked_source_idx, ITEM_TYPE_ROLE)
        if item_type not in [SOURCE_ITEM, SINK_ITEM, CALLGRAPH_ITEM]:
            return export_rows
        
        # Recursively gather all path IDs under this group/header
        child_paths = []
        self._collect_child_paths(clicked_source_idx, child_paths)
        
        # Include all child paths for export operations
        if child_paths:
            export_rows = sorted(set(export_rows + child_paths))
            
        return export_rows
    
    def _collect_child_paths(self, parent_idx, path_list: List[int]):
        """
        Recursively collect all path IDs under a parent index.
        """
        for row in range(self._model.rowCount(parent_idx)):
            child_idx = self._model.index(row, 0, parent_idx)
            child_type = self._model.data(child_idx, ITEM_TYPE_ROLE)
            
            if child_type == PATH_ITEM:
                path_id = self._model.get_path_id_from_index(child_idx)
                if path_id is not None and path_id not in path_list:
                    path_list.append(path_id)
            elif child_type in [SOURCE_ITEM, SINK_ITEM, CALLGRAPH_ITEM]:
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


# For backward compatibility
PathsTableView = PathsTreeView
