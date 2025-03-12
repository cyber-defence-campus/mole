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
    
    def add_path(self, path: Path, comment: str = ""):
        """
        Add a path to the view.
        """
        self._model.add_path(path, comment)
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
                           bv: bn.BinaryView = None,
                           tab_widget: qtw.QTabWidget = None):
        """
        Set up the context menu for the view.
        """
        
        def show_context_menu(pos: qtc.QPoint) -> None:
            rows = self.get_selected_rows()
            menu = qtw.QMenu(self)
            
            # Log instructions options
            menu_action_log_path = menu.addAction("Log instructions")
            menu_action_log_path_reversed = menu.addAction("Log instructions (reversed)")
            if len(rows) != 1:
                menu_action_log_path.setEnabled(False)
                menu_action_log_path_reversed.setEnabled(False)

            # Log difference option
            menu_action_log_path_diff = menu.addAction("Log instruction difference")
            if len(rows) != 2:
                menu_action_log_path_diff.setEnabled(False)
                
            menu.addSeparator()
            
            # Highlight and call graph options
            menu_action_highlight_path = menu.addAction("Un-/highlight instructions")
            menu_action_show_call_graph = menu.addAction("Show call graph")
            if len(rows) != 1 or not bv:
                menu_action_highlight_path.setEnabled(False)
                menu_action_show_call_graph.setEnabled(False)
                
            menu.addSeparator()
            
            # Tree-specific actions
            menu_action_expand_all = menu.addAction("Expand all")
            menu_action_collapse_all = menu.addAction("Collapse all")
                
            menu.addSeparator()
            
            # Import/export options
            menu_action_import_paths = menu.addAction("Import from file")
            menu_action_export_paths = menu.addAction("Export to file")
            if self._model.path_count <= 0:
                menu_action_export_paths.setEnabled(False)
                
            menu.addSeparator()
            
            # Remove options
            menu_action_remove_selected_path = menu.addAction("Remove selected")
            if len(rows) <= 0:
                menu_action_remove_selected_path.setEnabled(False)
            
            menu_action_remove_all_paths = menu.addAction("Remove all")
            if self._model.path_count <= 0:
                menu_action_remove_all_paths.setEnabled(False)

            # Execute menu and handle action
            menu_action = menu.exec(self.viewport().mapToGlobal(pos))
            if not menu_action:
                return
            
            if menu_action == menu_action_log_path:
                on_log_path(rows, False)
            elif menu_action == menu_action_log_path_reversed:
                on_log_path(rows, True)
            elif menu_action == menu_action_log_path_diff:
                on_log_path_diff(rows)
            elif menu_action == menu_action_highlight_path:
                on_highlight_path(rows)
            elif menu_action == menu_action_show_call_graph:
                on_show_call_graph(rows)
            elif menu_action == menu_action_expand_all:
                self.expandAll()
            elif menu_action == menu_action_collapse_all:
                self.collapseAll()
            elif menu_action == menu_action_import_paths:
                on_import_paths()
            elif menu_action == menu_action_export_paths:
                on_export_paths(rows)
            elif menu_action == menu_action_remove_selected_path:
                on_remove_selected(rows)
            elif menu_action == menu_action_remove_all:
                on_remove_all()
        
        # Store the function reference to enable future disconnections if needed
        self._context_menu_function = show_context_menu
        
        # Disconnect any existing connections to prevent multiple triggers
        if self._context_menu_connected:
            self.customContextMenuRequested.disconnect()
            
        # Connect the signal and mark as connected
        self.customContextMenuRequested.connect(show_context_menu)
        self._context_menu_connected = True
        
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
