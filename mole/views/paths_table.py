from __future__ import annotations
from typing import Callable, List, Optional
import binaryninja as bn
import binaryninjaui as bnui
import PySide6.QtCore as qtc
import PySide6.QtWidgets as qtw

from ..models.paths import PathsTableModel, PathsSortProxyModel
from ..core.data import Path


class PathsTableView(qtw.QTableView):
    """
    This class implements a view for displaying paths.
    """
    
    def __init__(self, parent=None):
        """
        Initialize the path table view.
        """
        super().__init__(parent)
        self._model = PathsTableModel()
        self._proxy_model = PathsSortProxyModel()
        self._proxy_model.setSourceModel(self._model)
        self.setModel(self._proxy_model)
        
        # Configure view properties
        self.setSelectionMode(qtw.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setSelectionBehavior(qtw.QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSortingEnabled(True)
        self.verticalHeader().setVisible(False)
        self.setContextMenuPolicy(qtc.Qt.ContextMenuPolicy.CustomContextMenu)
        self.horizontalHeader().setSectionResizeMode(qtw.QHeaderView.ResizeMode.Interactive)
        self.horizontalHeader().setStretchLastSection(True)
        
        # Ensure the columns are appropriately sized initially
        for col in range(self._model.columnCount()):
            self.resizeColumnToContents(col)
        
        # Track if signals are connected
        self._context_menu_connected = False
        self._navigation_connected = False
        self._context_menu_function = None
    
    @property
    def model(self) -> PathsTableModel:
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
    
    def get_selected_rows(self) -> List[int]:
        """
        Get the currently selected rows.
        """
        # Map proxy model indexes to source model rows
        return sorted(set(self._proxy_model.mapToSource(index).row() 
                         for index in self.selectionModel().selectedIndexes()))
    
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
            
            # Import/export options
            menu_action_import_paths = menu.addAction("Import from file")
            menu_action_export_paths = menu.addAction("Export to file")
            if self._model.rowCount() <= 0:
                menu_action_export_paths.setEnabled(False)
                
            menu.addSeparator()
            
            # Remove options
            menu_action_remove_selected_path = menu.addAction("Remove selected")
            if len(rows) <= 0:
                menu_action_remove_selected_path.setEnabled(False)
            
            menu_action_remove_all_paths = menu.addAction("Remove all")
            if self._model.rowCount() <= 0:
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
            elif menu_action == menu_action_import_paths:
                on_import_paths()
            elif menu_action == menu_action_export_paths:
                on_export_paths(rows)
            elif menu_action == menu_action_remove_selected_path:
                on_remove_selected(rows)
            elif menu_action == menu_action_remove_all_paths:
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
            row = source_index.row()
            col = source_index.column()
            
            # Navigate based on column
            if col in [PathsTableModel.SRC_ADDR_COL, PathsTableModel.SRC_FUNC_COL]:
                # Get source address
                addr = self._model.data(
                    self._model.index(row, PathsTableModel.SRC_ADDR_COL), 
                    qtc.Qt.UserRole
                )
                if addr:
                    vf.navigate(bv, addr)
            elif col in [PathsTableModel.SNK_ADDR_COL, PathsTableModel.SNK_FUNC_COL, PathsTableModel.SNK_PARM_COL]:
                # Get sink address
                addr = self._model.data(
                    self._model.index(row, PathsTableModel.SNK_ADDR_COL), 
                    qtc.Qt.UserRole
                )
                if addr:
                    vf.navigate(bv, addr)
        
        # Disconnect existing navigation signals to prevent multiple connections
        if self._navigation_connected:
            self.doubleClicked.disconnect()
        
        # Connect the cell double-clicked signal and mark as connected
        self.doubleClicked.connect(navigate)
        self._navigation_connected = True
