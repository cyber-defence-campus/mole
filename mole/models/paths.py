from __future__ import annotations
from typing import Dict, List, Optional, Any, Tuple
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui

from ..core.data import Path

# Column definitions
PATH_COLUMNS = ["Id", "Src Addr", "Src Func", "Snk Addr", "Snk Func", "Snk Parm", "Insts", "Phis", "Branches", "Comment"]

# Column indices
INDEX_COL = 0
SRC_ADDR_COL = 1
SRC_FUNC_COL = 2
SNK_ADDR_COL = 3
SNK_FUNC_COL = 4
SNK_PARM_COL = 5
INSTS_COL = 6
PHIS_COL = 7
BRANCHES_COL = 8
COMMENT_COL = 9

# Custom roles for tree items
PATH_ID_ROLE = qtc.Qt.UserRole + 100
IS_PATH_ITEM_ROLE = qtc.Qt.UserRole + 101

class PathsSortProxyModel(qtc.QSortFilterProxyModel):
    """
    This class implements a proxy model to handle proper numeric sorting for paths.
    """
    
    # Define columns that should be sorted numerically
    NUMERIC_COLUMNS = [INDEX_COL, INSTS_COL, PHIS_COL, BRANCHES_COL]
    HEX_COLUMNS = [SRC_ADDR_COL, SNK_ADDR_COL]
    
    def lessThan(self, left, right):
        """
        Override the lessThan method to provide proper sorting.
        """
        column = left.column()
        
        # First check if these are header items (treat differently)
        left_is_path = self.sourceModel().data(left, IS_PATH_ITEM_ROLE)
        right_is_path = self.sourceModel().data(right, IS_PATH_ITEM_ROLE)
        
        # Header items should come before path items
        if left_is_path != right_is_path:
            return right_is_path
            
        # Only use UserRole data for hex columns
        if column in self.HEX_COLUMNS:
            left_data = self.sourceModel().data(left, qtc.Qt.UserRole)
            right_data = self.sourceModel().data(right, qtc.Qt.UserRole)
            if left_data is not None and right_data is not None:
                try:
                    return int(left_data) < int(right_data)
                except (ValueError, TypeError):
                    pass
        # For numeric columns, convert display text to int
        elif column in self.NUMERIC_COLUMNS:
            try:
                left_value = int(self.sourceModel().data(left))
                right_value = int(self.sourceModel().data(right))
                return left_value < right_value
            except (ValueError, TypeError):
                pass
                    
        # Fall back to string comparison for non-numeric data
        return super().lessThan(left, right)


class PathsTreeModel(qtui.QStandardItemModel):
    """
    This class implements a tree model for displaying paths grouped by source and sink.
    """

    COLUMNS = PATH_COLUMNS
    
    def __init__(self, parent=None):
        """
        Initialize the path tree model.
        """
        super().__init__(parent)
        self.paths: List[Path] = []
        self.path_comments: Dict[int, str] = {}
        self.path_count = 0
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self.source_items: Dict[str, qtui.QStandardItem] = {}
        self.sink_items: Dict[Tuple[str, str], qtui.QStandardItem] = {}
        
    def clear(self) -> None:
        """
        Clear all data from the model.
        """
        self.paths.clear()
        self.path_comments.clear()
        self.source_items.clear()
        self.sink_items.clear()
        self.path_count = 0
        self.setRowCount(0)
        
    def add_path(self, path: Path, comment: str = "") -> None:
        """
        Add a path to the model grouped by source and sink.
        """
        self.paths.append(path)
        path_id = len(self.paths) - 1
        self.path_comments[path_id] = comment
        
        # Get or create source function group
        source_name = path.src_sym_name
        if source_name not in self.source_items:
            # Create source function group item
            source_item = qtui.QStandardItem(f"Source: {source_name}")
            source_item.setData(False, IS_PATH_ITEM_ROLE)
            
            # Create empty items for other columns
            source_row = [source_item]
            for _ in range(1, len(self.COLUMNS)):
                col_item = qtui.QStandardItem("")
                col_item.setData(False, IS_PATH_ITEM_ROLE)
                col_item.setFlags(col_item.flags() & ~qtc.Qt.ItemIsEditable)
                source_row.append(col_item)
                
            # Add the row to the root
            self.appendRow(source_row)
            self.source_items[source_name] = source_item
            
            # Set source item as non-editable
            source_item.setFlags(source_item.flags() & ~qtc.Qt.ItemIsEditable)
        
        # Get source item
        source_item = self.source_items[source_name]
        
        # Get or create sink function group under this source
        sink_name = path.snk_sym_name
        sink_key = (source_name, sink_name)
        if sink_key not in self.sink_items:
            # Create sink function group item
            sink_item = qtui.QStandardItem(f"Sink: {sink_name}")
            sink_item.setData(False, IS_PATH_ITEM_ROLE)
            sink_item.setFlags(sink_item.flags() & ~qtc.Qt.ItemIsEditable)
            
            # Create empty items for other columns
            sink_row = [sink_item]
            for _ in range(1, len(self.COLUMNS)):
                col_item = qtui.QStandardItem("")
                col_item.setData(False, IS_PATH_ITEM_ROLE)
                col_item.setFlags(col_item.flags() & ~qtc.Qt.ItemIsEditable)
                sink_row.append(col_item)
                
            # Add the row to the source item
            source_item.appendRow(sink_row)
            self.sink_items[sink_key] = sink_item
        
        # Get sink item
        sink_item = self.sink_items[sink_key]
        
        # Create path items
        index_item = qtui.QStandardItem(str(path_id))
        index_item.setData(path_id, PATH_ID_ROLE)
        index_item.setData(True, IS_PATH_ITEM_ROLE)
        
        # Only store hex values as UserRole data for proper sorting
        src_addr_item = qtui.QStandardItem(f"{path.src_sym_addr:x}")
        src_addr_item.setData(path.src_sym_addr, qtc.Qt.UserRole)
        src_addr_item.setData(True, IS_PATH_ITEM_ROLE)
        
        src_func_item = qtui.QStandardItem(path.src_sym_name)
        src_func_item.setData(True, IS_PATH_ITEM_ROLE)
        
        snk_addr_item = qtui.QStandardItem(f"{path.snk_sym_addr:x}")
        snk_addr_item.setData(path.snk_sym_addr, qtc.Qt.UserRole)
        snk_addr_item.setData(True, IS_PATH_ITEM_ROLE)
        
        snk_func_item = qtui.QStandardItem(path.snk_sym_name)
        snk_func_item.setData(True, IS_PATH_ITEM_ROLE)
        
        snk_parm_item = qtui.QStandardItem(f"arg#{path.snk_par_idx:d}:{str(path.snk_par_var):s}")
        snk_parm_item.setData(True, IS_PATH_ITEM_ROLE)
        
        insts_item = qtui.QStandardItem(str(len(path.insts)))
        insts_item.setData(True, IS_PATH_ITEM_ROLE)
        
        phis_item = qtui.QStandardItem(str(len(path.phiis)))
        phis_item.setData(True, IS_PATH_ITEM_ROLE)
        
        bdeps_item = qtui.QStandardItem(str(len(path.bdeps)))
        bdeps_item.setData(True, IS_PATH_ITEM_ROLE)
        
        comment_item = qtui.QStandardItem(comment)
        comment_item.setData(True, IS_PATH_ITEM_ROLE)

        # Set items as non-editable (except for comment)
        for item in [index_item, src_addr_item, src_func_item, snk_addr_item, 
                     snk_func_item, snk_parm_item, insts_item, phis_item, bdeps_item]:
            item.setFlags(item.flags() & ~qtc.Qt.ItemIsEditable)
            
        # Create path row and append to sink item
        path_row = [
            index_item, src_addr_item, src_func_item, snk_addr_item,
            snk_func_item, snk_parm_item, insts_item, phis_item, bdeps_item, comment_item
        ]
        sink_item.appendRow(path_row)
        
        self.path_count += 1

    def remove_paths_at_rows(self, rows: List[int]) -> None:
        """
        Remove paths at the specified row indices.
        """
        # Sort rows in descending order to avoid index shifting issues
        for row_id in sorted(rows, reverse=True):
            if 0 <= row_id < len(self.paths):
                # Get the path's info to identify its position in the tree
                path = self.paths[row_id]
                source_name = path.src_sym_name
                sink_name = path.snk_sym_name
                sink_key = (source_name, sink_name)
                
                # Remove path from internal lists
                self.paths[row_id] = None  # Mark as removed
                self.path_comments.pop(row_id, None)
                
                # Find and remove the path item from the tree
                if source_name in self.source_items and sink_key in self.sink_items:
                    source_item = self.source_items[source_name]
                    sink_item = self.sink_items[sink_key]
                    
                    # Find the item with matching path_id among sink item's children
                    for i in range(sink_item.rowCount()):
                        child = sink_item.child(i, 0)
                        if child and child.data(PATH_ID_ROLE) == row_id:
                            sink_item.removeRow(i)
                            self.path_count -= 1
                            break
                    
                    # If sink has no more paths, remove it
                    if sink_item.rowCount() == 0:
                        source_item.removeRow(sink_item.row())
                        self.sink_items.pop(sink_key, None)
                    
                    # If source has no more sinks, remove it
                    if source_item.rowCount() == 0:
                        self.removeRow(source_item.row())
                        self.source_items.pop(source_name, None)
        
    def path_at_row(self, row: int) -> Optional[Path]:
        """
        Get the path at the specified path ID.
        """
        if 0 <= row < len(self.paths):
            return self.paths[row]
        return None
    
    def get_comments(self) -> Dict[int, str]:
        """
        Get all comments from the model.
        """
        # Update comments from UI
        for source_name, source_item in self.source_items.items():
            for i in range(source_item.rowCount()):
                sink_item = source_item.child(i, 0)
                if not sink_item:
                    continue
                    
                for j in range(sink_item.rowCount()):
                    path_item = sink_item.child(j, 0)
                    if not path_item:
                        continue
                        
                    path_id = path_item.data(PATH_ID_ROLE)
                    if path_id is not None:
                        comment_item = sink_item.child(j, COMMENT_COL)
                        if comment_item:
                            self.path_comments[path_id] = comment_item.text()
                            
        return self.path_comments
    
    def get_path_id_from_index(self, index: qtc.QModelIndex) -> Optional[int]:
        """
        Get the path ID from a model index, or None if it's not a path item.
        """
        if not index.isValid():
            return None
            
        # Check if this is a path item
        if not index.data(IS_PATH_ITEM_ROLE):
            return None
            
        # Get the first column item which contains the path ID
        if index.column() != 0:
            index = index.sibling(index.row(), 0)
            
        # If we're dealing with a top-level item or second-level item, it's not a path
        if not index.parent().isValid() or not index.parent().parent().isValid():
            return None
            
        # Return the path ID
        return index.data(PATH_ID_ROLE)
    
    # Keep legacy PathsTableModel interface to maintain compatibility with existing code
PathsTableModel = PathsTreeModel
