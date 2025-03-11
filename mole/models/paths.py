from __future__ import annotations
from typing import Dict, List, Optional
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

class PathsSortProxyModel(qtc.QSortFilterProxyModel):
    """
    This class implements a proxy model to handle proper numeric sorting for paths.
    """
    
    # Define columns that should be sorted numerically
    NUMERIC_COLUMNS = [INDEX_COL, INSTS_COL, PHIS_COL, BRANCHES_COL]
    HEX_COLUMNS = [SRC_ADDR_COL, SNK_ADDR_COL]
    
    def lessThan(self, left, right):
        """
        Override the lessThan method to provide proper numeric sorting.
        
        Qt models typically display all data as strings in views, which means
        numbers would be sorted lexicographically by default (e.g., "10" comes before "2").
        This method ensures proper numeric sorting by converting string representations
        back to their actual numeric values before comparing them.
        """
        column = left.column()
        
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


class PathsTableModel(qtui.QStandardItemModel):
    """
    This class implements a model for displaying paths in a table view.
    """

    COLUMNS = PATH_COLUMNS
    
    def __init__(self, parent=None):
        """
        Initialize the path table model.
        """
        super().__init__(parent)
        self.paths: List[Path] = []
        self.setHorizontalHeaderLabels(self.COLUMNS)
        
    def clear(self) -> None:
        """
        Clear all data from the model.
        """
        self.paths.clear()
        self.setRowCount(0)
        
    def add_path(self, path: Path, comment: str = "") -> None:
        """
        Add a path to the model.
        """
        self.paths.append(path)
        row = self.rowCount()
        
        # Create row items
        index_item = qtui.QStandardItem(str(row))
        
        # Only store hex values as UserRole data for proper sorting
        src_addr_item = qtui.QStandardItem(f"{path.src_sym_addr:x}")
        src_addr_item.setData(path.src_sym_addr, qtc.Qt.UserRole)
        
        src_func_item = qtui.QStandardItem(path.src_sym_name)
        
        snk_addr_item = qtui.QStandardItem(f"{path.snk_sym_addr:x}")
        snk_addr_item.setData(path.snk_sym_addr, qtc.Qt.UserRole)
        
        snk_func_item = qtui.QStandardItem(path.snk_sym_name)
        
        snk_parm_item = qtui.QStandardItem(f"arg#{path.snk_par_idx:d}:{str(path.snk_par_var):s}")
        
        insts_item = qtui.QStandardItem(str(len(path.insts)))
        phis_item = qtui.QStandardItem(str(len(path.phiis)))
        bdeps_item = qtui.QStandardItem(str(len(path.bdeps)))
        
        comment_item = qtui.QStandardItem(comment)

        # Set items as non-editable (except for comment)
        for item in [index_item, src_addr_item, src_func_item, snk_addr_item, 
                     snk_func_item, snk_parm_item, insts_item, phis_item, bdeps_item]:
            item.setFlags(item.flags() & ~qtc.Qt.ItemIsEditable)
            
        # Append row
        self.appendRow([
            index_item, src_addr_item, src_func_item, snk_addr_item,
            snk_func_item, snk_parm_item, insts_item, phis_item, bdeps_item, comment_item
        ])

    def remove_paths_at_rows(self, rows: List[int]) -> None:
        """
        Remove paths at the specified row indices.
        """
        # Sort rows in descending order to avoid index shifting issues
        for row in sorted(rows, reverse=True):
            if 0 <= row < self.rowCount():
                path_id = int(self.data(self.index(row, 0)))  # Use displayed text as ID
                # Remove path from internal list
                if 0 <= path_id < len(self.paths):
                    del self.paths[path_id]
                # Remove row from model
                self.removeRow(row)
        
        # Update indices
        for row in range(self.rowCount()):
            self.setItem(row, 0, qtui.QStandardItem(str(row)))
            self.item(row, 0).setFlags(self.item(row, 0).flags() & ~qtc.Qt.ItemIsEditable)
    
    def path_at_row(self, row: int) -> Optional[Path]:
        """
        Get the path at the specified row.
        """
        if 0 <= row < self.rowCount():
            try:
                path_id = int(self.data(self.index(row, 0)))  # Use displayed text as ID
                if 0 <= path_id < len(self.paths):
                    return self.paths[path_id]
            except (ValueError, TypeError):
                pass
        return None
    
    def get_comments(self) -> Dict[int, str]:
        """
        Get all comments from the model.
        """
        comments = {}
        for row in range(self.rowCount()):
            try:
                path_id = int(self.data(self.index(row, 0)))  # Use displayed text as ID
                comment = self.data(self.index(row, COMMENT_COL))
                comments[path_id] = comment if comment else ""
            except (ValueError, TypeError):
                pass
        return comments
