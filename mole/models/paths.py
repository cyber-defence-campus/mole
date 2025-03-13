from __future__ import annotations
from typing import Dict, List, Optional
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui

from ..core.data import Path
from ..core.grouping import PathGrouper

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
LEVEL_ROLE = qtc.Qt.UserRole + 103  # Role to store the level of the item

# Only keep PATH_ITEM as it's needed to distinguish path items
PATH_ITEM = 4

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
        # Store group items instead of specific source, sink, callgraph items
        # Each level of grouping can have its own items
        self.group_items: Dict[str, qtui.QStandardItem] = {}
        
    def clear(self) -> None:
        """
        Clear all data from the model.
        """
        self.paths.clear()
        self.path_comments.clear()
        self.group_items.clear()
        self.path_count = 0
        self.setRowCount(0)
        
    def _create_non_path_item_row(self, text: str, level: int) -> List[qtui.QStandardItem]:
        """
        Create a row of items for non-path items (group headers).
        
        Args:
            text: The display text for the item
            level: The level in the hierarchy (used for display purposes)
        """
        # Create main item
        main_item = qtui.QStandardItem(text)
        main_item.setData(False, IS_PATH_ITEM_ROLE)
        main_item.setData(level, LEVEL_ROLE)  # Store level information
        main_item.setFlags(main_item.flags() & ~qtc.Qt.ItemIsEditable)
        
        # Return a single item - we'll use setFirstColumnSpanned in the view to make it span all columns
        return [main_item]
        
    def add_path(self, path: Path, comment: str = "", grouping_strategy: str = PathGrouper.CALLGRAPH) -> None:
        """
        Add a path to the model grouped by strategy.
        
        Args:
            path: The path to add
            comment: Comment for the path
            grouping_strategy: How to group paths - one of the PathGrouper strategies (e.g., PathGrouper.NONE, PathGrouper.CALLGRAPH)
        """
        self.paths.append(path)
        path_id = len(self.paths) - 1
        self.path_comments[path_id] = comment
        
        # Get the appropriate grouper for this strategy
        grouper = PathGrouper.create(grouping_strategy)
        
        # Get the hierarchy of group keys for this path
        group_keys = grouper.get_group_keys(path)
        
        # Track the parent item as we create or find each group level
        parent_item = self
        
        # Create or get group items for each level of the hierarchy
        for display_name, internal_id, level in group_keys:
            if internal_id not in self.group_items:
                # Create and add the group item with level information
                group_row = self._create_non_path_item_row(display_name, level)
                
                if isinstance(parent_item, qtui.QStandardItemModel):
                    parent_item.appendRow(group_row)
                else:
                    parent_item.appendRow(group_row)
                    
                self.group_items[internal_id] = group_row[0]
            
            # Update parent for next iteration
            parent_item = self.group_items[internal_id]
        
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
            
        # Create path row and append to parent item (lowest level group)
        path_row = [
            index_item, src_addr_item, src_func_item, snk_addr_item,
            snk_func_item, snk_parm_item, insts_item, phis_item, bdeps_item, comment_item
        ]
        parent_item.appendRow(path_row)
        
        self.path_count += 1
        
        # Emit a dataChanged signal to ensure the view updates properly
        self.dataChanged.emit(qtc.QModelIndex(), qtc.QModelIndex())

    def remove_paths_at_rows(self, rows: List[int]) -> None:
        """
        Remove paths at the specified row indices.
        """
        # Sort rows in descending order to avoid index shifting issues
        for row_id in sorted(rows, reverse=True):
            if 0 <= row_id < len(self.paths):
                # Mark this path as removed in the paths list
                self.paths[row_id] = None
                self.path_comments.pop(row_id, None)
                
                # Find and remove the path item from the tree
                self._remove_path_item_by_id(row_id)
                
                # Decrement the path count
                self.path_count -= 1
                
        # Clean up empty groups
        self._cleanup_empty_groups()
    
    def _remove_path_item_by_id(self, path_id: int) -> bool:
        """
        Find and remove a path item by its ID.
        Returns True if found and removed, False otherwise.
        """
        # Search through all items recursively
        def find_and_remove_path(parent_item):
            # Check in the standard item model
            if isinstance(parent_item, qtui.QStandardItemModel):
                for row in range(parent_item.rowCount()):
                    item = parent_item.item(row, 0)
                    if find_and_remove_path(item):
                        return True
            else:
                # Check this item's children
                for row in range(parent_item.rowCount()):
                    child = parent_item.child(row, 0)
                    if child is not None:
                        # Check if this is the path item we're looking for
                        if child.data(IS_PATH_ITEM_ROLE) and child.data(PATH_ID_ROLE) == path_id:
                            parent_item.removeRow(row)
                            return True
                        # Or search its children
                        if find_and_remove_path(child):
                            return True
            return False
        
        return find_and_remove_path(self)
    
    def _cleanup_empty_groups(self) -> None:
        """
        Remove any group items that no longer have children.
        """
        # Process groups from the bottom level up
        group_keys = list(self.group_items.keys())
        keys_to_remove = []
        
        for key in group_keys:
            group_item = self.group_items[key]
            if group_item.rowCount() == 0:
                # Remove this empty group
                if group_item.parent():
                    group_item.parent().removeRow(group_item.row())
                else:
                    self.removeRow(group_item.row())
                keys_to_remove.append(key)
        
        # Remove deleted groups from the dictionary
        for key in keys_to_remove:
            self.group_items.pop(key, None)
        
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
        # Find all path items in the tree and update comments dictionary
        def update_comments(parent_item, column):
            if isinstance(parent_item, qtui.QStandardItemModel):
                for row in range(parent_item.rowCount()):
                    for col in range(parent_item.columnCount()):
                        item = parent_item.item(row, col)
                        update_comments(item, col)
            else:
                # Check if this is a path item
                if parent_item and parent_item.data(IS_PATH_ITEM_ROLE):
                    if column == COMMENT_COL:
                        # Find the index item in the same row
                        index_item = parent_item.model().item(parent_item.row(), 0, parent_item.parent())
                        if index_item:
                            path_id = index_item.data(PATH_ID_ROLE)
                            if path_id is not None:
                                self.path_comments[path_id] = parent_item.text()
                
                # Process children
                if parent_item:
                    for row in range(parent_item.rowCount()):
                        for col in range(parent_item.model().columnCount()):
                            child = parent_item.child(row, col)
                            if child:
                                update_comments(child, col)
        
        update_comments(self, 0)
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
            
        # Return the path ID
        return index.data(PATH_ID_ROLE)

# Keep legacy PathsTableModel interface to maintain compatibility with existing code
PathsTableModel = PathsTreeModel
