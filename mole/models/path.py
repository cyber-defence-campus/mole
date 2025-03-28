from __future__  import annotations
from ..core.data import Path
from ..grouping  import get_grouper
from typing      import Dict, List, Optional
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui


# Column definitions
PATH_COLS = {
    "Id": 0,
    "Src Addr": 1,
    "Src Func": 2,
    "Snk Addr": 3,
    "Snk Func": 4,
    "Snk Parm": 5,
    "Insts": 6,
    "Phis": 7,
    "Branches": 8,
    "Comment": 9,
}

# Custom roles for tree items
PATH_ID_ROLE = qtc.Qt.UserRole + 100
IS_PATH_ITEM_ROLE = qtc.Qt.UserRole + 101
LEVEL_ROLE = qtc.Qt.UserRole + 103  # Role to store the level of the item

# Only keep PATH_ITEM as it's needed to distinguish path items
PATH_ITEM = 4

class PathSortProxyModel(qtc.QSortFilterProxyModel):
    """
    This class implements a proxy model to handle proper sorting for paths. It uses
    `qtc.Qt.UserRole` data to maintain original data types during sorting.
    """
    
    def lessThan(
            self,
            left: qtc.QModelIndex | qtc.QPersistentModelIndex,
            right: qtc.QModelIndex | qtc.QPersistentModelIndex
        ) -> bool:
        """
        This method overrides the `lessThan` method to provide proper sorting based on data types.
        """
        # First check if these are header items (treat differently)
        left_is_path = self.sourceModel().data(left, IS_PATH_ITEM_ROLE)
        right_is_path = self.sourceModel().data(right, IS_PATH_ITEM_ROLE)
        
        # Header items should come before path items
        if left_is_path != right_is_path:
            return right_is_path
        
        # Get the values stored in UserRole for proper type comparison
        left_data = self.sourceModel().data(left, qtc.Qt.UserRole)
        right_data = self.sourceModel().data(right, qtc.Qt.UserRole)
        
        # If we have UserRole data available, use it for comparison
        if left_data is not None and right_data is not None:
            # Compare based on the actual types
            return left_data > right_data
        
        # Fall back to string comparison of display text
        left_text = self.sourceModel().data(left, qtc.Qt.DisplayRole)
        right_text = self.sourceModel().data(right, qtc.Qt.DisplayRole)
        
        # Try numeric comparison first if both are convertible to numbers
        try:
            left_num = float(left_text)
            right_num = float(right_text)
            return left_num > right_num
        except Exception as _:
            pass
        # Fall back to string comparison
        return str(left_text).lower() > str(right_text).lower()


class PathTreeModel(qtui.QStandardItemModel):
    """
    This class implements a tree model for displaying paths grouped by source and sink.
    """
    
    def __init__(self, parent=None) -> None:
        """
        This method initializes the path tree model.
        """
        super().__init__(parent)
        self.paths: List[Path] = []
        self.path_count = 0
        self.setHorizontalHeaderLabels(PATH_COLS.keys())
        # Store group items instead of specific source, sink, callgraph items
        # Each level of grouping can have its own items
        self.group_items: Dict[str, qtui.QStandardItem] = {}
        return
        
    def clear(self) -> None:
        """
        This method clears all data from the model.
        """
        self.paths.clear()
        self.group_items.clear()
        self.path_count = 0
        self.setRowCount(0)
        return
        
    def _create_non_path_item_row(self, text: str, level: int) -> List[qtui.QStandardItem]:
        """
        This method creates a row of items for non-path items (group headers).
        
        Args:
            text: The display text for the item
            level: The level in the hierarchy (used for display purposes)
        """
        # Styling
        font = qtui.QFont()
        font.setItalic(True)
        color = qtui.QBrush(qtui.QColor(255, 239, 213)) # Peach puff (light pastel orange)
        # Create main item
        main_item = qtui.QStandardItem(text)
        main_item.setFont(font)
        main_item.setForeground(color)
        main_item.setData(False, IS_PATH_ITEM_ROLE)
        main_item.setData(level, LEVEL_ROLE)  # Store level information
        main_item.setFlags(main_item.flags() & ~qtc.Qt.ItemIsEditable & ~qtc.Qt.ItemIsSelectable)
        
        # Return a single item - we'll use setFirstColumnSpanned in the view to make it span all columns
        return [main_item]
        
    def add_path(self, path: Path, path_grouping: str = None) -> None:
        """
        This method adds a path to the model grouped by strategy.
        
        Args:
            path: The path to add
            path_grouping: How to group paths - one of the PathGrouper strategies
        """
        self.paths.append(path)
        path_id = len(self.paths)-1

        # Get the appropriate grouper for this strategy
        grouper = get_grouper(path_grouping)
        if grouper is None:
            parent_item = self
            group_keys = []  # No grouping hierarchy
        else:            
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
        src_addr_item = qtui.QStandardItem(f"0x{path.src_sym_addr:x}")
        src_addr_item.setData(path.src_sym_addr, qtc.Qt.UserRole)
        src_addr_item.setData(True, IS_PATH_ITEM_ROLE)
        
        src_func_item = qtui.QStandardItem(path.src_sym_name)
        src_func_item.setData(True, IS_PATH_ITEM_ROLE)
        
        snk_addr_item = qtui.QStandardItem(f"0x{path.snk_sym_addr:x}")
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
        
        comment_item = qtui.QStandardItem(path.comment)
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
        return

    def remove_paths_at_rows(self, rows: List[int]) -> None:
        """
        This method removes paths at the specified row indices.
        """
        # Sort rows in descending order to avoid index shifting issues
        for row_id in sorted(rows, reverse=True):
            if 0 <= row_id < len(self.paths):
                # Mark this path as removed in the paths list
                self.paths[row_id] = None
                # Find and remove the path item from the tree
                self.find_path(row_id)
                self._remove_path_item_by_id(row_id)
                # Decrement the path count
                self.path_count -= 1
        # Clean up empty groups
        self._cleanup_empty_groups()
        return
    
    def _remove_path_item_by_id(self, path_id: int) -> bool:
        """
        This method finds and removes a path item by its ID. It returns `True` if found and removed,
        `False` otherwise.
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
        TODO:
        This method removes any group items that no longer have children.
        """
        # Process groups from the bottom level up
        group_keys = list(self.group_items.keys())
        keys_to_remove = []
        
        for key in reversed(group_keys):
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
        return
        
    def path_at_row(self, row: int) -> Optional[Path]:
        """
        This method returns the path at the specified path ID.
        """
        if 0 <= row < len(self.paths):
            return self.paths[row]
        return None
    
    def get_path_id_from_index(self, index: qtc.QModelIndex) -> Optional[int]:
        """
        This method returns the path ID from a model index, or `None` if it's not a path item.
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
    
    def update_path_comment(self, path_id: int, comment: str) -> None:
        """
        This method updates the comment of a given path.

        Args:
            path_id: The ID of the path to update
            comment: The new comment for the path
        """
        if 0 <= path_id < len(self.paths):
            self.paths[path_id].comment = comment
        return

    def regroup_paths(self, path_grouping: str = None) -> None:
        """
        This method regroups all paths using the specified grouping strategy.
        
        Args:
            path_grouping: The new grouping strategy to use
        """
        if self.path_count == 0:
            return  # Nothing to regroup
            
        # Store the existing paths and comments
        paths = [path for path in self.paths if path is not None]
        
        # Clear the model
        self.clear()
        
        # Re-add all paths with the new grouping strategy
        for idx, path in enumerate(paths):
            self.add_path(path, path_grouping)
        return