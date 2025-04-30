from __future__ import annotations
from mole.core.data import Path
from mole.grouping import get_grouper
from typing import Dict, List, Optional, Tuple
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui


# Column definitions
PATH_COLS = {
    "Id": 0,
    "Src Addr": 1,
    "Src Func": 2,
    "Src Parm": 3,
    "Snk Addr": 4,
    "Snk Func": 5,
    "Snk Parm": 6,
    "Insts": 7,
    "Phis": 8,
    "Branches": 9,
    "Comment": 10,
}

# Custom roles for tree items
PATH_ID_ROLE = qtc.Qt.UserRole + 100
IS_PATH_ITEM_ROLE = qtc.Qt.UserRole + 101
LEVEL_ROLE = qtc.Qt.UserRole + 102  # Role to store the level of the item

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
        right: qtc.QModelIndex | qtc.QPersistentModelIndex,
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
        self.path_id = 0
        self.path_map: Dict[int, Path] = {}
        self.setHorizontalHeaderLabels(PATH_COLS.keys())
        # Store group items instead of specific source, sink, callgraph items
        # Each level of grouping can have its own items
        self.group_items: Dict[str, qtui.QStandardItem] = {}
        return

    def _create_non_path_item_row(self, text: str, level: int) -> qtui.QStandardItem:
        """
        This method creates a row of items for non-path items (group headers).

        Args:
            text: The display text for the item
            level: The level in the hierarchy (used for display purposes)
        """
        # Styling
        font = qtui.QFont()
        font.setItalic(True)
        color = qtui.QBrush(
            qtui.QColor(255, 239, 213)
        )  # Peach puff (light pastel orange)
        # Create main item
        main_item = qtui.QStandardItem(text)
        main_item.setFont(font)
        main_item.setForeground(color)
        main_item.setData(False, IS_PATH_ITEM_ROLE)
        main_item.setData(level, LEVEL_ROLE)  # Store level information
        main_item.setFlags(
            main_item.flags() & ~qtc.Qt.ItemIsEditable & ~qtc.Qt.ItemIsSelectable
        )
        # Return a single item - we'll use setFirstColumnSpanned in the view to make it span all columns
        return main_item

    def add_path(self, path: Path, path_grouping: str = None) -> None:
        """
        This method adds a path to the model grouped by the specified strategy.

        Args:
            path: The path to add
            path_grouping: How to group paths - one of the PathGrouper strategies
        """
        self.path_id += 1
        self.path_map[self.path_id] = path

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
                self.group_items[internal_id] = group_row

            # Update parent for next iteration
            parent_item = self.group_items[internal_id]

        # Create path items
        id_item = qtui.QStandardItem(f"{self.path_id:d}")
        id_item.setData(self.path_id, PATH_ID_ROLE)
        id_item.setData(True, IS_PATH_ITEM_ROLE)

        # Only store hex values as UserRole data for proper sorting
        src_addr_item = qtui.QStandardItem(f"0x{path.src_sym_addr:x}")
        src_addr_item.setData(path.src_sym_addr, qtc.Qt.UserRole)
        src_addr_item.setData(True, IS_PATH_ITEM_ROLE)

        src_func_item = qtui.QStandardItem(path.src_sym_name)
        src_func_item.setData(True, IS_PATH_ITEM_ROLE)

        if path.src_par_idx and path.src_par_var:
            src_parm_label = f"arg#{path.src_par_idx:d}:{str(path.src_par_var):s}"
        else:
            src_parm_label = ""
        src_parm_item = qtui.QStandardItem(src_parm_label)
        src_parm_item.setData(True, IS_PATH_ITEM_ROLE)

        snk_addr_item = qtui.QStandardItem(f"0x{path.snk_sym_addr:x}")
        snk_addr_item.setData(path.snk_sym_addr, qtc.Qt.UserRole)
        snk_addr_item.setData(True, IS_PATH_ITEM_ROLE)

        snk_func_item = qtui.QStandardItem(path.snk_sym_name)
        snk_func_item.setData(True, IS_PATH_ITEM_ROLE)

        snk_parm_item = qtui.QStandardItem(
            f"arg#{path.snk_par_idx:d}:{str(path.snk_par_var):s}"
        )
        snk_parm_item.setData(True, IS_PATH_ITEM_ROLE)

        inst_item = qtui.QStandardItem(str(len(path.insts)))
        inst_item.setData(True, IS_PATH_ITEM_ROLE)

        phis_item = qtui.QStandardItem(str(len(path.phiis)))
        phis_item.setData(True, IS_PATH_ITEM_ROLE)

        bdeps_item = qtui.QStandardItem(str(len(path.bdeps)))
        bdeps_item.setData(True, IS_PATH_ITEM_ROLE)

        comment_item = qtui.QStandardItem(path.comment)
        comment_item.setData(True, IS_PATH_ITEM_ROLE)

        # Set items as non-editable (except for comment)
        for item in [
            id_item,
            src_addr_item,
            src_func_item,
            src_parm_item,
            snk_addr_item,
            snk_func_item,
            snk_parm_item,
            inst_item,
            phis_item,
            bdeps_item,
        ]:
            item.setFlags(item.flags() & ~qtc.Qt.ItemIsEditable)

        # Create path row and append to parent item (lowest level group)
        path_row = [
            id_item,
            src_addr_item,
            src_func_item,
            src_parm_item,
            snk_addr_item,
            snk_func_item,
            snk_parm_item,
            inst_item,
            phis_item,
            bdeps_item,
            comment_item,
        ]
        parent_item.appendRow(path_row)

        # Emit a dataChanged signal to ensure the view updates properly
        self.dataChanged.emit(qtc.QModelIndex(), qtc.QModelIndex())
        return

    def clear(self) -> int:
        """
        This method clears all data from the model.
        """
        path_cnt = len(self.path_map)
        self.path_id = 0
        self.setRowCount(0)
        self.path_map.clear()
        self.group_items.clear()
        return path_cnt

    def find_path_item(
        self, path_id
    ) -> Tuple[Optional[qtui.QStandardItem], Optional[qtui.QStandardItem], int]:
        """
        This method tries to find the path item matching the given path ID.

        Args:
            path_id    : ID of the path that should be found

        Returns:
            parent_item: The parent item or `None` if the parent does not exist
            child_item : The child item or `None` if it has not been found
            child_row  : The child's row index relative to its parent item
        """

        def _find_path(
            item: qtui.QStandardItem,
        ) -> Tuple[Optional[qtui.QStandardItem], Optional[qtui.QStandardItem], int]:
            # If the item is a path, check whether the `path_id` matches
            if item.data(IS_PATH_ITEM_ROLE):
                if item.data(PATH_ID_ROLE) == path_id:
                    return (None, item, -1)
            # If the item is not a path, try finding in its children
            else:
                for row in range(item.rowCount()):
                    parent_item, child_item, child_row = _find_path(item.child(row, 0))
                    if child_item is not None:
                        if parent_item is None:
                            parent_item = item
                            child_row = row
                        return (parent_item, child_item, child_row)
            return (None, None, -1)

        # Iterate all top-level items
        for row in range(self.rowCount()):
            parent_item, child_item, child_row = _find_path(self.item(row, 0))
            if child_item is not None:
                if parent_item is None:
                    child_row = row
                return (parent_item, child_item, child_row)
        return (None, None, -1)

    def remove_selected_paths(self, path_ids: List[int]) -> int:
        """
        This method removes selected paths.
        """
        # Remove paths
        cnt_removed_paths = 0
        for path_id in path_ids:
            # Find the path item
            parent_item, child_item, child_row = self.find_path_item(path_id)
            # Remove the path item
            if child_item is not None:
                if parent_item is not None:
                    # Remove from parent
                    parent_item.removeRow(child_row)
                else:
                    # Remove from top-level
                    self.removeRow(child_row)
                cnt_removed_paths += 1
            # Remove the path from the map
            if path_id in self.path_map:
                del self.path_map[path_id]
        # Cleanup empty groups
        self._cleanup_empty_groups()
        return cnt_removed_paths

    def _cleanup_empty_groups(self) -> None:
        """
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

    def get_path(self, path_id: int) -> Optional[Path]:
        """
        This method returns the path with the specified ID.
        """
        return self.path_map.get(path_id, None)

    def get_path_id_from_index(self, index: qtc.QModelIndex) -> Optional[int]:
        """
        This method returns the path ID from a model index, or `None` if it's not a path item.
        """
        # Check if this is a valid path item
        if not index.isValid() or not index.data(IS_PATH_ITEM_ROLE):
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
        path = self.path_map.get(path_id, None)
        if path:
            path.comment = comment
        return

    def regroup_paths(self, path_grouping: str = None) -> None:
        """
        This method regroups all paths using the specified grouping strategy.

        Args:
            path_grouping: The new grouping strategy to use
        """
        # Nothing to regroup
        if len(self.path_map) == 0:
            return
        # Store existing paths
        paths = list(self.path_map.values())
        # Clear the model
        self.clear()
        # Re-add all paths with the new grouping strategy
        for path in paths:
            self.add_path(path, path_grouping)
        return
