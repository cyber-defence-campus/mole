from __future__ import annotations
from mole.core.data import Path
from mole.grouping import get_grouper
from mole.models import IndexedLabeledEnum
from mole.services.ai import AiVulnerabilityReport
from typing import Dict, List, Optional, Tuple
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui


class PathRole(IndexedLabeledEnum):
    ID = qtc.Qt.UserRole + 100  # Path ID (empty for headers)
    LEVEL = qtc.Qt.UserRole + 101  # Header level (empty for paths)
    SORT = qtc.Qt.UserRole + 101  # Key for sorting (empty for sorting on DisplayRole)


class PathColumn(IndexedLabeledEnum):
    ID = (0, "Id")
    SRC_ADDR = (1, "Src Addr")
    SRC_FUNC = (2, "Src Func")
    SRC_PARM = (3, "Src Parm")
    SNK_ADDR = (4, "Snk Addr")
    SNK_FUNC = (5, "Snk Func")
    SNK_PARM = (6, "Snk Parm")
    INSTS = (7, "Insts")
    PHIS = (8, "Phis")
    BRANCHES = (9, "Branches")
    AI_SEVERITY = (10, "AI Severity")
    COMMENT = (11, "Comment")


class PathSortProxyModel(qtc.QSortFilterProxyModel):
    """
    This class implements a proxy model to handle proper sorting for paths. It
    uses `qtc.Qt.UserRole` data to maintain original data types during sorting.
    """

    def lessThan(
        self,
        left: qtc.QModelIndex | qtc.QPersistentModelIndex,
        right: qtc.QModelIndex | qtc.QPersistentModelIndex,
    ) -> bool:
        """
        This method overrides the `lessThan` method to provide proper sorting
        based on data types.
        """
        # Access model data
        model = self.sourceModel()
        lft_id = model.data(left, PathRole.ID.index)
        lft_level = model.data(left, PathRole.LEVEL.index)
        lft_sort = model.data(left, PathRole.SORT.index)
        lft_text = str(model.data(left, qtc.Qt.DisplayRole)).lower()
        rgt_id = model.data(right, PathRole.ID.index)
        rgt_level = model.data(right, PathRole.LEVEL.index)
        rgt_sort = model.data(right, PathRole.SORT.index)
        rgt_text = str(model.data(right, qtc.Qt.DisplayRole)).lower()

        # Left is header
        if lft_id is None:
            # Right is header
            if rgt_id is None:
                try:
                    lft_level = int(lft_level)
                    rgt_level = int(rgt_level)
                except Exception as _:
                    if lft_text == rgt_text:
                        return False
                    return lft_text >= rgt_text
                if lft_level == rgt_level:
                    return False
                return lft_level >= rgt_level
            # Right is path
            return True
        # Left is path
        else:
            # Right is header
            if rgt_id is None:
                return False
            # Right is path
            try:
                lft_sort = int(lft_sort)
                rgt_sort = int(rgt_sort)
            except Exception as _:
                if lft_text == rgt_text:
                    return False
                return lft_text >= rgt_text
            if lft_sort == rgt_sort:
                return False
            return lft_sort >= rgt_sort


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
        self.setHorizontalHeaderLabels(PathColumn.labels())
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
        color = qtui.QBrush(qtui.QColor(255, 239, 213))
        # Create main item
        main_item = qtui.QStandardItem(text)
        main_item.setData(level, PathRole.LEVEL.index)
        main_item.setFlags(
            main_item.flags() & ~qtc.Qt.ItemIsEditable & ~qtc.Qt.ItemIsSelectable
        )
        main_item.setFont(font)
        main_item.setForeground(color)
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
        id_item.setData(self.path_id, PathRole.ID.index)
        id_item.setData(self.path_id, PathRole.SORT.index)

        src_addr_item = qtui.QStandardItem(f"0x{path.src_sym_addr:x}")
        src_addr_item.setData(self.path_id, PathRole.ID.index)
        src_addr_item.setData(path.src_sym_addr, PathRole.SORT.index)

        src_func_item = qtui.QStandardItem(path.src_sym_name)
        src_func_item.setData(self.path_id, PathRole.ID.index)

        if path.src_par_idx is not None and path.src_par_var is not None:
            src_parm_label = f"arg#{path.src_par_idx:d}:{str(path.src_par_var):s}"
            src_parm_sort = path.src_par_idx
        else:
            src_parm_label = ""
            src_parm_sort = 0
        src_parm_item = qtui.QStandardItem(src_parm_label)
        src_parm_item.setData(self.path_id, PathRole.ID.index)
        src_parm_item.setData(src_parm_sort, PathRole.SORT.index)

        snk_addr_item = qtui.QStandardItem(f"0x{path.snk_sym_addr:x}")
        snk_addr_item.setData(self.path_id, PathRole.ID.index)
        snk_addr_item.setData(path.snk_sym_addr, PathRole.SORT.index)

        snk_func_item = qtui.QStandardItem(path.snk_sym_name)
        snk_func_item.setData(self.path_id, PathRole.ID.index)

        snk_parm_item = qtui.QStandardItem(
            f"arg#{path.snk_par_idx:d}:{str(path.snk_par_var):s}"
        )
        snk_parm_item.setData(self.path_id, PathRole.ID.index)
        snk_parm_item.setData(path.snk_par_idx, PathRole.SORT.index)

        inst_item = qtui.QStandardItem(str(len(path.insts)))
        inst_item.setData(self.path_id, PathRole.ID.index)
        inst_item.setData(len(path.insts), PathRole.SORT.index)

        phis_item = qtui.QStandardItem(str(len(path.phiis)))
        phis_item.setData(self.path_id, PathRole.ID.index)
        phis_item.setData(len(path.phiis), PathRole.SORT.index)

        bdeps_item = qtui.QStandardItem(str(len(path.bdeps)))
        bdeps_item.setData(self.path_id, PathRole.ID.index)
        bdeps_item.setData(len(path.bdeps), PathRole.SORT.index)

        if path.ai_report is not None:
            if path.ai_report.truePositive:
                severity_label = f"{path.ai_report.severityLevel.label:s}"
                severity_sort = path.ai_report.severityLevel.index
                match path.ai_report.severityLevel.label:
                    case "Critical":
                        severity_color = qtui.QBrush(qtui.QColor("#FF0000"))
                    case "High":
                        severity_color = qtui.QBrush(qtui.QColor("#FFA500"))
                    case "Medium":
                        severity_color = qtui.QBrush(qtui.QColor("#FFFF00"))
                    case _:
                        severity_color = qtui.QBrush(qtui.QColor("#008000"))
            else:
                severity_label = f"{path.ai_report.severityLevel.label:s}*"
                severity_sort = path.ai_report.severityLevel.index - 1
                severity_color = qtui.QBrush(qtui.QColor("#FFFFFF"))
        else:
            severity_label = ""
            severity_sort = 0
            severity_color = qtui.QBrush(qtui.QColor("#FFFFFF"))
        severity_item = qtui.QStandardItem(severity_label)
        severity_item.setData(self.path_id, PathRole.ID.index)
        severity_item.setData(severity_sort, PathRole.SORT.index)
        severity_item.setForeground(severity_color)

        comment_item = qtui.QStandardItem(path.comment)
        comment_item.setData(self.path_id, PathRole.ID.index)

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
            severity_item,
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
            severity_item,
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
            # Check matching path ID
            if item.data(PathRole.ID.index) == path_id:
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
        if not index.isValid() or not index.data(PathRole.ID.index):
            return None
        # Get the first column item which contains the path ID
        if index.column() != 0:
            index = index.sibling(index.row(), 0)
        # Return the path ID
        return index.data(PathRole.ID.index)

    def update_path_report(
        self, path_id: int, ai_report: AiVulnerabilityReport
    ) -> bool:
        """
        This method updates the AI-generated report for the specified path and
        adjusts the severity display.

        Args:
            path_id: The ID of the path to update
            ai_report: The AI-generated report of the path
        Returns:
            bool: True if the update was successful, False otherwise
        """
        # Update path's AI report
        path = self.path_map.get(path_id, None)
        if not path:
            return False
        path.ai_report = ai_report
        # Find the path item
        parent_item, child_item, child_row = self.find_path_item(path_id)
        # Find the severity column item
        if not child_item:
            return False
        if parent_item:
            severity_item = parent_item.child(child_row, PathColumn.AI_SEVERITY.index)
        else:
            severity_item = self.item(child_row, PathColumn.AI_SEVERITY.index)
        if not severity_item:
            return False
        # Update the severity item
        if ai_report.truePositive:
            text = f"{ai_report.severityLevel.label:s}"
            sort = ai_report.severityLevel.index
        else:
            text = f"{ai_report.severityLevel.label:s}*"
            sort = ai_report.severityLevel.index - 1
        severity_item.setText(text)
        severity_item.setData(sort, PathRole.SORT.index)
        # Color formatting
        if ai_report.truePositive:
            match ai_report.severityLevel.label:
                case "Critical":
                    severity_item.setForeground(qtui.QBrush(qtui.QColor("#FF0000")))
                case "High":
                    severity_item.setForeground(qtui.QBrush(qtui.QColor("#FFA500")))
                case "Medium":
                    severity_item.setForeground(qtui.QBrush(qtui.QColor("#FFFF00")))
                case _:
                    severity_item.setForeground(qtui.QBrush(qtui.QColor("#008000")))
        else:
            severity_item.setForeground(qtui.QBrush(qtui.QColor("#FFFFFF")))
        return True

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

    # def update_analysis_result(
    #     self, path_id: int, ai_report: AiVulnerabilityReport
    # ) -> bool:
    #     """
    #     This method updates the AI report for a path and updates the score
    #     display.

    #     Args:
    #         path_id: The ID of the path to update
    #         ai_report: The AI report object

    #     Returns:
    #         bool: True if the update was successful, False otherwise
    #     """
    #     if path_id not in self.path_map:
    #         return False

    #     # Update the path with the new analysis result
    #     self.path_map[path_id].ai_report = ai_report

    #     # Find the path item
    #     parent_item, child_item, child_row = self.find_path_item(path_id)
    #     if child_item is None:
    #         return False

    #     # # TODO
    #     # ai_report.severityLevel

    #     # # Determine score
    #     # score_value = 0.0
    #     # score_display = ""
    #     # if ai_report is not None:
    #     #     score_value = ai_report.exploitabilityScore
    #     #     if ai_report.truePositive:
    #     #         score_display = f"{score_value:.1f}"
    #     #     else:
    #     #         score_display = f"{score_value:.1f}*"

    #     # Find the severity column item
    #     if parent_item:
    #         severity_item = parent_item.child(child_row, PATH_COLS["AI Severity"])
    #     else:
    #         severity_item = self.item(child_row, PATH_COLS["AI Severity"])

    #     if severity_item:
    #         severity_item.setText(score_display)
    #         severity_item.setData(score_value, qtc.Qt.UserRole)  # For sorting

    #         # Color formatting for true positives
    #         if ai_report.truePositive:
    #             # Critical: red
    #             if score_value >= 9.0:
    #                 severity_item.setForeground(qtui.QBrush(qtui.QColor("#FF0000")))
    #             # High: orange
    #             if score_value >= 7.0:
    #                 severity_item.setForeground(qtui.QBrush(qtui.QColor("#FFA500")))
    #             # Medium: yellow
    #             elif score_value >= 4.0:
    #                 severity_item.setForeground(qtui.QBrush(qtui.QColor("#FFFF00")))
    #             # Low: green
    #             elif score_value >= 0.1:
    #                 severity_item.setForeground(qtui.QBrush(qtui.QColor("#008000")))
    #             # None: gray
    #             else:
    #                 severity_item.setForeground(qtui.QBrush(qtui.QColor("#FFFFFF")))
    #         return True
    #     return False

    def get_analysis_result(self, path_id: int) -> Optional[AiVulnerabilityReport]:
        """
        This method returns the analysis result object for a path.

        Args:
            path_id: The ID of the path

        Returns:
            The analysis result object or None if not available
        """
        path = self.path_map.get(path_id)
        return path.ai_report if path else None
