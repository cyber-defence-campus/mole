from __future__ import annotations
from mole.data.path import Path
from mole.grouping import PathGrouper
from mole.models.ai import AiVulnerabilityReport
from mole.models import IndexedLabeledEnum
from typing import Dict, List, Tuple
import binaryninja as bn
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui


tag = "Path"


class PathRole(IndexedLabeledEnum):
    ID = qtc.Qt.UserRole + 100  # type: ignore ; Path ID (empty for headers)
    LEVEL = qtc.Qt.UserRole + 101  # type: ignore ; Header level (empty for paths)
    SORT = qtc.Qt.UserRole + 101  # type: ignore ; Key for sorting (empty for sorting on DisplayRole)


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


class PathProxyModel(qtc.QSortFilterProxyModel):
    """
    This class implements a proxy model to handle proper sorting for Mole's paths.
    """

    def __init__(self, path_tree_model: PathTreeModel) -> None:
        """
        This method initializes the path proxy model.
        """
        super().__init__()
        self.path_tree_model = path_tree_model
        self.setSourceModel(self.path_tree_model)
        return

    def lessThan(
        self,
        left: qtc.QModelIndex | qtc.QPersistentModelIndex,
        right: qtc.QModelIndex | qtc.QPersistentModelIndex,
    ) -> bool:
        """
        This method overrides the `lessThan` method to handle proper sorting of paths.
        """
        # Get model
        model = self.sourceModel()
        # Get data of left item
        l_id = model.data(left, PathRole.ID.index)
        l_level = model.data(left, PathRole.LEVEL.index)
        l_sort = model.data(left, PathRole.SORT.index)
        l_text = str(model.data(left, qtc.Qt.DisplayRole)).lower()  # type: ignore
        # Get data of right item
        r_id = model.data(right, PathRole.ID.index)
        r_level = model.data(right, PathRole.LEVEL.index)
        r_sort = model.data(right, PathRole.SORT.index)
        r_text = str(model.data(right, qtc.Qt.DisplayRole)).lower()  # type: ignore
        # Left is header
        if l_id is None:
            # Right is header
            if r_id is None:
                try:
                    l_level = int(l_level)
                    r_level = int(r_level)
                except Exception as _:
                    if l_text == r_text:
                        return False
                    return l_text >= r_text
                if l_level == r_level:
                    return False
                return l_level >= r_level
            # Right is path
            return True
        # Left is path
        else:
            # Right is header
            if r_id is None:
                return False
            # Right is path
            try:
                l_sort = int(l_sort)
                r_sort = int(r_sort)
            except Exception as _:
                if l_text == r_text:
                    return False
                return l_text >= r_text
            if l_sort == r_sort:
                return False
            return l_sort >= r_sort


class PathTreeModel(qtui.QStandardItemModel):
    """
    This class implements a tree model for Mole's paths.
    """

    signal_paths_updated = qtc.Signal()

    def __init__(self) -> None:
        """
        This method initializes the path tree model.
        """
        super().__init__()
        self._path_id = 0
        self._path_map: Dict[int, Path] = {}
        self._group_items: Dict[str, qtui.QStandardItem] = {}
        self.setHorizontalHeaderLabels(PathColumn.labels())
        return

    @property
    def paths(self) -> List[Path]:
        """
        This property returns a list of all paths in the model.
        """
        return list(self._path_map.values())

    @property
    def path_ids(self) -> List[int]:
        """
        This property returns a list of all path IDs in the model.
        """
        return list(self._path_map.keys())

    def get_path(self, path_id: int) -> Path | None:
        """
        This method gets the path for the given path ID.
        """
        if path_id is not None:
            return self._path_map.get(path_id, None)
        return None

    def get_path_id(
        self, index: qtc.QModelIndex | qtc.QPersistentModelIndex
    ) -> int | None:
        """
        This method gets the path ID for the given model index.
        """
        # Check if this is a valid path item
        if not index.isValid() or index.data(PathRole.ID.index) is None:
            return None
        # Get the first column item which contains the path ID
        if index.column() != 0:
            index = index.sibling(index.row(), 0)
        # Return the path ID
        return int(index.data(PathRole.ID.index))

    def find_path_item(
        self, path_id
    ) -> Tuple[qtui.QStandardItem | None, qtui.QStandardItem | None, int]:
        """
        This method tries to find the path item matching the given path ID.

        Args:
            path_id    : ID of the path to be found

        Returns:
            parent_item: The parent item or `None` if no parent exsits
            child_item : The child item or `None` if it has not been found
            child_row  : The child's row index relative to its parent item
        """

        # Find path item recursively
        def _find_path_item_recursively(
            item: qtui.QStandardItem,
        ) -> Tuple[qtui.QStandardItem | None, qtui.QStandardItem | None, int]:
            # Check matching path ID
            if item.data(PathRole.ID.index) == path_id:
                return (None, item, -1)
            # If the item is not a path, try finding in its children
            else:
                for row in range(item.rowCount()):
                    parent_item, child_item, child_row = _find_path_item_recursively(
                        item.child(row, 0)
                    )
                    if child_item is not None:
                        if parent_item is None:
                            parent_item = item
                            child_row = row
                        return (parent_item, child_item, child_row)
            return (None, None, -1)

        # Iterate top-level items
        for row in range(self.rowCount()):
            parent_item, child_item, child_row = _find_path_item_recursively(
                self.item(row, 0)
            )
            if child_item is not None:
                if parent_item is None:
                    child_row = row
                return (parent_item, child_item, child_row)
        return (None, None, -1)

    def _create_group_item(self, text: str, level: int) -> qtui.QStandardItem:
        """
        This method creates an item for the group with the given text and level.
        """
        # Styling
        font = qtui.QFont()
        font.setItalic(True)
        color = qtui.QBrush(qtui.QColor(255, 239, 213))
        # Create main item
        main_item = qtui.QStandardItem(text)
        main_item.setData(level, PathRole.LEVEL.index)
        main_item.setFlags(
            main_item.flags() & ~qtc.Qt.ItemIsEditable & ~qtc.Qt.ItemIsSelectable  # type: ignore
        )
        main_item.setFont(font)
        main_item.setForeground(color)
        return main_item

    def _create_path_items(self, path: Path, path_id: int) -> List[qtui.QStandardItem]:
        """
        This method creates a list of items for the given path.
        """
        # Create path items
        id_item = qtui.QStandardItem(f"{path_id:d}")
        id_item.setData(path_id, PathRole.ID.index)
        id_item.setData(path_id, PathRole.SORT.index)

        src_addr_item = qtui.QStandardItem(f"0x{path.src_sym_addr:x}")
        src_addr_item.setData(path_id, PathRole.ID.index)
        src_addr_item.setData(path.src_sym_addr, PathRole.SORT.index)

        src_func_item = qtui.QStandardItem(path.src_sym_name)
        src_func_item.setData(path_id, PathRole.ID.index)

        if path.src_par_idx is not None and path.src_par_var is not None:
            src_parm_label = f"arg#{path.src_par_idx:d}:{str(path.src_par_var):s}"
            src_parm_sort = path.src_par_idx
        else:
            src_parm_label = ""
            src_parm_sort = 0
        src_parm_item = qtui.QStandardItem(src_parm_label)
        src_parm_item.setData(path_id, PathRole.ID.index)
        src_parm_item.setData(src_parm_sort, PathRole.SORT.index)

        snk_addr_item = qtui.QStandardItem(f"0x{path.snk_sym_addr:x}")
        snk_addr_item.setData(path_id, PathRole.ID.index)
        snk_addr_item.setData(path.snk_sym_addr, PathRole.SORT.index)

        snk_func_item = qtui.QStandardItem(path.snk_sym_name)
        snk_func_item.setData(path_id, PathRole.ID.index)

        snk_parm_item = qtui.QStandardItem(
            f"arg#{path.snk_par_idx:d}:{str(path.snk_par_var):s}"
        )
        snk_parm_item.setData(path_id, PathRole.ID.index)
        snk_parm_item.setData(path.snk_par_idx, PathRole.SORT.index)

        inst_item = qtui.QStandardItem(str(len(path.insts)))
        inst_item.setData(path_id, PathRole.ID.index)
        inst_item.setData(len(path.insts), PathRole.SORT.index)

        phis_item = qtui.QStandardItem(str(len(path.phiis)))
        phis_item.setData(path_id, PathRole.ID.index)
        phis_item.setData(len(path.phiis), PathRole.SORT.index)

        bdeps_item = qtui.QStandardItem(str(len(path.bdeps)))
        bdeps_item.setData(path_id, PathRole.ID.index)
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
        severity_item.setData(path_id, PathRole.ID.index)
        severity_item.setData(severity_sort, PathRole.SORT.index)
        severity_item.setForeground(severity_color)

        comment_item = qtui.QStandardItem(path.comment)
        comment_item.setData(path_id, PathRole.ID.index)

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
            item.setFlags(item.flags() & ~qtc.Qt.ItemIsEditable)  # type: ignore

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
        return path_row

    def add_paths(self, paths: List[Path], path_grouper: PathGrouper | None) -> None:
        """
        This method adds the given paths to the model using the given grouper.
        """
        # Add new groups items to the model and map path items to their group
        path_items_map: Dict[str, List[List[qtui.QStandardItem]]] = {}
        for path in paths:
            # Increment path ID and store path
            self._path_id += 1
            self._path_map[self._path_id] = path
            # Add new group items to the model and store path items to the correct group
            group_name = ""
            parent_group_item: qtui.QStandardItem | None = None
            group_keys = (
                path_grouper.get_group_keys(path) if path_grouper is not None else []
            )
            for display_name, internal_name, level in group_keys:
                group_item = self._group_items.get(internal_name, None)
                # Create the group items that do not yet exist and add them to the model
                if group_item is None:
                    # Create and store new group item
                    group_item = self._create_group_item(display_name, level)
                    self._group_items[internal_name] = group_item

                    # Add new group item to the model
                    def _add_group_item(item: qtui.QStandardItem) -> None:
                        # Add new group item to the root item
                        if parent_group_item is None:
                            self.appendRow(item)
                        # Add new group item to its parent group item
                        else:
                            parent_group_item.appendRow(item)
                        return

                    bn.execute_on_main_thread_and_wait(
                        lambda: _add_group_item(group_item)
                        if group_item is not None
                        else None
                    )
                # Update the path's group name
                group_name = internal_name
                # Update the parent group item for the next iteration
                parent_group_item = group_item
            # Create path items and map them to their group item
            path_items = self._create_path_items(path, self._path_id)
            path_items_map.setdefault(group_name, []).append(path_items)
        # Add path items to the model
        for group_name, path_items_list in path_items_map.items():
            group_item = self._group_items.get(group_name, None)

            # Add new path items to the model
            def _add_path_items() -> None:
                # Add new path items to the root item
                if group_item is None:
                    for path_items in path_items_list:
                        self.appendRow(path_items)
                # Add new path items to their parent group item
                else:
                    for path_items in path_items_list:
                        group_item.appendRow(path_items)
                return

            bn.execute_on_main_thread_and_wait(lambda: _add_path_items())
        self.signal_paths_updated.emit()
        return

    def add_path_report(self, path_id: int, ai_report: AiVulnerabilityReport) -> None:
        """
        This method adds the given path to the model using the given grouper.
        """
        # Update the path's AI report
        path = self._path_map.get(path_id, None)
        if path is None:
            return
        path.ai_report = ai_report
        # Find the path item
        parent_item, child_item, child_row = self.find_path_item(path_id)
        # Find the severity column item
        if child_item is None:
            return
        if parent_item is not None:
            severity_item = parent_item.child(child_row, PathColumn.AI_SEVERITY.index)
        else:
            severity_item = self.item(child_row, PathColumn.AI_SEVERITY.index)
        # Update the severity item
        if ai_report.truePositive:
            text = f"{ai_report.severityLevel.label:s}"
            sort = ai_report.severityLevel.index
        else:
            text = f"{ai_report.severityLevel.label:s}*"
            sort = ai_report.severityLevel.index - 1

        def _add_path_report() -> None:
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
            self.dataChanged.emit(qtc.QModelIndex(), qtc.QModelIndex())

        bn.execute_on_main_thread(_add_path_report)
        return

    def update_paths(self, path_grouper: PathGrouper | None) -> None:
        """
        This method updates all paths in the model using the given grouper.
        """

        # Update item recursively
        def _update_item_recursively(
            item: qtui.QStandardItem, row: int, parent_items: List[qtui.QStandardItem]
        ) -> None:
            # Get item ID
            item_id: int | None = item.data(PathRole.ID.index)
            # Item is a path
            if item_id is not None:
                path = self._path_map.get(item_id, None)
                if path is not None:
                    # Update path and create new path items
                    path.update()
                    path_items = self._create_path_items(path, item_id)

                    def __update_item_recusively() -> None:
                        # Path has parents (is in a group)
                        if parent_items:
                            # Update path items
                            parent_item = parent_items[-1]
                            for col in range(parent_item.columnCount()):
                                child_item = parent_item.child(row, col)
                                new_text = path_items[col].text()
                                child_item.setText(new_text)
                            # Update group names
                            group_keys = (
                                path_grouper.get_group_keys(path)
                                if path_grouper is not None
                                else []
                            )
                            for i, (group_name, _, _) in enumerate(group_keys):
                                parent_items[i].setText(group_name)
                        # Path has no parents (is top-level)
                        else:
                            # Replace row (not bothering about collapsing/expanding groups)
                            self.removeRow(row)
                            self.insertRow(row, path_items)

                    bn.execute_on_main_thread(__update_item_recusively)
            # Item is a group
            else:
                # Iterate item's children and update them recursively
                for row in range(item.rowCount()):
                    child_item = item.child(row, 0)
                    _update_item_recursively(child_item, row, parent_items + [item])
            return

        # Update top-level items recursively
        for row in range(self.rowCount()):
            _update_item_recursively(self.item(row, 0), row, [])
        return

    def regroup_paths(
        self, path_grouper: PathGrouper | None, batch_size: int = 100
    ) -> None:
        """
        This method regroups all paths in the model using the given grouper.
        """
        # Store paths
        paths = self.paths
        # Clear paths
        self.clear_paths()
        # Re-add paths in batches with new grouping strategy
        for i in range(0, len(paths), batch_size):
            paths_batch = paths[i : i + batch_size]
            self.add_paths(paths_batch, path_grouper)
        return

    def _remove_empty_groups(self) -> None:
        """
        This method removes all groups that do not have any children.
        """
        # Iterate groups in reversed order
        group_keys = []
        for group_key, group_item in reversed(self._group_items.items()):
            # Remove groups without children
            if group_item.rowCount() == 0:
                if group_item.parent():
                    group_item.parent().removeRow(group_item.row())
                else:
                    self.removeRow(group_item.row())
                group_keys.append(group_key)
        # Remove groups from the dictionary
        for group_key in group_keys:
            self._group_items.pop(group_key, None)
        return

    def remove_paths(self, path_ids: List[int]) -> int:
        """
        This method removes the given paths from the model.
        """
        # Remove paths
        cnt_removed_paths = 0
        for path_id in path_ids:
            # Find the path item
            parent_item, child_item, child_row = self.find_path_item(path_id)
            # Remove the path item
            if child_item is not None:

                def _remove_path() -> None:
                    if parent_item is not None:
                        # Remove from parent
                        parent_item.removeRow(child_row)
                    else:
                        # Remove from top-level
                        self.removeRow(child_row)

                bn.execute_on_main_thread_and_wait(_remove_path)
                cnt_removed_paths += 1
            # Remove the path from the map
            if path_id in self._path_map:
                del self._path_map[path_id]
        # Remove empty groups
        self._remove_empty_groups()
        # Emit data change signal
        if cnt_removed_paths > 0:
            bn.execute_on_main_thread(
                lambda: self.dataChanged.emit(qtc.QModelIndex(), qtc.QModelIndex())
            )
        return cnt_removed_paths

    def clear_paths(self) -> None:
        """
        This method clears all paths from the model.
        """
        self._path_id = 0
        self._path_map.clear()
        self._group_items.clear()

        def _clear_paths() -> None:
            self.removeRows(0, self.rowCount())
            self.dataChanged.emit(qtc.QModelIndex(), qtc.QModelIndex())

        bn.execute_on_main_thread(_clear_paths)
        return
