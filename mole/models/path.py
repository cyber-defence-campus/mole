from __future__ import annotations
from dataclasses import dataclass, field
from mole.common.helper.instruction import InstructionHelper
from mole.common.log import Logger
from mole.core.graph import MediumLevelILFunctionGraph
from mole.grouping import PathGrouper
from mole.models.ai import AiVulnerabilityReport
from mole.models import IndexedLabeledEnum
from typing import Dict, List, Tuple, Type
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

    def add_path(self, path: Path, path_grouper: PathGrouper | None) -> None:
        """
        This method adds the given path to the model using the given grouper.
        """
        # Increment path ID and add to map
        self._path_id += 1
        self._path_map[self._path_id] = path
        # Get group keys
        if path_grouper is not None:
            group_keys = path_grouper.get_group_keys(path)
        else:
            group_keys = []
        # Create group items
        parent_item = self
        for display_name, internal_id, level in group_keys:
            # Create group item if it does not yet exist and add it to its parent item
            if internal_id not in self._group_items:
                group_item = self._create_group_item(display_name, level)
                parent_item.appendRow(group_item)
                self._group_items[internal_id] = group_item
            # Update parent item for the next iteration
            parent_item = self._group_items[internal_id]
        # Create path items
        path_items = self._create_path_items(path, self._path_id)
        parent_item.appendRow(path_items)
        # Emit data change signal
        self.dataChanged.emit(qtc.QModelIndex(), qtc.QModelIndex())
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

    def regroup_paths(self, path_grouper: PathGrouper | None) -> None:
        """
        This method regroups all paths in the model using the given grouper.
        """
        # Store paths
        paths = self.paths
        # Clear paths
        self.clear_paths()
        # Re-add paths
        for path in paths:
            self.add_path(path, path_grouper)
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
                if parent_item is not None:
                    # Remove from parent
                    parent_item.removeRow(child_row)
                else:
                    # Remove from top-level
                    self.removeRow(child_row)
                cnt_removed_paths += 1
            # Remove the path from the map
            if path_id in self._path_map:
                del self._path_map[path_id]
        # Remove empty groups
        self._remove_empty_groups()
        # Emit data change signal
        if cnt_removed_paths > 0:
            self.dataChanged.emit(qtc.QModelIndex(), qtc.QModelIndex())
        return cnt_removed_paths

    def clear_paths(self) -> None:
        """
        This method clears all paths from the model.
        """
        self._path_id = 0
        self._path_map.clear()
        self._group_items.clear()
        self.removeRows(0, self.rowCount())
        self.dataChanged.emit(qtc.QModelIndex(), qtc.QModelIndex())
        return


@dataclass
class Path:
    """
    This class is a representation of the data associated with identified paths.
    """

    src_sym_addr: int
    src_sym_name: str
    src_par_idx: int | None
    src_par_var: bn.MediumLevelILInstruction | None
    src_inst_idx: int
    snk_sym_addr: int
    snk_sym_name: str
    snk_par_idx: int
    snk_par_var: bn.MediumLevelILInstruction
    insts: List[bn.MediumLevelILInstruction]
    comment: str = ""
    sha1_hash: str = ""
    phiis: List[bn.MediumLevelILInstruction] = field(default_factory=list)
    bdeps: Dict[int, bn.ILBranchDependence] = field(default_factory=dict)
    calls: List[Tuple[bn.MediumLevelILFunction, int]] = field(default_factory=list)
    call_graph: MediumLevelILFunctionGraph = MediumLevelILFunctionGraph()
    ai_report: AiVulnerabilityReport | None = None

    def __init__(
        self,
        src_sym_addr: int,
        src_sym_name: str,
        src_par_idx: int | None,
        src_par_var: bn.MediumLevelILInstruction | None,
        src_inst_idx: int,
        snk_sym_addr: int,
        snk_sym_name: str,
        snk_par_idx: int,
        snk_par_var: bn.MediumLevelILInstruction,
        insts: List[bn.MediumLevelILInstruction],
        comment: str = "",
        sha1_hash: str = "",
        ai_report: AiVulnerabilityReport | None = None,
    ) -> None:
        self.src_sym_addr = src_sym_addr
        self.src_sym_name = src_sym_name
        self.src_par_idx = src_par_idx
        self.src_par_var = src_par_var
        self.src_inst_idx = src_inst_idx
        self.snk_sym_addr = snk_sym_addr
        self.snk_sym_name = snk_sym_name
        self.snk_par_idx = snk_par_idx
        self.snk_par_var = snk_par_var
        self.insts = insts
        self.comment = comment
        self.sha1_hash = sha1_hash
        self.phiis = []
        self.bdeps = {}
        self.calls = []
        self.call_graph = MediumLevelILFunctionGraph()
        self.ai_report = ai_report
        return

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Path):
            return False
        return (
            # Equal source
            self.src_sym_addr == other.src_sym_addr
            and self.src_sym_name == other.src_sym_name
            and (
                self.src_par_idx is None
                or other.src_par_idx is None
                or self.src_par_idx == other.src_par_idx
            )
            and (
                self.src_par_var is None
                or other.src_par_var is None
                or self.src_par_var == other.src_par_var
            )
            # Equal sink
            and self.snk_sym_addr == other.snk_sym_addr
            and self.snk_sym_name == other.snk_sym_name
            and self.snk_par_idx == other.snk_par_idx
            and self.snk_par_var == other.snk_par_var
            # Equal instructions (ignoring the ones originating from slicing the
            # source, only considering the source's call instruction)
            and self.src_inst_idx == other.src_inst_idx
            and self.insts[: self.src_inst_idx - 1]
            == other.insts[: self.src_inst_idx - 1]
            and self.insts[-1] == other.insts[-1]
            # Equal binary
            and self.sha1_hash == other.sha1_hash
        )

    def __str__(self) -> str:
        src = f"0x{self.src_sym_addr:x} {self.src_sym_name:s}"
        if self.src_par_idx and self.src_par_var:
            src = f"{src:s}(arg#{self.src_par_idx:d}:{str(self.src_par_var):s})"
        else:
            src = f"{src:s}"
        snk = f"0x{self.snk_sym_addr:x} {self.snk_sym_name:s}"
        snk = f"{snk:s}(arg#{self.snk_par_idx:d}:{str(self.snk_par_var):s})"
        return f"{snk:s} <-- {src:s}"

    def init(self, call_graph: MediumLevelILFunctionGraph) -> None:
        # Create call graph
        self.call_graph = call_graph.copy()
        # Iterate instructions in path
        old_func = None
        prv_inst = None
        for inst in self.insts:
            # Mark instruction's function being in the path
            func = inst.function
            self.call_graph.nodes[func]["in_path"] = True
            # Path goes upwards
            if self.call_graph.has_edge(func, old_func):
                self.call_graph[func][old_func]["in_path"] = True
                self.call_graph[func][old_func]["call_site"] = inst.address
            # Path goes downwards
            if self.call_graph.has_edge(old_func, func):
                self.call_graph[old_func][func]["in_path"] = True
                self.call_graph[old_func][func]["call_site"] = prv_inst.address
            # Phi-instructions
            if isinstance(inst, bn.MediumLevelILVarPhi):
                self.phiis.append(inst)
            # Branch dependencies
            for bch_idx, bch_dep in inst.branch_dependence.items():
                self.bdeps.setdefault(bch_idx, bch_dep)
            # Function in path changes
            if old_func != func:
                self.calls.append((func, 0))
                old_func = func
            prv_inst = inst
        # Add `src` node attribute
        src_func = self.insts[-1].function
        if src_func in self.call_graph:
            src_info = f"src: {self.src_sym_name:s}"
            if self.src_par_var:
                src_info = f"{src_info:s} | {str(self.src_par_var):s}"
            self.call_graph.nodes[src_func]["src"] = src_info
        # Add `snk` node attribute
        snk_func = self.insts[0].function
        if snk_func in self.call_graph:
            snk_info = f"snk: {self.snk_sym_name:s} | {str(self.snk_par_var):s}"
            self.call_graph.nodes[snk_func]["snk"] = snk_info
        # Calculate call levels
        self.call_graph.update_call_levels()
        # Update call levels
        for i, call in enumerate(self.calls):
            call_func = call[0]
            call_level = self.call_graph.nodes[call_func].get("level", 0)
            self.calls[i] = (call_func, call_level)
        return

    def update(self) -> Path:
        """
        This method updates the symbol names of the source and sink functions.
        """
        # Ensure path has instructions
        if not self.insts:
            return self
        # Update source function's symbol name
        src_inst = self.insts[-1]
        if isinstance(
            src_inst,
            bn.MediumLevelILCall
            | bn.MediumLevelILCallSsa
            | bn.MediumLevelILTailcall
            | bn.MediumLevelILTailcallSsa,
        ):
            src_sym_name, _ = InstructionHelper.get_func_signature(src_inst)
            if src_sym_name:
                self.src_sym_name = src_sym_name
        # Update sink function's symbol name
        snk_inst = self.insts[0]
        if isinstance(
            snk_inst,
            bn.MediumLevelILCall
            | bn.MediumLevelILCallSsa
            | bn.MediumLevelILTailcall
            | bn.MediumLevelILTailcallSsa,
        ):
            snk_sym_name, _ = InstructionHelper.get_func_signature(snk_inst)
            if snk_sym_name:
                self.snk_sym_name = snk_sym_name
        return self

    def to_dict(self) -> Dict:
        # Serialize instructions
        insts: List[Dict[str, str]] = []
        for inst in self.insts:
            inst_dict = {
                "fun_addr": hex(inst.function.source_function.start),
                "expr_idx": hex(inst.expr_index),
                "inst": InstructionHelper.get_inst_info(inst, True),
            }
            insts.append(inst_dict)
        return {
            "src_sym_addr": hex(self.src_sym_addr),
            "src_sym_name": self.src_sym_name,
            "src_par_idx": self.src_par_idx,
            "src_inst_idx": self.src_inst_idx,
            "snk_sym_addr": hex(self.snk_sym_addr),
            "snk_sym_name": self.snk_sym_name,
            "snk_par_idx": self.snk_par_idx,
            "insts": insts,
            "call_graph": self.call_graph.to_dict(),
            "comment": self.comment,
            "sha1_hash": self.sha1_hash,
            "ai_report": self.ai_report.to_dict() if self.ai_report else None,
        }

    @classmethod
    def from_dict(cls: Type[Path], bv: bn.BinaryView, d: Dict) -> Path | None:
        log = Logger(bv)
        try:
            # Deserialize instructions
            insts: List[bn.MediumLevelILInstruction] = []
            for inst_dict in d["insts"]:
                inst_dict = inst_dict  # type: Dict[str, str]
                fun_addr = int(inst_dict["fun_addr"], 0)
                expr_idx = int(inst_dict["expr_idx"], 0)
                func = bv.get_function_at(fun_addr)
                inst = func.mlil.ssa_form.get_expr(expr_idx)
                inst_info = InstructionHelper.get_inst_info(inst, True)
                if inst_info != inst_dict["inst"]:
                    log.warn(tag, "Instruction mismatch:")
                    log.warn(tag, f"- Expected: {inst_dict['inst']:s}")
                    log.warn(tag, f"- Found   : {inst_info:s}")
                insts.append(inst)
            # Deserialize parameter variables
            src_par_idx = d["src_par_idx"]
            if src_par_idx is not None and src_par_idx > 0:
                inst: bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa = insts[-1]
                src_par_var = inst.params[src_par_idx - 1]
            else:
                src_par_var = None
            snk_par_idx = d["snk_par_idx"]
            if snk_par_idx is not None and snk_par_idx > 0:
                inst: bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa = insts[0]
                snk_par_var = inst.params[snk_par_idx - 1]
            else:
                snk_par_var = None
            # Deserialize path
            path: Path = cls(
                src_sym_addr=int(d["src_sym_addr"], 0),
                src_sym_name=d["src_sym_name"],
                src_par_idx=src_par_idx,
                src_par_var=src_par_var,
                src_inst_idx=d["src_inst_idx"],
                snk_sym_addr=int(d["snk_sym_addr"], 0),
                snk_sym_name=d["snk_sym_name"],
                snk_par_idx=snk_par_idx,
                snk_par_var=snk_par_var,
                insts=insts,
                comment=d["comment"],
                sha1_hash=d["sha1_hash"],
                ai_report=AiVulnerabilityReport(**d["ai_report"])
                if d["ai_report"]
                else None,
            )
            path.init(MediumLevelILFunctionGraph.from_dict(bv, d["call_graph"]))
            return path
        except Exception as e:
            src_sym_addr_str = str(d.get("src_sym_addr", "unknown"))
            src_sym_name_str = str(d.get("src_sym_name", "unknown"))
            snk_sym_addr_str = str(d.get("snk_sym_addr", "unknown"))
            snk_sym_name_str = str(d.get("snk_sym_name", "unknown"))
            log.error(tag, f"Failed to deserialize path: {str(e):s}")
            log.error(tag, f"- Source: {src_sym_addr_str:s} {src_sym_name_str:s}")
            log.error(tag, f"- Sink  : {snk_sym_addr_str:s} {snk_sym_name_str:s}")
        return None
