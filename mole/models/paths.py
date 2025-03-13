from __future__ import annotations
from typing import Dict, List, Optional, Any, Tuple
import PySide6.QtCore as qtc
import PySide6.QtGui as qtui

from ..core.data import Path, GroupingStrategy

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
ITEM_TYPE_ROLE = qtc.Qt.UserRole + 102

# Item type values
SOURCE_ITEM = 1
SINK_ITEM = 2
CALLGRAPH_ITEM = 3
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
        self.source_items: Dict[str, qtui.QStandardItem] = {}
        self.sink_items: Dict[Tuple[str, str], qtui.QStandardItem] = {}
        self.callgraph_items: Dict[Tuple[str, str, str], qtui.QStandardItem] = {}
        
    def clear(self) -> None:
        """
        Clear all data from the model.
        """
        self.paths.clear()
        self.path_comments.clear()
        self.source_items.clear()
        self.sink_items.clear()
        self.callgraph_items.clear()
        self.path_count = 0
        self.setRowCount(0)
        
    def _format_callgraph_name(self, path: Path) -> str:
        """
        Format a readable call graph path from the path's call graph.
        """
        if not path.call_graph or not path.call_graph.nodes:
            return "Direct call"
            
        # Extract function names from the call graph
        func_names = []
        for node in path.call_graph.nodes:
            if path.call_graph.nodes[node]["in_path"]:
                func_names.append(node.source_function.name)
                
        # Format the call graph path
        if func_names:
            return " -> ".join(func_names)
        return "Unknown call path"
        
    def _create_non_path_item_row(self, text: str, item_type: int) -> List[qtui.QStandardItem]:
        """
        Create a row of items for non-path items (source, sink, callgraph headers).
        """
        # Create main item
        main_item = qtui.QStandardItem(text)
        main_item.setData(False, IS_PATH_ITEM_ROLE)
        main_item.setData(item_type, ITEM_TYPE_ROLE)
        main_item.setFlags(main_item.flags() & ~qtc.Qt.ItemIsEditable)
        
        # Return a single item - we'll use setFirstColumnSpanned in the view to make it span all columns
        return [main_item]
        
    def add_path(self, path: Path, comment: str = "", grouping_strategy: GroupingStrategy = GroupingStrategy.CALLGRAPH) -> None:
        """
        Add a path to the model grouped by source and sink, optionally by call graph.
        
        Args:
            path: The path to add
            comment: Comment for the path
            grouping_strategy: How to group paths - GroupingStrategy.NONE or GroupingStrategy.CALLGRAPH
        """
        self.paths.append(path)
        path_id = len(self.paths) - 1
        self.path_comments[path_id] = comment
        
        # Get or create source function group
        source_name = path.src_sym_name
        if source_name not in self.source_items:
            # Create source function group row
            source_row = self._create_non_path_item_row(f"Source: {source_name}", SOURCE_ITEM)
            self.appendRow(source_row)
            self.source_items[source_name] = source_row[0]
            
        # Get source item
        source_item = self.source_items[source_name]
        
        # Get or create sink function group under this source
        sink_name = path.snk_sym_name
        sink_key = (source_name, sink_name)
        if sink_key not in self.sink_items:
            # Create sink function group row
            sink_row = self._create_non_path_item_row(f"Sink: {sink_name}", SINK_ITEM)
            source_item.appendRow(sink_row)
            self.sink_items[sink_key] = sink_row[0]
        
        # Get sink item
        sink_item = self.sink_items[sink_key]
        
        # Add path directly under sink if grouping strategy is None
        parent_item = sink_item
        
        # Otherwise, group by callgraph if the strategy is Callgraph
        if grouping_strategy == GroupingStrategy.CALLGRAPH:
            # Get or create call graph group under this sink
            callgraph_name = self._format_callgraph_name(path)
            callgraph_key = (source_name, sink_name, callgraph_name)
            if callgraph_key not in self.callgraph_items:
                # Create call graph group row
                callgraph_row = self._create_non_path_item_row(f"Path: {callgraph_name}", CALLGRAPH_ITEM)
                sink_item.appendRow(callgraph_row)
                self.callgraph_items[callgraph_key] = callgraph_row[0]
                
            # Get call graph item as parent for path items
            parent_item = self.callgraph_items[callgraph_key]
        
        # Create path items
        index_item = qtui.QStandardItem(str(path_id))
        index_item.setData(path_id, PATH_ID_ROLE)
        index_item.setData(True, IS_PATH_ITEM_ROLE)
        index_item.setData(PATH_ITEM, ITEM_TYPE_ROLE)
        
        # Only store hex values as UserRole data for proper sorting
        src_addr_item = qtui.QStandardItem(f"{path.src_sym_addr:x}")
        src_addr_item.setData(path.src_sym_addr, qtc.Qt.UserRole)
        src_addr_item.setData(True, IS_PATH_ITEM_ROLE)
        src_addr_item.setData(PATH_ITEM, ITEM_TYPE_ROLE)
        
        src_func_item = qtui.QStandardItem(path.src_sym_name)
        src_func_item.setData(True, IS_PATH_ITEM_ROLE)
        src_func_item.setData(PATH_ITEM, ITEM_TYPE_ROLE)
        
        snk_addr_item = qtui.QStandardItem(f"{path.snk_sym_addr:x}")
        snk_addr_item.setData(path.snk_sym_addr, qtc.Qt.UserRole)
        snk_addr_item.setData(True, IS_PATH_ITEM_ROLE)
        snk_addr_item.setData(PATH_ITEM, ITEM_TYPE_ROLE)
        
        snk_func_item = qtui.QStandardItem(path.snk_sym_name)
        snk_func_item.setData(True, IS_PATH_ITEM_ROLE)
        snk_func_item.setData(PATH_ITEM, ITEM_TYPE_ROLE)
        
        snk_parm_item = qtui.QStandardItem(f"arg#{path.snk_par_idx:d}:{str(path.snk_par_var):s}")
        snk_parm_item.setData(True, IS_PATH_ITEM_ROLE)
        snk_parm_item.setData(PATH_ITEM, ITEM_TYPE_ROLE)
        
        insts_item = qtui.QStandardItem(str(len(path.insts)))
        insts_item.setData(True, IS_PATH_ITEM_ROLE)
        insts_item.setData(PATH_ITEM, ITEM_TYPE_ROLE)
        
        phis_item = qtui.QStandardItem(str(len(path.phiis)))
        phis_item.setData(True, IS_PATH_ITEM_ROLE)
        phis_item.setData(PATH_ITEM, ITEM_TYPE_ROLE)
        
        bdeps_item = qtui.QStandardItem(str(len(path.bdeps)))
        bdeps_item.setData(True, IS_PATH_ITEM_ROLE)
        bdeps_item.setData(PATH_ITEM, ITEM_TYPE_ROLE)
        
        comment_item = qtui.QStandardItem(comment)
        comment_item.setData(True, IS_PATH_ITEM_ROLE)
        comment_item.setData(PATH_ITEM, ITEM_TYPE_ROLE)

        # Set items as non-editable (except for comment)
        for item in [index_item, src_addr_item, src_func_item, snk_addr_item, 
                     snk_func_item, snk_parm_item, insts_item, phis_item, bdeps_item]:
            item.setFlags(item.flags() & ~qtc.Qt.ItemIsEditable)
            
        # Create path row and append to parent item (sink or callgraph)
        path_row = [
            index_item, src_addr_item, src_func_item, snk_addr_item,
            snk_func_item, snk_parm_item, insts_item, phis_item, bdeps_item, comment_item
        ]
        parent_item.appendRow(path_row)
        
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
                callgraph_name = self._format_callgraph_name(path)
                sink_key = (source_name, sink_name)
                callgraph_key = (source_name, sink_name, callgraph_name)
                
                # Remove path from internal lists
                self.paths[row_id] = None  # Mark as removed
                self.path_comments.pop(row_id, None)
                
                # Find and remove the path item from the tree
                if (source_name in self.source_items and 
                    sink_key in self.sink_items and
                    callgraph_key in self.callgraph_items):
                    
                    source_item = self.source_items[source_name]
                    sink_item = self.sink_items[sink_key]
                    callgraph_item = self.callgraph_items[callgraph_key]
                    
                    # Find the item with matching path_id among callgraph item's children
                    for i in range(callgraph_item.rowCount()):
                        child = callgraph_item.child(i, 0)
                        if child and child.data(PATH_ID_ROLE) == row_id:
                            callgraph_item.removeRow(i)
                            self.path_count -= 1
                            break
                    
                    # If callgraph has no more paths, remove it
                    if callgraph_item.rowCount() == 0:
                        sink_item.removeRow(callgraph_item.row())
                        self.callgraph_items.pop(callgraph_key, None)
                    
                    # If sink has no more callgraphs, remove it
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
            for src_i in range(source_item.rowCount()):
                sink_item = source_item.child(src_i, 0)
                if not sink_item:
                    continue
                    
                for snk_i in range(sink_item.rowCount()):
                    callgraph_item = sink_item.child(snk_i, 0)
                    if not callgraph_item:
                        continue
                        
                    for cg_i in range(callgraph_item.rowCount()):
                        path_item = callgraph_item.child(cg_i, 0)
                        if not path_item:
                            continue
                            
                        path_id = path_item.data(PATH_ID_ROLE)
                        if path_id is not None:
                            comment_item = callgraph_item.child(cg_i, COMMENT_COL)
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
            
        # Check if we're dealing with an actual path item (not a header)
        # With call graph grouping, a path item has 3 levels of parent nodes
        if (not index.parent().isValid() or 
            not index.parent().parent().isValid() or
            not index.parent().parent().parent().isValid()):
            return None
            
        # Return the path ID
        return index.data(PATH_ID_ROLE)
    
    # Keep legacy PathsTableModel interface to maintain compatibility with existing code
PathsTableModel = PathsTreeModel
