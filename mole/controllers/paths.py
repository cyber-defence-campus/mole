from __future__          import annotations
from ..common.log      import Logger
from ..common.parse    import LogicalExpressionParser
from ..core.data       import Path, InstructionHelper
from ..models.config   import ConfigModel
from ..services.slicer import MediumLevelILBackwardSlicerThread
from ..views.graph     import GraphWidget
from ..views.sidebar   import SidebarView
from ..views.utils     import IntTableWidgetItem
from typing            import Dict, List, Tuple
import binaryninja       as bn
import copy              as copy
import difflib           as difflib
import hashlib           as hashlib
import json              as json
import os                as os
import PySide6.QtCore    as qtc
import PySide6.QtWidgets as qtw
import shutil            as shu
import yaml              as yaml


class PathController:
    """
    This class implements a controller to handle paths.
    """

    def __init__(
            self,
            view: SidebarView,
            model: ConfigModel,
            tag: str,
            log: Logger
        ) -> None:
        """
        This method initializes a controller (MVC pattern).
        """
        self._view = view
        self._model = model
        self._tag = tag
        self._log = log
        self._thread: MediumLevelILBackwardSlicerThread = None
        self._parser: LogicalExpressionParser = LogicalExpressionParser(tag, log)
        self._paths: List[Path] = []
        self._paths_widget: qtw.QTableWidget = None
        self._paths_highlight: Tuple[
            Path,
            Dict[int, Tuple[bn.MediumLevelILInstruction, bn.HighlightColor]]
        ] = (None, {})
        self._config_path: str = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "../../conf/"
        )
        return
    
    @property
    def paths(self) -> List[Path]:
        return self._paths
    
    def add_path_to_view(
            self,
            path: Path,
            comment: str = ""
        ) -> None:
        """
        This method updates the UI with a newly identified path.
        """
        def update_paths_widget() -> None:
            self._paths.append(path)
            if not self._paths_widget:
                return
            row = self._paths_widget.rowCount()
            self._paths_widget.setSortingEnabled(False)
            self._paths_widget.insertRow(row)
            path_idx = IntTableWidgetItem(row, as_hex=False)
            path_idx.setFlags(qtc.Qt.ItemIsSelectable | qtc.Qt.ItemIsEnabled)
            self._paths_widget.setItem(row, 0, path_idx)
            src_addr = IntTableWidgetItem(path.src_sym_addr, as_hex=True)
            src_addr.setFlags(qtc.Qt.ItemIsSelectable | qtc.Qt.ItemIsEnabled)
            self._paths_widget.setItem(row, 1, src_addr)
            src_name = qtw.QTableWidgetItem(path.src_sym_name)
            src_name.setFlags(qtc.Qt.ItemIsSelectable | qtc.Qt.ItemIsEnabled)
            self._paths_widget.setItem(row, 2, src_name)
            snk_addr = IntTableWidgetItem(path.snk_sym_addr, as_hex=True)
            snk_addr.setFlags(qtc.Qt.ItemIsSelectable | qtc.Qt.ItemIsEnabled)
            self._paths_widget.setItem(row, 3, snk_addr)
            snk_name = qtw.QTableWidgetItem(path.snk_sym_name)
            snk_name.setFlags(qtc.Qt.ItemIsSelectable | qtc.Qt.ItemIsEnabled)
            self._paths_widget.setItem(row, 4, snk_name)
            snk_parm = qtw.QTableWidgetItem(f"arg#{path.snk_par_idx:d}:{str(path.snk_par_var):s}")
            snk_parm.setFlags(qtc.Qt.ItemIsSelectable | qtc.Qt.ItemIsEnabled)
            self._paths_widget.setItem(row, 5, snk_parm)
            lines = IntTableWidgetItem(len(path.insts), as_hex=False)
            lines.setFlags(qtc.Qt.ItemIsSelectable | qtc.Qt.ItemIsEnabled)
            self._paths_widget.setItem(row, 6, lines)
            phiis = IntTableWidgetItem(len(path.phiis), as_hex=False)
            phiis.setFlags(qtc.Qt.ItemIsSelectable | qtc.Qt.ItemIsEnabled)
            self._paths_widget.setItem(row, 7, phiis)
            bdeps = IntTableWidgetItem(len(path.bdeps), as_hex=False)
            bdeps.setFlags(qtc.Qt.ItemIsSelectable | qtc.Qt.ItemIsEnabled)
            self._paths_widget.setItem(row, 8, bdeps)
            cmnt = qtw.QTableWidgetItem(comment)
            self._paths_widget.setItem(row, 9, cmnt)
            self._paths_widget.setSortingEnabled(True)
            return
        
        bn.execute_on_main_thread(update_paths_widget)
        return

    def find_paths(
            self,
            bv: bn.BinaryView,
            max_workers: int | None = None,
            max_call_level: int = None,
            max_slice_depth: int = None,
            enable_all_funs: bool = False,
            tbl: qtw.QTableWidget = None
        ) -> None | List[Path]:
        """
        This method analyzes the entire binary for interesting looking code paths.
        """
        # Require a binary to be loaded
        if not bv:
            self._log.warn(self._tag, "No binary loaded.")
            self._view.give_feedback("Find", "No Binary Loaded...")
            return
        # Require the binary to be in mapped view
        if bv.view_type == "Raw":
            self._log.warn(self._tag, "Binary is in Raw view.")
            self._view.give_feedback("Find", "Binary is in Raw View...")
            return
        # Require previous analyses to complete
        if self._thread and not self._thread.finished:
            self._log.warn(self._tag, "Analysis already running.")
            self._view.give_feedback("Find", "Analysis Already Running...")
            return
        # Initialize new logger to detect newly attached debugger
        self._log = Logger(self._log.get_level(), False)
        self._view.give_feedback("Find", "Finding Paths...")
        # Initialize data structures
        if tbl:
            self._paths_widget = tbl
        # Run background thread
        self._thread = MediumLevelILBackwardSlicerThread(
            bv=bv,
            model=self._model,
            tag=f"{self._tag:s}.Slicer",
            log=self._log,
            found_path_callback=self.add_path_to_view,
            max_workers=max_workers,
            max_call_level=max_call_level,
            max_slice_depth=max_slice_depth,
            enable_all_funs=enable_all_funs
        )
        self._thread.start()
        return None
    
    def load_paths(
            self,
            bv: bn.BinaryView,
            tbl: qtw.QTableWidget
        ) -> None:
        """
        This method loads paths from the binary's database.
        """
        if not tbl: 
            return
        self._view.give_feedback("Load", "Loading Paths...")
        # Clear paths
        self._paths = []
        self._paths_widget = tbl
        self._paths_widget.setRowCount(0)
        # Load paths from database
        try:
            # Calculate SHA1 hash
            sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
            # Deserialize paths
            s_paths: List[Dict] = bv.query_metadata("mole_paths")
            for s_path in s_paths:
                if s_path["sha1"] != sha1_hash:
                    self._log.warn(self._tag, "Loaded path seems to origin from another binary")
                path = Path.from_dict(bv, s_path)
                self.add_path_to_view(path, s_path["comment"])
            self._log.info(self._tag, f"Loaded {len(s_paths):d} path(s)")
        except KeyError:
            self._log.info(self._tag, "No paths found")
        except Exception as e:
            self._log.error(self._tag, f"Failed to load paths: {str(e):s}")
        return
    
    def import_paths(
            self,
            bv: bn.BinaryView,
            tbl: qtw.QTableWidget
        ) -> None:
        """
        This method imports paths from a file.
        """
        if not tbl: 
            return
        # Select file
        filepath, _ = qtw.QFileDialog.getOpenFileName(
            None,
            "Open File",
            "",
            "JSON Files (*.json);;YAML Files (*.yml *.yaml)"
        )
        if not filepath:
            self._log.info(self._tag, "No paths imported")
            return
        # Open file
        try:
            # Load YAML or JSON data
            with open(filepath, "r") as f:
                if filepath.lower().endswith(".yml") or filepath.lower().endswith(".yaml"):
                    s_paths = yaml.safe_load(f)
                else:
                    s_paths = json.load(f)
            # Append paths
            self._paths_widget = tbl
            # Calculate SHA1 hash
            sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
            # Deserialize paths
            for s_path in s_paths:
                if s_path["sha1"] != sha1_hash:
                    self._log.warn(self._tag, "Loaded path seems to origin from another binary")
                path = Path.from_dict(bv, s_path)
                self.add_path_to_view(path, s_path["comment"])
            self._log.info(self._tag, f"Imported {len(s_paths):d} path(s)")
        except Exception as e:
            self._log.error(self._tag, f"Failed to import paths: {str(e):s}")
        return
    
    def save_paths(
            self,
            bv: bn.BinaryView,
            tbl: qtw.QTableWidget
        ) -> None:
        """
        This method stores paths to the binary's database.
        """
        if not tbl: 
            return
        self._view.give_feedback("Save", "Saving Paths...")
        try:
            # Calculate SHA1 hash of binary
            sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
            # Serialize paths
            s_paths: List[Dict] = []
            for row in range(tbl.rowCount()):
                path_id = tbl.item(row, 0).data(qtc.Qt.ItemDataRole.UserRole)
                path: Path = self._paths[path_id]
                s_path = path.to_dict()
                s_path["comment"] = tbl.item(row, 9).text()
                s_path["sha1"] = sha1_hash
                s_paths.append(s_path)
            bv.store_metadata("mole_paths", s_paths)
            self._log.info(self._tag, f"Saved {len(s_paths):d} path(s)")
        except Exception as e:
            self._log.error(self._tag, f"Failed to save paths: {str(e):s}")
        return
    
    def export_paths(
            self,
            bv: bn.BinaryView,
            tbl: qtw.QTableWidget,
            rows: List[int]
        ) -> None:
        """
        This method exports paths to a file.
        """
        if not tbl: 
            return
        # Select file
        filepath, _ = qtw.QFileDialog.getSaveFileName(
            None,
            "Save As",
            "",
            "JSON Files (*.json);;YAML Files (*.yml *.yaml)"
        )
        if not filepath:
            self._log.error(self._tag, "No paths exported")
            return
        # Calculate SHA1 hash of binary
        sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
        # Serialize paths
        s_paths: List[Dict] = []
        for row in (rows if rows else range(tbl.rowCount())):
            path_id = tbl.item(row, 0).data(qtc.Qt.ItemDataRole.UserRole)
            path: Path = self._paths[path_id]
            s_path = path.to_dict()
            s_path["comment"] = tbl.item(row, 9).text()
            s_path["sha1"] = sha1_hash
            s_paths.append(s_path)
        # Open file
        with open(filepath, "w") as f:
            # Write YAML data
            if filepath.lower().endswith(".yml") or filepath.lower().endswith(".yaml"):
                yaml.safe_dump(
                    s_paths,
                    f,
                    sort_keys=False,
                    default_style=None,
                    default_flow_style=False,
                    encoding="utf-8"
                )
            # Write JSON data (default)
            else:
                json.dump(
                    s_paths,
                    f,
                    indent=2
                )
        self._log.info(self._tag, f"Exported {len(s_paths):d} path(s)")
        return
    
    def log_path(
            self,
            tbl: qtw.QTableWidget,
            rows: List[int],
            reverse: bool = False
        ) -> None:
        """
        This method logs information about a path.
        """
        if not tbl: 
            return
        if len(rows) != 1: 
            return
        path_id = tbl.item(rows[0], 0).data(qtc.Qt.ItemDataRole.UserRole)
        path = self._paths[path_id]
        if not path: 
            return
        msg = f"Path {path_id:d}: {str(path):s}"
        msg = f"{msg:s} [L:{len(path.insts):d},P:{len(path.phiis):d},B:{len(path.bdeps):d}]!"
        self._log.info(self._tag, msg)
        if reverse:
            self._log.debug(self._tag, "--- Forward  Slice ---")
            insts = reversed(path.insts)
        else:
            self._log.debug(self._tag, "--- Backward Slice ---")
            insts = path.insts
        basic_block = None
        for inst in insts:
            if inst.il_basic_block != basic_block:
                basic_block = inst.il_basic_block
                fun_name = basic_block.function.name
                bb_addr = basic_block[0].address
                self._log.debug(self._tag, f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}")
            self._log.debug(self._tag, InstructionHelper.get_inst_info(inst))
        self._log.debug(self._tag, "----------------------")
        self._log.debug(self._tag, msg)
        return
    
    def log_path_diff(
            self,
            tbl: qtw.QTableWidget,
            rows: List[int]
        ) -> None:
        """
        This method logs the difference between two paths.
        """
        if not tbl: 
            return
        if len(rows) != 2: 
            return

        # Get instructions of path 0
        path_0_id = tbl.item(rows[0], 0).data(qtc.Qt.ItemDataRole.UserRole)
        path_0: Path = self._paths[path_0_id]
        if not path_0: 
            return
        path_0_insts = [InstructionHelper.get_inst_info(inst, False) for inst in path_0.insts] 

        # Get instructions of path 1
        path_1_id = tbl.item(rows[1], 0).data(qtc.Qt.ItemDataRole.UserRole)
        path_1: Path = self._paths[path_1_id]
        if not path_1: 
            return
        path_1_insts = [InstructionHelper.get_inst_info(inst, False) for inst in path_1.insts]

        # Get terminal width and calculate column width
        ter_width = shu.get_terminal_size().columns
        col_width = ter_width // 2 - 2

        # Compare paths
        lft_col = []
        rgt_col = []
        diff = difflib.ndiff(path_0_insts, path_1_insts)
        path_0_msg = f"Path {path_0_id:d}: {str(path_0):s}"
        path_0_msg = f"{path_0_msg:s} [L:{len(path_0.insts):d},P:{len(path_0.phiis):d},B:{len(path_0.bdeps):d}]!"
        lft_col.append(path_0_msg)
        lft_col.append("----")
        path_1_msg = f"Path {path_1_id:d}: {str(path_1):s}"
        path_1_msg = f"{path_1_msg:s} [L:{len(path_1.insts):d},P:{len(path_1.phiis):d},B:{len(path_1.bdeps):d}]!"
        rgt_col.append(path_1_msg)
        rgt_col.append("----")
        for line in diff:
            if line.startswith("- "):
                lft_col.append(line[2:])
                rgt_col.append("")
            elif line.startswith("+ "):
                lft_col.append("")
                rgt_col.append(line[2:])
            elif line.startswith("? "):
                continue
            else:
                lft_col.append(line[2:])
                rgt_col.append(line[2:])

        # Log differences side by side
        for lft, rgt in zip(lft_col, rgt_col):
            self._log.debug(
                self._tag,
                f"{lft:<{col_width}} | {rgt:<{col_width}}"
            )
        return
    
    def highlight_path(
            self,
            bv: bn.BinaryView,
            tbl: qtw.QTableWidget,
            rows: List[int]
        ) -> None:
        """
        This method highlights all instructions in a path.
        """
        if not tbl: 
            return
        if len(rows) != 1: 
            return
        path_id = tbl.item(rows[0], 0).data(qtc.Qt.ItemDataRole.UserRole)
        path = self._paths[path_id]
        if not path: 
            return
        undo_action = bv.begin_undo_actions()
        highlighted_path, insts_colors = self._paths_highlight
        # Undo path highlighting
        for addr, (inst, old_color) in insts_colors.items():
            func = inst.function.source_function
            func.set_user_instr_highlight(addr, old_color)
        self._log.info(self._tag, "Un-highlighted instructions of all paths")
        # Remove path highlighting
        if path == highlighted_path:
            highlighted_path = None
            insts_colors = {}
        # Add path highlighting
        else:
            highlighted_path = path
            insts_colors = {}
            try:
                model = self._model.get()
                color_name = model.settings.get("highlight_color").widget.currentText().capitalize()
                color = bn.HighlightStandardColor[f"{color_name:s}HighlightColor"]
            except Exception as _:
                color = bn.HighlightStandardColor.RedHighlightColor
            for inst in path.insts:
                func = inst.function.source_function
                addr = inst.address
                if addr not in insts_colors:
                    insts_colors[addr] = (inst, func.get_instr_highlight(addr))
                func.set_user_instr_highlight(addr, color)
            self._log.info(self._tag, f"Highlighted instructions of path {rows[0]:d}")
        self._paths_highlight = (highlighted_path, insts_colors)
        bv.forget_undo_actions(undo_action)
        return
    
    def show_call_graph(
            self,
            bv: bn.BinaryView,
            tbl: qtw.QTableWidget,
            rows: List[int],
            wid: qtw.QTabWidget
        ) -> None:
        """
        This method shows the call graph of a path.
        """
        if not tbl: 
            return
        if len(rows) != 1: 
            return
        path_id = tbl.item(rows[0], 0).data(qtc.Qt.ItemDataRole.UserRole)
        path = self._paths[path_id]
        if not path: 
            return
        for idx in range(wid.count()):
            if wid.tabText(idx) == "Graph":
                graph_widget: GraphWidget = wid.widget(idx)
                graph_widget.load_path(bv, path, path_id)
                wid.setCurrentWidget(graph_widget)
                return
        self._log.info(self._tag, f"Showing call graph of path {rows[0]:d}")
        return

    def remove_selected_paths(
            self,
            tbl: qtw.QTableWidget,
            rows: List[int]
        ) -> None:
        """
        This method removes the paths at rows `rows` from the table `tbl`.
        """
        if not tbl: 
            return
        for c, row in enumerate(sorted(rows, reverse=True)):
            if row < 0: 
                continue
            path_id = tbl.item(row, 0).data(qtc.Qt.ItemDataRole.UserRole)
            del self._paths[path_id-c]
            tbl.removeRow(row)
        for row in range(tbl.rowCount()):
            tbl.setItem(row, 0, IntTableWidgetItem(row, as_hex=False))
        self._log.info(self._tag, f"Removed {len(rows):d} path(s)")
        return
    
    def remove_all_paths(
            self,
            tbl: qtw.QTableWidget = None
        ) -> None:
        """
        This method removes all paths from the table `tbl`.
        """
        self._paths.clear()
        if tbl:
            tbl.setRowCount(0)
        self._log.info(self._tag, "Removed all path(s)")
        return