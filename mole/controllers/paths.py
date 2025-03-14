from __future__          import annotations
from ..common.log      import Logger
from ..common.parse    import LogicalExpressionParser
from ..core.data       import Path, InstructionHelper
from ..models.config   import ConfigModel
from ..services.slicer import MediumLevelILBackwardSlicerThread
from ..views.graph     import GraphWidget
from ..views.sidebar   import SidebarView
from ..views.paths_tree import PathsTreeView
from typing            import Dict, List, Tuple, Optional
import binaryninja       as bn
import copy              as copy
import difflib           as difflib
import hashlib           as hashlib
import json              as json
import os                as os
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
        self._paths_view: Optional[PathsTreeView] = None
        self._paths_highlight: Tuple[
            Path,
            Dict[int, Tuple[bn.MediumLevelILInstruction, bn.HighlightColor]]
        ] = (None, {})
        self._config_path: str = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "../../conf/"
        )
        view.set_controller(self)
    
    @property
    def paths(self) -> List[Path]:
        """
        Get all paths from either the internal list or the view, if available.
        """
        if self._paths_view and self._paths_view.model.path_count > 0:
            return self._paths_view.get_all_paths()
        return self._paths
    
    def add_path_to_view(
            self,
            path: Path,
            comment: str = ""
        ) -> None:
        """
        This method updates the UI with a newly identified path.
        """
        def update_paths_view() -> None:
            if not self._paths_view:
                self._paths.append(path)
                return
                
            # Get current grouping strategy from settings
            grouping_strategy = None
            settings = self._model.get().settings
            if "grouping_strategy" in settings:
                strategy_value = settings["grouping_strategy"].value
                # Strategy value is already a string, use directly
                grouping_strategy = strategy_value
                
            # Update the model directly - the view will update automatically
            self._paths_view.model.add_path(path, comment, grouping_strategy)
            return
        
        bn.execute_on_main_thread(update_paths_view)
        return

    def find_paths(
            self,
            bv: bn.BinaryView,
            view: PathsTreeView = None
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
        if view:
            self._paths_view = view
        # Run background thread
        self._thread = MediumLevelILBackwardSlicerThread(
            bv=bv,
            model=self._model,
            tag=f"{self._tag:s}.Slicer",
            log=self._log,
            found_path_callback=self.add_path_to_view
        )
        self._thread.start()
        return None
    
    def load_paths(
            self,
            bv: bn.BinaryView,
            view: PathsTreeView
        ) -> None:
        """
        This method loads paths from the binary's database.
        """
        if not view: 
            return
        self._view.give_feedback("Load", "Loading Paths...")
        # Clear paths
        self._paths = []
        self._paths_view = view
        self._paths_view.clear()
        
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
                
                # Update model directly instead of through the view
                grouping_strategy = None
                settings = self._model.get().settings
                if "grouping_strategy" in settings:
                    strategy_value = settings["grouping_strategy"].value
                    # Strategy value is already a string, use directly
                    grouping_strategy = strategy_value
                
                self._paths_view.model.add_path(path, s_path.get("comment", ""), grouping_strategy)
                
            self._log.info(self._tag, f"Loaded {len(s_paths):d} path(s)")
        except KeyError:
            self._log.info(self._tag, "No paths found")
        except Exception as e:
            self._log.error(self._tag, f"Failed to load paths: {str(e):s}")
        return
    
    def import_paths(
            self,
            bv: bn.BinaryView
        ) -> None:
        """
        This method imports paths from a file.
        """
        if not self._paths_view: 
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
                if filepath.lower().endswith((".yml", ".yaml")):
                    s_paths = yaml.safe_load(f)
                else:
                    s_paths = json.load(f)
                    
            if not isinstance(s_paths, list):
                self._log.error(self._tag, f"Invalid paths format in {filepath}")
                return
                
            # Calculate SHA1 hash
            sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
            
            # Deserialize paths
            imported_count = 0
            for s_path in s_paths:
                try:
                    if s_path.get("sha1") != sha1_hash:
                        self._log.warn(self._tag, "Loaded path seems to origin from another binary")
                    path = Path.from_dict(bv, s_path)
                    self.add_path_to_view(path, s_path.get("comment", ""))
                    imported_count += 1
                except Exception as e:
                    self._log.warn(self._tag, f"Could not import path: {str(e)}")
                    
            self._log.info(self._tag, f"Imported {imported_count:d} path(s)")
            
        except Exception as e:
            self._log.error(self._tag, f"Failed to import paths: {str(e):s}")
        return
    
    def save_paths(
            self,
            bv: bn.BinaryView
        ) -> None:
        """
        This method stores paths to the binary's database.
        """
        if not self._paths_view: 
            return
        self._view.give_feedback("Save", "Saving Paths...")
        try:
            # Calculate SHA1 hash of binary
            sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
            # Serialize paths
            s_paths: List[Dict] = []
            paths = self._paths_view.get_all_paths()
            comments = self._paths_view.model.get_comments()
            
            for idx, path in enumerate(paths):
                s_path = path.to_dict()
                s_path["comment"] = comments.get(idx, "")
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
            rows: List[int]
        ) -> None:
        """
        This method exports paths to a file.
        """
        if not self._paths_view: 
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
        comments = self._paths_view.model.get_comments()
        
        # Only include valid path rows (filtering out header/group items)
        valid_paths = []
        for row in (rows if rows else list(range(len(self._paths_view.model.paths)))):
            path = self._paths_view.path_at_row(row)
            if path:  # Only include rows that correspond to actual paths
                valid_paths.append((row, path))
        
        # Now export each valid path
        for row, path in valid_paths:
            s_path = path.to_dict()
            path_id = row  # row here is actually the path_id from the valid_paths list
            s_path["comment"] = comments.get(path_id, "")
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
            rows: List[int],
            reverse: bool = False
        ) -> None:
        """
        This method logs information about a path.
        """
        if not self._paths_view: 
            return
        if len(rows) != 1: 
            return
        
        path = self._paths_view.path_at_row(rows[0])
        if not path: 
            return
        
        path_id = rows[0]
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
            rows: List[int]
        ) -> None:
        """
        This method logs the difference between two paths.
        """
        if not self._paths_view: 
            return
        if len(rows) != 2: 
            return

        # Get instructions of path 0
        path_0 = self._paths_view.path_at_row(rows[0])
        if not path_0: 
            return
        path_0_id = rows[0]
        path_0_insts = [InstructionHelper.get_inst_info(inst, False) for inst in path_0.insts]

        # Get instructions of path 1
        path_1 = self._paths_view.path_at_row(rows[1])
        if not path_1: 
            return
        path_1_id = rows[1]
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
            rows: List[int]
        ) -> None:
        """
        This method highlights all instructions in a path.
        """
        if not self._paths_view: 
            return
        if len(rows) != 1: 
            return
        
        path = self._paths_view.path_at_row(rows[0])
        if not path: 
            return
            
        undo_action = bv.begin_undo_actions()
        highlighted_path, insts_colors = self._paths_highlight
        
        # Undo previous path highlighting
        for addr, (inst, old_color) in insts_colors.items():
            func = inst.function.source_function
            func.set_user_instr_highlight(addr, old_color)
        
        # Clear the highlight tracking data
        self._paths_highlight = (None, {})
        
        # If the clicked path was already highlighted, just log and return (it's now unhighlighted)
        if path == highlighted_path:
            self._log.info(self._tag, f"Un-highlighted instructions of path {rows[0]:d}")
            bv.forget_undo_actions(undo_action)
            return
        
        # Add new path highlighting
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
            rows: List[int],
            wid: qtw.QTabWidget
        ) -> None:
        """
        This method shows the call graph of a path.
        """
        if not self._paths_view: 
            return
        if len(rows) != 1: 
            return
            
        path = self._paths_view.path_at_row(rows[0])
        if not path: 
            return
            
        for idx in range(wid.count()):
            if wid.tabText(idx) == "Graph":
                graph_widget: GraphWidget = wid.widget(idx)
                graph_widget.load_path(bv, path, rows[0])
                wid.setCurrentWidget(graph_widget)
                return
                
        self._log.info(self._tag, f"Showing call graph of path {rows[0]:d}")
        return

    def remove_selected_paths(
            self,
            rows: List[int]
        ) -> None:
        """
        This method removes the paths at rows `rows` from the view.
        """
        if not self._paths_view: 
            return
            
        self._paths_view.remove_paths_at_rows(rows)
        self._log.info(self._tag, f"Removed {len(rows):d} path(s)")
        return
    
    def remove_all_paths(self) -> None:
        """
        This method removes all paths from the view.
        """
        if self._paths_view:
            self._paths_view.clear()
        else:
            self._paths.clear()
            
        self._log.info(self._tag, "Removed all path(s)")
        return

    def setup_paths_tree(self, bv: bn.BinaryView, view: PathsTreeView, tab_widget: qtw.QTabWidget = None) -> None:
        """
        This method sets up the path tree view with controller callbacks.
        """
        if not view:
            return
            
        # Store reference to the view 
        self._paths_view = view
        
        # Set up context menu
        view.setup_context_menu(
            on_log_path=self.log_path,
            on_log_path_diff=self.log_path_diff,
            on_highlight_path=lambda rows: self.highlight_path(bv, rows),
            on_show_call_graph=lambda rows: self.show_call_graph(bv, rows, tab_widget),
            on_import_paths=lambda: self.import_paths(bv),
            on_export_paths=lambda rows: self.export_paths(bv, rows),
            on_remove_selected=self.remove_selected_paths,
            on_remove_all=self.remove_all_paths,
            bv=bv
        )
        
        # Set up navigation
        view.setup_navigation(bv)
        
        # Expand all nodes by default
        view.expandAll()
        
        return