from __future__        import annotations
from ..core.data       import Path, InstructionHelper
from ..services.slicer import MediumLevelILBackwardSlicerThread
from ..views.graph     import GraphWidget
from ..views.path      import PathView
from ..views.path_tree import PathTreeView
from .config           import ConfigController
from mole.common.log   import log
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


tag = "Mole.Path"


class PathController:
    """
    This class implements a controller to handle paths.
    """

    def __init__(
            self,
            config_ctr: ConfigController,
            path_view: PathView
        ) -> None:
        """
        This method initializes a controller (MVC pattern).
        """
        # Initialization
        self.config_ctr = config_ctr
        self.path_view = path_view
        self._paths: List[Path] = []
        self._paths_highlight: Tuple[
            Path,
            Dict[int, Tuple[bn.MediumLevelILInstruction, bn.HighlightColor]]
        ] = (None, {})
        self._thread: Optional[MediumLevelILBackwardSlicerThread] = None
        self.path_tree_view: Optional[PathTreeView] = None
        # Connect signals
        self.connect_signal_find_paths(self.find_paths)
        self.connect_signal_load_paths(self.load_paths)
        self.connect_signal_save_paths(self.save_paths)
        self.connect_signal_setup_paths_tree(self.setup_path_tree)
        self.config_ctr.connect_signal_change_path_grouping(self._change_path_grouping)
        return
    
    def connect_signal_find_paths(self, slot: object) -> None:
        """
        This method allows connecting to the signal that is triggered when paths should be found.
        """
        self.path_view.signal_find_paths.connect(slot)
        return
    
    def connect_signal_load_paths(self, slot: object) -> None:
        """
        This method allows connecting to the signal that is triggered when paths should be loaded.
        """
        self.path_view.signal_load_paths.connect(slot)
        return
    
    def connect_signal_save_paths(self, slot: object) -> None:
        """
        This method allows connecting to the signal that is triggered when paths should be saved.
        """
        self.path_view.signal_save_paths.connect(slot)
        return
    
    def connect_signal_setup_paths_tree(self, slot: object) -> None:
        """
        This method allows connecting to the signal that is triggered when the Binary View changes.
        """
        self.path_view.signal_setup_path_tree.connect(slot)
        return

    def _change_path_grouping(self, new_strategy: str) -> None:
        """
        Handler for when grouping strategy changes in the config.
        Regroups all paths with the new strategy.
        """
        if self.path_tree_view and self.path_tree_view.model.path_count > 0:
            log.info(tag, f"Regrouping paths with new strategy: {new_strategy}")
            self.path_tree_view.model.regroup_paths(new_strategy)
    
    @property
    def paths(self) -> List[Path]:
        """
        Get all paths from either the internal list or the view, if available.
        """
        if self.path_tree_view and self.path_tree_view.model.path_count > 0:
            return self.path_tree_view.get_all_paths()
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
            if not self.path_tree_view:
                self._paths.append(path)
                return
                
            # Get current path grouping strategy from settings
            path_grouping = None
            setting = self.config_ctr.get_setting("path_grouping")
            if setting:
                path_grouping = setting.value
                
            # Update the model directly - the view will update automatically
            self.path_tree_view.model.add_path(path, comment, path_grouping)
            return
        
        bn.execute_on_main_thread(update_paths_view)
        return

    def find_paths(
            self,
            bv: bn.BinaryView,
            view: PathTreeView = None
        ) -> None | List[Path]:
        """
        This method analyzes the entire binary for interesting looking code paths.
        """
        # Require a binary to be loaded
        if not bv:
            log.warn(tag, "No binary loaded.")
            self.path_view.give_feedback("Find", "No Binary Loaded...")
            return
        # Require the binary to be in mapped view
        if bv.view_type == "Raw":
            log.warn(tag, "Binary is in Raw view.")
            self.path_view.give_feedback("Find", "Binary is in Raw View...")
            return
        # Require previous analyses to complete
        if self._thread and not self._thread.finished:
            log.warn(tag, "Analysis already running.")
            self.path_view.give_feedback("Find", "Analysis Already Running...")
            return
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Initialize data structures
        if view:
            self.path_tree_view = view
        # Run background thread
        self.path_view.give_feedback("Find", "Finding Paths...")
        self._thread = MediumLevelILBackwardSlicerThread(
            bv=bv,
            model=self.config_ctr.config_model,
            found_path_callback=self.add_path_to_view
        )
        self._thread.start()
        return None
    
    def load_paths(
            self,
            bv: bn.BinaryView,
            view: PathTreeView
        ) -> None:
        """
        This method loads paths from the binary's database.
        """
        if not view: 
            return
        self.path_view.give_feedback("Load", "Loading Paths...")
        # Clear paths
        self._paths = []
        self.path_tree_view = view
        self.path_tree_view.clear()
        
        # Load paths from database
        try:
            # Calculate SHA1 hash
            sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
            # Deserialize paths
            s_paths: List[Dict] = bv.query_metadata("mole_paths")
            for s_path in s_paths:
                if s_path["sha1"] != sha1_hash:
                    log.warn(tag, "Loaded path seems to origin from another binary")
                path = Path.from_dict(bv, s_path)
                
                # Update model directly instead of through the view
                path_grouping = None
                setting = self.config_ctr.get_setting("path_grouping")
                if setting:
                    path_grouping = setting.value
                
                self.path_tree_view.model.add_path(path, s_path.get("comment", ""), path_grouping)
                
            log.info(tag, f"Loaded {len(s_paths):d} path(s)")
        except KeyError:
            log.info(tag, "No paths found")
        except Exception as e:
            log.error(tag, f"Failed to load paths: {str(e):s}")
        return
    
    def import_paths(
            self,
            bv: bn.BinaryView
        ) -> None:
        """
        This method imports paths from a file.
        """
        if not self.path_tree_view: 
            return
        # Select file
        filepath, _ = qtw.QFileDialog.getOpenFileName(
            None,
            "Open File",
            "",
            "JSON Files (*.json);;YAML Files (*.yml *.yaml)"
        )
        if not filepath:
            log.info(tag, "No paths imported")
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
                log.error(tag, f"Invalid paths format in {filepath}")
                return
                
            # Calculate SHA1 hash
            sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
            
            # Deserialize paths
            imported_count = 0
            for s_path in s_paths:
                try:
                    if s_path.get("sha1") != sha1_hash:
                        log.warn(tag, "Loaded path seems to origin from another binary")
                    path = Path.from_dict(bv, s_path)
                    self.add_path_to_view(path, s_path.get("comment", ""))
                    imported_count += 1
                except Exception as e:
                    log.warn(tag, f"Could not import path: {str(e)}")
                    
            log.info(tag, f"Imported {imported_count:d} path(s)")
            
        except Exception as e:
            log.error(tag, f"Failed to import paths: {str(e):s}")
        return
    
    def save_paths(
            self,
            bv: bn.BinaryView
        ) -> None:
        """
        This method stores paths to the binary's database.
        """
        if not self.path_tree_view: 
            return
        self.path_view.give_feedback("Save", "Saving Paths...")
        try:
            # Calculate SHA1 hash of binary
            sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
            # Serialize paths
            s_paths: List[Dict] = []
            paths = self.path_tree_view.get_all_paths()
            comments = self.path_tree_view.model.get_comments()
            
            for idx, path in enumerate(paths):
                s_path = path.to_dict()
                s_path["comment"] = comments.get(idx, "")
                s_path["sha1"] = sha1_hash
                s_paths.append(s_path)
                
            bv.store_metadata("mole_paths", s_paths)
            log.info(tag, f"Saved {len(s_paths):d} path(s)")
        except Exception as e:
            log.error(tag, f"Failed to save paths: {str(e):s}")
        return
    
    def export_paths(
            self,
            bv: bn.BinaryView,
            rows: List[int]
        ) -> None:
        """
        This method exports paths to a file.
        """
        if not self.path_tree_view: 
            return
        # Select file
        filepath, _ = qtw.QFileDialog.getSaveFileName(
            None,
            "Save As",
            "",
            "JSON Files (*.json);;YAML Files (*.yml *.yaml)"
        )
        if not filepath:
            log.error(tag, "No paths exported")
            return
        # Calculate SHA1 hash of binary
        sha1_hash = hashlib.sha1(bv.file.raw.read(0, bv.file.raw.end)).hexdigest()
        # Serialize paths
        s_paths: List[Dict] = []
        comments = self.path_tree_view.model.get_comments()
        
        # Only include valid path rows (filtering out header/group items)
        valid_paths = []
        for row in (rows if rows else list(range(len(self.path_tree_view.model.paths)))):
            path = self.path_tree_view.path_at_row(row)
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
        log.info(tag, f"Exported {len(s_paths):d} path(s)")
        return
    
    def log_path(
            self,
            rows: List[int],
            reverse: bool = False
        ) -> None:
        """
        This method logs information about a path.
        """
        if not self.path_tree_view or len(rows) != 1:
            return
        
        path = self.path_tree_view.path_at_row(rows[0])
        if not path: 
            return
        
        path_id = rows[0]
        msg = f"Path {path_id:d}: {str(path):s}"
        msg = f"{msg:s} [L:{len(path.insts):d},P:{len(path.phiis):d},B:{len(path.bdeps):d}]!"
        log.info(tag, msg)
        
        if reverse:
            log.debug(tag, "--- Forward  Slice ---")
            insts = reversed(path.insts)
        else:
            log.debug(tag, "--- Backward Slice ---")
            insts = path.insts
            
        basic_block = None
        for inst in insts:
            if inst.il_basic_block != basic_block:
                basic_block = inst.il_basic_block
                fun_name = basic_block.function.name
                bb_addr = basic_block[0].address
                log.debug(tag, f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}")
            log.debug(tag, InstructionHelper.get_inst_info(inst))
        log.debug(tag, "----------------------")
        log.debug(tag, msg)
        return
    
    def log_path_diff(
            self,
            rows: List[int]
        ) -> None:
        """
        This method logs the difference between two paths.
        """
        if not self.path_tree_view or len(rows) != 2: 
            return

        # Get instructions of path 0
        path_0 = self.path_tree_view.path_at_row(rows[0])
        if not path_0: 
            return
        path_0_id = rows[0]
        path_0_insts = [InstructionHelper.get_inst_info(inst, False) for inst in path_0.insts]

        # Get instructions of path 1
        path_1 = self.path_tree_view.path_at_row(rows[1])
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
            log.debug(
                tag,
                f"{lft:<{col_width}} | {rgt:<{col_width}}"
            )
        return
    
    def log_call(
            self,
            rows: List[int],
            reverse: bool = False
        ) -> None:
        """
        This method logs the calls of a path.
        """
        if not self.path_tree_view or len(rows) != 1:
            return
        
        path = self.path_tree_view.path_at_row(rows[0])
        if not path: 
            return
        
        path_id = rows[0]
        msg = f"Path {path_id:d}: {str(path):s}"
        msg = f"{msg:s} [L:{len(path.insts):d},P:{len(path.phiis):d},B:{len(path.bdeps):d}]!"
        log.info(tag, msg)
        
        if reverse:
            log.debug(tag, "--- Forward  Calls ---")
            calls = list(reversed(path.calls))
        else:
            log.debug(tag, "--- Backward Calls ---")
            calls = path.calls
        
        min_call_level = min(calls, key=lambda x: x[2])[2]
        for call_addr, call_name, call_level in calls:
            indent = call_level - min_call_level
            log.debug(tag, f"{'>'*indent:s} 0x{call_addr:x} {call_name:s}")
        log.debug(tag, "----------------------")
        log.debug(tag, msg)
        return
    
    def highlight_path(
            self,
            bv: bn.BinaryView,
            rows: List[int]
        ) -> None:
        """
        This method highlights all instructions in a path.
        """
        if not self.path_tree_view or len(rows) != 1: 
            return
        
        path = self.path_tree_view.path_at_row(rows[0])
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
            log.info(tag, f"Un-highlighted instructions of path {rows[0]:d}")
            bv.forget_undo_actions(undo_action)
            return
        
        # Add new path highlighting
        highlighted_path = path
        insts_colors = {}
        try:
            setting = self.config_ctr.get_setting("highlight_color")
            color_name = setting.widget.currentText().capitalize()
            color = bn.HighlightStandardColor[f"{color_name:s}HighlightColor"]
        except Exception as _:
            color = bn.HighlightStandardColor.RedHighlightColor
            
        for inst in path.insts:
            func = inst.function.source_function
            addr = inst.address
            if addr not in insts_colors:
                insts_colors[addr] = (inst, func.get_instr_highlight(addr))
            func.set_user_instr_highlight(addr, color)
            
        log.info(tag, f"Highlighted instructions of path {rows[0]:d}")
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
        if not self.path_tree_view or len(rows) != 1: 
            return
            
        path = self.path_tree_view.path_at_row(rows[0])
        if not path: 
            return
            
        for idx in range(wid.count()):
            if wid.tabText(idx) == "Graph":
                graph_widget: GraphWidget = wid.widget(idx)
                graph_widget.load_path(bv, path, rows[0])
                wid.setCurrentWidget(graph_widget)
                return
                
        log.info(tag, f"Showing call graph of path {rows[0]:d}")
        return

    def remove_selected_paths(
            self,
            rows: List[int]
        ) -> None:
        """
        This method removes the paths at rows `rows` from the view.
        """
        if not self.path_tree_view: 
            return
            
        self.path_tree_view.remove_paths_at_rows(rows)
        log.info(tag, f"Removed {len(rows):d} path(s)")
        return
    
    def remove_all_paths(self) -> None:
        """
        This method removes all paths from the view.
        """
        if self.path_tree_view:
            self.path_tree_view.clear()
        else:
            self._paths.clear()
            
        log.info(tag, "Removed all path(s)")
        return

    def setup_path_tree(
            self,
            bv: bn.BinaryView,
            path_tree_view: PathTreeView,
            wid: qtw.QTabWidget = None
        ) -> None:
        """
        This method sets up the path tree view with controller callbacks.
        """            
        # Store reference to the view 
        self.path_tree_view = path_tree_view
        
        # Set up context menu
        path_tree_view.setup_context_menu(
            on_log_path=self.log_path,
            on_log_path_diff=self.log_path_diff,
            on_log_call=self.log_call,
            on_highlight_path=lambda rows: self.highlight_path(bv, rows),
            on_show_call_graph=lambda rows: self.show_call_graph(bv, rows, wid),
            on_import_paths=lambda: self.import_paths(bv),
            on_export_paths=lambda rows: self.export_paths(bv, rows),
            on_remove_selected=self.remove_selected_paths,
            on_remove_all=self.remove_all_paths,
            bv=bv
        )
        
        # Set up navigation
        path_tree_view.setup_navigation(bv)
        
        # Expand all nodes by default
        path_tree_view.expandAll()
        
        # Apply current path grouping strategy to any existing paths
        setting = self.config_ctr.get_setting("path_grouping")
        if setting and self.path_tree_view.model.path_count > 0:
            self.path_tree_view.model.regroup_paths(setting.value)
        return