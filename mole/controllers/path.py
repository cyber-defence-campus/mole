from __future__ import annotations
from mole.common.log import Logger
from mole.common.helper.instruction import InstructionHelper
from mole.data.config import ComboboxSetting, SourceFunction, SinkFunction
from mole.data.path import Path
from mole.models.ai import AiVulnerabilityReport
from mole.models.path import PathTreeModel
from mole.services.path import PathService
from PySide6 import QtWidgets as qtw
from typing import cast, Dict, List, Literal, Tuple, TYPE_CHECKING
import binaryninja as bn
import difflib
import hashlib
import ijson
import json
import os

if TYPE_CHECKING:
    from mole.models.path import PathProxyModel
    from mole.views.path import PathView


tag = "Path"


class PathController:
    """
    This class implements a controller for Mole's path.
    """

    def __init__(
        self,
        bv: bn.BinaryView,
        log: Logger,
        path_service: PathService,
        path_proxy_model: PathProxyModel,
        path_view: PathView,
    ) -> None:
        """
        This method initializes the path controller.
        """
        self.bv = bv
        self.log = log
        self.path_service = path_service
        self.path_proxy_model = path_proxy_model
        self.path_view = path_view
        self._auto_update_paths: bool = True
        self._paths_highlight: Tuple[
            Path | None,
            Dict[int, Tuple[bn.MediumLevelILInstruction, bn.HighlightColor]],
        ] = (None, {})
        return

    @property
    def auto_update_paths(self) -> bool:
        """
        This method returns whether automatic updates of paths in the view are enabled.
        """
        return self._auto_update_paths

    @auto_update_paths.setter
    def auto_update_paths(self, enable: bool) -> None:
        """
        This method sets whether automatic updates of paths in the view are enabled.
        """
        if not self._auto_update_paths and enable:
            self.update_paths()
        self._auto_update_paths = enable
        return

    def give_feedback(
        self,
        button_type: Literal["Find", "Load", "Save"] = "Find",
        tmp_text: str = "",
        new_text: str = "",
        msec: int = 1000,
    ) -> None:
        """
        This method gives feedback on the given button.
        """
        match button_type:
            case "Find":
                self.path_view.signal_find_paths_feedback.emit(tmp_text, new_text, msec)
            case "Load":
                self.path_view.signal_load_paths_feedback.emit(tmp_text, new_text, msec)
            case "Save":
                self.path_view.signal_save_paths_feedback.emit(tmp_text, new_text, msec)
        return

    def get_paths(self) -> List[Path]:
        """
        This method gets all paths from the model.
        """
        path_tree_model = cast(PathTreeModel, self.path_proxy_model.sourceModel())
        return path_tree_model.paths

    def get_path_ids(self) -> List[int]:
        """
        This method gets all path IDs from the model.
        """
        path_tree_model = cast(PathTreeModel, self.path_proxy_model.sourceModel())
        return path_tree_model.path_ids

    def get_path(self, path_id: int) -> Path | None:
        """
        This method gets the path with the given `path_id` from the model.
        """
        path_tree_model = cast(PathTreeModel, self.path_proxy_model.sourceModel())
        return path_tree_model.get_path(path_id)

    def add_path(self, path: Path) -> None:
        """
        This method adds the given path to the model.
        """
        path_grouper = self.path_service.get_path_grouper()
        path_tree_model = cast(PathTreeModel, self.path_proxy_model.sourceModel())
        bn.execute_on_main_thread(lambda: path_tree_model.add_path(path, path_grouper))
        return

    def add_path_report(self, path_id: int, ai_report: AiVulnerabilityReport) -> None:
        """
        This method adds the given path's AI-generated report to the model.
        """
        path_tree_model = cast(PathTreeModel, self.path_proxy_model.sourceModel())
        bn.execute_on_main_thread(
            lambda: path_tree_model.add_path_report(path_id, ai_report)
        )
        return

    def update_paths(self) -> None:
        """
        This method updates all paths in the model.
        """
        path_grouper = self.path_service.get_path_grouper()
        path_tree_model = cast(PathTreeModel, self.path_proxy_model.sourceModel())
        path_count = len(path_tree_model.paths)
        if path_count > 0:
            bn.execute_on_main_thread(
                lambda: path_tree_model.update_paths(path_grouper)
            )
        return

    def regroup_paths(self) -> None:
        """
        This method regroups all paths in the model.
        """
        path_grouper = self.path_service.get_path_grouper()
        path_tree_model = cast(PathTreeModel, self.path_proxy_model.sourceModel())
        path_count = len(path_tree_model.paths)
        if path_count > 0:
            bn.execute_on_main_thread(
                lambda: path_tree_model.regroup_paths(path_grouper)
            )
            self.log.info(tag, f"Regrouped {path_count:d} path(s)")
        return

    def clear_paths(self) -> None:
        """
        This method clears all paths from the model.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Clear all paths
        path_tree_model = cast(PathTreeModel, self.path_proxy_model.sourceModel())
        path_count = len(path_tree_model.paths)
        if path_count > 0:
            bn.execute_on_main_thread(path_tree_model.clear_paths)
        self.log.info(tag, f"Cleared {path_count:d} path(s)")
        return

    def find_paths(
        self,
        manual_fun: SourceFunction | SinkFunction | None = None,
        manual_fun_inst: bn.MediumLevelILCall
        | bn.MediumLevelILCallSsa
        | bn.MediumLevelILCallUntyped
        | bn.MediumLevelILCallUntypedSsa
        | bn.MediumLevelILTailcall
        | bn.MediumLevelILTailcallUntyped
        | bn.MediumLevelILTailcallSsa
        | bn.MediumLevelILTailcallUntypedSsa
        | None = None,
        manual_fun_all_code_xrefs: bool = False,
    ) -> None:
        """
        This method searches for paths and adds them to the model/view accordingly.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Find paths in background thread
        self.path_service.find_paths(
            manual_fun=manual_fun,
            manual_fun_inst=manual_fun_inst,
            manual_fun_all_code_xrefs=manual_fun_all_code_xrefs,
            path_callback=self.add_path,
            progress_callback=lambda tmp_text, new_text, msec: self.give_feedback(
                "Find", tmp_text, new_text, msec
            ),
        )
        return

    def find_paths_from_call_inst(
        self,
        inst: bn.MediumLevelILCallSsa
        | bn.MediumLevelILCallUntypedSsa
        | bn.MediumLevelILTailcallSsa
        | bn.MediumLevelILTailcallUntypedSsa,
        fun: SourceFunction | SinkFunction | None = None,
        err_msg: str = "",
        all_code_xrefs: bool = True,
    ) -> str:
        """
        This method finds paths using the given call instruction `inst` as the single source
        (`is_src=True`) or sink (`is_src=False`) function.
        """
        if fun is not None:
            self.find_paths(
                manual_fun=fun,
                manual_fun_inst=inst,
                manual_fun_all_code_xrefs=all_code_xrefs,
            )
        return err_msg

    def load_paths(self) -> None:
        """
        This method loads paths from the binary's database.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Cancel path loading thread if already running
        if self.path_service.is_alive(thread_name="load"):
            self.path_service.cancel(thread_name="load")
            return
        # Ensure no other thread is running
        if self.path_service.is_alive():
            self.log.warn(tag, "Another thread of the path service is still runnning")
            return

        # Define background task
        def _load_paths() -> None:
            self.give_feedback("Load", "", "Cancel [0%]", 0)
            # Clear all existing paths
            self.clear_paths()
            # Load paths from database
            cnt_loaded_paths = 0
            try:
                # Calculate SHA1 hash of binary
                if self.bv.file.raw is not None:
                    sha1_hash = hashlib.sha1(
                        self.bv.file.raw.read(0, self.bv.file.raw.end)
                    ).hexdigest()
                else:
                    sha1_hash = ""
                # Load paths from database
                s_paths: List[Dict] = json.loads(
                    str(self.bv.query_metadata("mole_paths"))
                )
                for i, s_path in enumerate(s_paths, start=1):
                    try:
                        # Check if user cancelled the background task
                        if self.path_service.cancelled(thread_name="load"):
                            break
                        # Compare SHA1 hashes
                        if s_path["sha1_hash"] != sha1_hash:
                            self.log.warn(
                                tag,
                                f"Path #{i:d} seems to origin from another binary",
                            )
                        # Deserialize and add path
                        path = Path.from_dict(self.bv, s_path)
                        if path is not None:
                            self.add_path(path.update())
                            cnt_loaded_paths += 1
                        self.give_feedback(
                            "Load", "", f"Cancel [{i / len(s_paths):.0%}]", 0
                        )
                    except Exception as e:
                        self.log.error(tag, f"Failed to load path #{i:d}: {str(e):s}")
            except KeyError:
                pass
            except Exception as e:
                self.log.error(tag, f"Failed to load paths: {str(e):s}")
            self.give_feedback("Load", "Cancel [Done]", "Load", 1000)
            self.give_feedback("Save", "", "Save", 0)
            self.log.info(tag, f"Loaded {cnt_loaded_paths:d} path(s)")
            return

        # Start background task
        self.path_service.start(
            thread_name="load",
            run=_load_paths,
        )
        return

    def save_paths(self) -> None:
        """
        This method saves paths to the binary's database.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Cancel path saving thread if already running
        if self.path_service.is_alive(thread_name="save"):
            self.path_service.cancel(thread_name="save")
            return

        # Define background task
        def _save_paths() -> None:
            self.give_feedback("Save", "", "Cancel [0%]", 0)
            # Get all existing paths
            paths = self.get_paths()
            # Save paths to database
            cnt_saved_paths = 0
            try:
                s_paths: List[Dict] = []
                for i, path in enumerate(paths, start=1):
                    try:
                        # Check if user cancelled the background task
                        if self.path_service.cancelled(thread_name="save"):
                            break
                        # Serialize paths
                        s_path = path.to_dict()
                        s_paths.append(s_path)
                        # Increment exported path counter
                        cnt_saved_paths += 1
                        self.give_feedback(
                            "Save", "", f"Cancel [{i / len(paths):.0%}]", 0
                        )
                    except Exception as e:
                        self.log.error(tag, f"Failed to save path #{i:d}: {str(e):s}")
                self.bv.store_metadata("mole_paths", json.dumps(s_paths))
            except Exception as e:
                self.log.error(tag, f"Failed to save paths: {str(e):s}")
            self.give_feedback("Save", "Cancel [Done]", "Save", 1000)
            self.log.info(tag, f"Saved {cnt_saved_paths:d} path(s)")
            return

        # Start a background task
        self.path_service.start(
            thread_name="save",
            run=_save_paths,
        )
        return

    def import_paths(self) -> None:
        """
        This method imports paths from a file.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Ensure no other import thread is running
        if self.path_service.is_alive("import"):
            self.log.warn(tag, "Another thread of the path service is still runnning")
            return
        # Open dialog to select file path
        filepath, _ = qtw.QFileDialog.getOpenFileName(
            caption="Open File", filter="JSON Files (*.json);;All Files (*)"
        )
        if not filepath:
            self.log.warn(tag, "No paths imported")
            return
        # Expand file path
        filepath = os.path.abspath(os.path.expanduser(os.path.expandvars(filepath)))

        # Define background task
        def _import_paths() -> None:
            # Import paths from file
            cnt_imported_paths = 0
            try:
                # Calculate SHA1 hash of binary
                if self.bv.file.raw is not None:
                    sha1_hash = hashlib.sha1(
                        self.bv.file.raw.read(0, self.bv.file.raw.end)
                    ).hexdigest()
                else:
                    sha1_hash = ""
                # Count the total number of paths to be imported
                cnt_total_paths = 0
                with open(filepath, "r") as f:
                    for _ in ijson.items(f, "item"):
                        cnt_total_paths += 1
                # Iteratively import paths from the JSON file
                with open(filepath, "r") as f:
                    for i, s_path in enumerate(ijson.items(f, "item"), start=1):
                        try:
                            # Check if user cancelled the background task
                            if self.path_service.cancelled(thread_name="import"):
                                break
                            # Compare SHA1 hashes
                            if s_path["sha1_hash"] != sha1_hash:
                                self.log.warn(
                                    tag,
                                    f"Path #{i:d} seems to origin from another binary",
                                )
                            # Deserialize and add path
                            path = Path.from_dict(self.bv, s_path)
                            if path is not None:
                                self.add_path(path.update())
                                cnt_imported_paths += 1
                        except Exception as e:
                            self.log.error(
                                tag, f"Failed to import path #{i:d}: {str(e):s}"
                            )
            except Exception as e:
                self.log.error(tag, f"Failed to import paths: {str(e):s}")
            self.log.info(tag, f"Imported {cnt_imported_paths:d} path(s)")
            return

        # Start background task
        self.path_service.start(
            thread_name="import",
            run=_import_paths,
        )
        return

    def export_paths(self, path_ids: List[int]) -> None:
        """
        This method exports paths to a file.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Ensure no other export save thread is running
        if self.path_service.is_alive("export"):
            self.log.warn(tag, "Another thread of the path service is still runnning")
            return
        # Open dialog to select file path
        filepath, _ = qtw.QFileDialog.getSaveFileName(
            caption="Save As", filter="JSON Files (*.json);;All Files (*)"
        )
        if not filepath:
            self.log.info(tag, "No paths exported")
            return

        # Define background task
        def _export_paths() -> None:
            nonlocal path_ids
            # Export paths to file
            ident = 2
            cnt_exported_paths = 0
            try:
                # Iteratively export paths to the JSON file
                with open(filepath, "w") as f:
                    path_ids = path_ids if path_ids else self.get_path_ids()
                    f.write("[\n")
                    for i, path_id in enumerate(path_ids, start=1):
                        try:
                            # Check if user cancelled the background task
                            if self.path_service.cancelled(thread_name="export"):
                                break
                            # Get path (filtering out headers/groups)
                            path = self.get_path(path_id)
                            if path is None:
                                continue
                            # Serialize and dump path
                            s_path = path.to_dict()
                            if i != 1:
                                f.write(",\n")
                            f.write(" " * ident)
                            f.write(
                                json.dumps(s_path, indent=ident).replace(
                                    "\n", "\n" + " " * ident
                                )
                            )
                            # Increment exported path counter
                            cnt_exported_paths += 1
                        except Exception as e:
                            self.log.error(
                                tag, f"Failed to export path #{i:d}: {str(e):s}"
                            )
                    f.write("\n]")
            except Exception as e:
                self.log.error(tag, f"Failed to export paths: {str(e):s}")
            self.log.info(tag, f"Exported {cnt_exported_paths:d} path(s)")
            return

        # Start background task
        self.path_service.start(
            thread_name="export",
            run=_export_paths,
        )
        return

    def log_path(self, path_id: int | None, reverse: bool = False) -> None:
        """
        This method logs information about a path.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Print selected path to log
        if path_id is None:
            return
        path = self.get_path(path_id)
        if path is None:
            return
        path_str = str(path)
        if reverse:
            snk, src = [part.strip() for part in path_str.split("<--")]
            path_str = f"{src:s} --> {snk:s}"
        msg = f"Path {path_id:d}: {path_str:s}"
        msg = f"{msg:s} [L:{len(path.insts):d},P:{len(path.phiis):d},B:{len(path.bdeps):d}]!"
        self.log.info(tag, msg)
        if reverse:
            self.log.debug(tag, "--- Forward  Slice ---")
            src_inst_idx = len(path.insts) - path.src_inst_idx
            insts = reversed(path.insts)
        else:
            self.log.debug(tag, "--- Backward Slice ---")
            src_inst_idx = path.src_inst_idx
            insts = path.insts
        basic_block = None
        for i, inst in enumerate(insts):
            call_level = path.call_graph.nodes[inst.function]["level"]
            if (not reverse and i < src_inst_idx) or (reverse and i >= src_inst_idx):
                custom_tag = f"{tag}] [Snk] [{call_level:+d}"
            else:
                custom_tag = f"{tag}] [Src] [{call_level:+d}"
            try:
                inst_basic_block = inst.il_basic_block
                if inst_basic_block != basic_block:
                    basic_block = inst_basic_block
                    fun_name = (
                        basic_block.function.symbol.short_name
                        if basic_block.function is not None
                        else "Unknown"
                    )
                    bb_addr = basic_block[0].address
                    self.log.debug(
                        custom_tag, f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}"
                    )
            except Exception:
                pass
            self.log.debug(custom_tag, InstructionHelper.get_inst_info(inst))
        self.log.debug(tag, "----------------------")
        self.log.debug(tag, msg)
        return

    def log_path_diff(self, path_ids: List[int]) -> None:
        """
        This method logs the difference between two paths.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Ensure expected number of selected paths
        if len(path_ids) != 2:
            return
        max_msg_size = 0
        # Get instructions of path 0
        path_0 = self.get_path(path_ids[0])
        if not path_0:
            return
        path_0_id = path_ids[0]
        path_0_insts = []
        for i, inst in enumerate(path_0.insts):
            call_level = path_0.call_graph.nodes[inst.function]["level"]
            if i < path_0.src_inst_idx:
                ori = f"[Snk] [{call_level:+d}]"
            else:
                ori = f"[Src] [{call_level:+d}]"
            info = InstructionHelper.get_inst_info(inst, False)
            msg = f"{ori:s} {info:s}"
            max_msg_size = max(max_msg_size, len(msg))
            path_0_insts.append(msg)
        # Get instructions of path 1
        path_1 = self.get_path(path_ids[1])
        if not path_1:
            return
        path_1_id = path_ids[1]
        path_1_insts = []
        for i, inst in enumerate(path_1.insts):
            call_level = path_1.call_graph.nodes[inst.function]["level"]
            if i < path_1.src_inst_idx:
                ori = f"[Snk] [{call_level:+d}]"
            else:
                ori = f"[Src] [{call_level:+d}]"
            info = InstructionHelper.get_inst_info(inst, False)
            msg = f"{ori:s} {info:s}"
            max_msg_size = max(max_msg_size, len(msg))
            path_1_insts.append(msg)
        # Compare paths
        lft_col = []
        rgt_col = []
        diff = difflib.ndiff(path_0_insts, path_1_insts)
        path_0_msg = f"Path {path_0_id:d} [L:{len(path_0.insts):d},P:{len(path_0.phiis):d},B:{len(path_0.bdeps):d}]:"
        max_msg_size = max(max_msg_size, len(path_0_msg))
        lft_col.append(path_0_msg)
        path_0_msg = f"{str(path_0):s}"
        path_0_msg = f"{path_0_msg:s}"
        max_msg_size = max(max_msg_size, len(path_0_msg))
        lft_col.append(path_0_msg)
        path_1_msg = f"Path {path_1_id:d} [L:{len(path_1.insts):d},P:{len(path_1.phiis):d},B:{len(path_1.bdeps):d}]:"
        max_msg_size = max(max_msg_size, len(path_1_msg))
        rgt_col.append(path_1_msg)
        path_1_msg = f"{str(path_1):s}"
        path_1_msg = f"{path_1_msg:s}"
        max_msg_size = max(max_msg_size, len(path_1_msg))
        rgt_col.append(path_1_msg)
        lft_col.append("-" * max_msg_size)
        rgt_col.append("-" * max_msg_size)
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
        lft_col.append("-" * max_msg_size)
        rgt_col.append("-" * max_msg_size)
        # Log differences side by side
        for lft, rgt in zip(lft_col, rgt_col):
            self.log.debug(tag, f"{lft:<{max_msg_size}} | {rgt:<{max_msg_size}}")
        return

    def log_call(self, path_ids: List[int], reverse: bool = False) -> None:
        """
        This method logs the calls of a path.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Ensure expected number of selected paths
        if len(path_ids) != 1:
            return
        # Print selected path to log
        path = self.get_path(path_ids[0])
        if not path:
            return
        path_id = path_ids[0]
        path_str = str(path)
        if reverse:
            snk, src = [part.strip() for part in path_str.split("<--")]
            path_str = f"{src:s} --> {snk:s}"
        msg = f"Path {path_id:d}: {path_str:s}"
        msg = f"{msg:s} [L:{len(path.insts):d},P:{len(path.phiis):d},B:{len(path.bdeps):d}]!"
        self.log.info(tag, msg)
        if reverse:
            self.log.debug(tag, "--- Forward  Calls ---")
            calls = list(reversed(path.calls))
        else:
            self.log.debug(tag, "--- Backward Calls ---")
            calls = path.calls
        min_call_level = min(calls, key=lambda x: x[1])[1]
        for call_func, call_level in calls:
            indent = call_level - min_call_level + 1
            call_addr = call_func.source_function.start
            call_name = call_func.source_function.symbol.short_name
            self.log.debug(tag, f"{'>' * indent:s} 0x{call_addr:x} {call_name:s}")
        self.log.debug(tag, "----------------------")
        self.log.debug(tag, msg)
        return

    def highlight_path(self, path_ids: List[int]) -> None:
        """
        This method highlights all instructions in a path.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Ensure expected number of selected paths
        if len(path_ids) != 1:
            return
        # Get path
        path = self.get_path(path_ids[0])
        if not path:
            return
        undo_action = self.bv.begin_undo_actions()
        highlighted_path, insts_colors = self._paths_highlight
        # Undo previous path highlighting
        for addr, (inst, old_color) in insts_colors.items():
            func = inst.function.source_function
            func.set_user_instr_highlight(addr, old_color)
        # Clear the highlight tracking data
        self._paths_highlight = (None, {})
        # If the clicked path was already highlighted, just log and return (it's now unhighlighted)
        if path == highlighted_path:
            self.log.info(tag, f"Un-highlighted instructions of path {path_ids[0]:d}")
            if hasattr(self.bv, "forget_undo_actions"):
                self.bv.forget_undo_actions(undo_action)
            return
        # Add new path highlighting
        highlighted_path = path
        insts_colors = {}
        try:
            setting = self.path_service.config_model.get_setting("src_highlight_color")
            if isinstance(setting, ComboboxSetting) and isinstance(
                setting.widget, qtw.QComboBox
            ):
                color_name = setting.widget.currentText().capitalize()
            else:
                color_name = "Red"
            src_color = bn.HighlightStandardColor[f"{color_name:s}HighlightColor"]
        except Exception as _:
            src_color = bn.HighlightStandardColor.RedHighlightColor
        try:
            setting = self.path_service.config_model.get_setting("snk_highlight_color")
            if isinstance(setting, ComboboxSetting) and isinstance(
                setting.widget, qtw.QComboBox
            ):
                color_name = setting.widget.currentText().capitalize()
            else:
                color_name = "Red"
            snk_color = bn.HighlightStandardColor[f"{color_name:s}HighlightColor"]
        except Exception as _:
            snk_color = bn.HighlightStandardColor.RedHighlightColor
        for i, inst in enumerate(path.insts):
            if i < path.src_inst_idx:
                color = snk_color
            else:
                color = src_color
            func = inst.function.source_function
            addr = inst.address
            if addr not in insts_colors:
                insts_colors[addr] = (inst, func.get_instr_highlight(addr))
            func.set_user_instr_highlight(addr, color)
        self.log.info(tag, f"Highlighted instructions of path {path_ids[0]:d}")
        self._paths_highlight = (highlighted_path, insts_colors)
        if hasattr(self.bv, "forget_undo_actions"):
            self.bv.forget_undo_actions(undo_action)
        return

    def remove_paths(self, path_ids: List[int]) -> None:
        """
        This method removes selected paths from the view.
        """
        # Detect newly attached debuggers
        self.log.detect_attached_debugger()
        # Remove selected paths
        bn.execute_on_main_thread(
            lambda: self.path_proxy_model.path_tree_model.remove_paths(path_ids)
        )
        self.log.info(tag, f"Removed {len(path_ids):d} path(s)")
        return
