from __future__ import annotations
from mole.common.helper.function import FunctionHelper
from mole.common.helper.instruction import InstructionHelper
from mole.common.log import log
from mole.common.parse import LogicalExpressionParser
from mole.common.task import BackgroundTask
from mole.controllers.ai import AiController
from mole.controllers.config import ConfigController
from mole.core.data import Path, SourceFunction, SinkFunction
from mole.services.path import PathService
from mole.views.config import ManualConfigDialog
from mole.views.graph import GraphWidget
from mole.views.path import PathView
from mole.views.path_tree import PathTreeView
from typing import Dict, List, Literal, Tuple, Optional
import binaryninja as bn
import copy as copy
import difflib as difflib
import hashlib as hashlib
import ijson as ijson
import json as json
import os as os
import PySide6.QtWidgets as qtw
import yaml as yaml


tag = "Mole.Path"


class PathController:
    """
    This class implements a controller to handle paths.
    """

    def __init__(
        self, path_view: PathView, config_ctr: ConfigController, ai_ctr: AiController
    ) -> None:
        """
        This method initializes a controller (MVC pattern).
        """
        # Initialization
        self.path_view = path_view
        self.config_ctr = config_ctr
        self.ai_ctr = ai_ctr
        self._bv: Optional[bn.BinaryView] = None
        self.path_tree_view: Optional[PathTreeView] = None
        self._thread: Optional[BackgroundTask] = None
        self._paths_highlight: Tuple[
            Path, Dict[int, Tuple[bn.MediumLevelILInstruction, bn.HighlightColor]]
        ] = (None, {})
        self.path_view.init(self)
        # Register plugin commands
        bn.PluginCommand.register_for_high_level_il_instruction(
            name="Mole\\1. Select HLIL Instruction as Source",
            description="Find paths using the selected HLIL call instruction as source",
            action=lambda bv, inst: self.find_paths_from_manual_inst(
                bv, inst, is_src=True
            ),
        )
        bn.PluginCommand.register_for_high_level_il_instruction(
            name="Mole\\2. Select HLIL Instruction as Sink",
            description="Find paths using the selected HLIL call instruction as sink",
            action=lambda bv, inst: self.find_paths_from_manual_inst(
                bv, inst, is_src=False
            ),
        )
        bn.PluginCommand.register_for_high_level_il_function(
            name="Mole\\1. Select HLIL Function as Source",
            description="Find paths using the selected HLIL function as source",
            action=lambda bv, func: self.find_paths_from_manual_func(
                bv, func, is_src=True
            ),
        )
        bn.PluginCommand.register_for_medium_level_il_instruction(
            name="Mole\\1. Select MLIL Instruction as Source",
            description="Find paths using the selected MLIL call instruction as source",
            action=lambda bv, inst: self.find_paths_from_manual_inst(
                bv, inst, is_src=True
            ),
        )
        bn.PluginCommand.register_for_medium_level_il_instruction(
            name="Mole\\2. Select MLIL Instruction as Sink",
            description="Find paths using the selected MLIL call instruction as sink",
            action=lambda bv, inst: self.find_paths_from_manual_inst(
                bv, inst, is_src=False
            ),
        )
        bn.PluginCommand.register_for_medium_level_il_function(
            name="Mole\\1. Select MLIL Function as Source",
            description="Find paths using the selected MLIL function as source",
            action=lambda bv, func: self.find_paths_from_manual_func(
                bv, func, is_src=True
            ),
        )
        bn.PluginCommand.register_for_low_level_il_instruction(
            name="Mole\\1. Select LLIL Instruction as Source",
            description="Find paths using the selected LLIL call instruction as source",
            action=lambda bv, inst: self.find_paths_from_manual_inst(
                bv, inst, is_src=True
            ),
        )
        bn.PluginCommand.register_for_low_level_il_instruction(
            name="Mole\\2. Select LLIL Instruction as Sink",
            description="Find paths using the selected LLIL call instruction as sink",
            action=lambda bv, inst: self.find_paths_from_manual_inst(
                bv, inst, is_src=False
            ),
        )
        bn.PluginCommand.register_for_low_level_il_function(
            name="Mole\\1. Select LLIL Function as Source",
            description="Find paths using the selected LLIL function as source",
            action=lambda bv, func: self.find_paths_from_manual_func(
                bv, func, is_src=True
            ),
        )
        # Connect signals
        self.path_view.signal_find_paths.connect(self.find_paths)
        self.path_view.signal_load_paths.connect(self.load_paths)
        self.path_view.signal_save_paths.connect(self.save_paths)
        self.path_view.signal_setup_path_tree.connect(self.setup_path_tree)
        self.config_ctr.config_view.signal_change_path_grouping.connect(
            self.config_ctr.change_setting
        )
        return

    def _change_path_grouping(self, new_strategy: str) -> None:
        """
        Handler for when grouping strategy changes in the config. Regroups all paths with the new
        strategy.
        """
        if self.path_tree_view and len(self.path_tree_view.model.path_map) > 0:
            log.info(tag, f"Regrouping paths with new strategy: {new_strategy:s}")
            self.path_tree_view.model.regroup_paths(new_strategy)
        return

    def _give_feedback(
        self,
        button_type: Optional[Literal["Find", "Load", "Save"]] = None,
        tmp_text: str = None,
        new_text: str = None,
        msec: int = 1000,
    ) -> None:
        """
        This method gives user feedback on buttons.
        """
        match button_type:
            case "Find":
                self.path_view.signal_find_paths_feedback.emit(tmp_text, new_text, msec)
            case "Load":
                self.path_view.signal_load_paths_feedback.emit(tmp_text, new_text, msec)
            case "Save":
                self.path_view.signal_save_paths_feedback.emit(tmp_text, new_text, msec)
        return

    def _validate_bv(
        self,
        view_types: Optional[List[str]] = None,
        button_type: Optional[Literal["Find", "Load", "Save"]] = None,
    ) -> bool:
        """
        This method ensures that the given views exist and is not one in `view_types`.
        """
        if not self._bv:
            log.warn(tag, "No binary loaded")
            self._give_feedback(button_type, "No Binary Loaded...")
            return False
        if view_types is not None and self._bv.view_type in view_types:
            log.warn(
                tag,
                f"Binary is in '{self._bv.view_type:s}' but must not be one of '{', '.join(view_types):s}'",
            )
            self._give_feedback(button_type, "Incorrect Binary View")
            return False
        return True

    def add_path_to_view(self, path: Path) -> None:
        """
        This method updates the UI with a newly identified path.
        """

        def update_paths_view() -> None:
            # Ensure view exists
            if not self.path_tree_view:
                return
            # Determine path grouping strategy
            path_grouping = None
            setting = self.config_ctr.get_setting("path_grouping")
            if setting:
                path_grouping = setting.value
            # Update the model
            self.path_tree_view.model.add_path(path, path_grouping)
            return

        bn.execute_on_main_thread(update_paths_view)
        return

    def find_paths(
        self,
        manual_fun: Optional[SourceFunction | SinkFunction] = None,
        manual_fun_inst: Optional[
            bn.MediumLevelILCall
            | bn.MediumLevelILCallSsa
            | bn.MediumLevelILTailcall
            | bn.MediumLevelILTailcallSsa
        ] = None,
        manual_fun_all_code_xrefs: bool = False,
    ) -> None:
        """
        This method analyzes the entire binary for interesting looking code paths.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv(["Raw"], "Find"):
            return
        # Require previous background threads to have completed
        if self._thread and not self._thread.finished:
            log.warn(tag, "Wait for previous background thread to complete first")
            self._give_feedback("Find", "Other Task Running...")
            return
        # Start background thread
        self._give_feedback("Find", "Finding...")
        self._thread = PathService(
            bv=self._bv,
            config_model=self.config_ctr.config_model,
            manual_fun=manual_fun,
            manual_fun_inst=manual_fun_inst,
            manual_fun_all_code_xrefs=manual_fun_all_code_xrefs,
            path_callback=self.add_path_to_view,
            initial_progress_text="Mole finds paths...",
            can_cancel=True,
        )
        self._thread.start()
        return

    def find_paths_from_manual_inst(
        self,
        bv: bn.BinaryView,
        inst: bn.HighLevelILInstruction
        | bn.MediumLevelILInstruction
        | bn.LowLevelILInstruction,
        is_src: bool = True,
        is_from_manual_func: bool = False,
    ) -> None:
        """
        This method analyzes the entire binary for interesting looking code paths using `inst` as
        the only source or sink (based on `is_src`).
        """
        # Map to MLIL call instruction in SSA form
        mlil_call_insts = InstructionHelper.get_mlil_call_insts(inst)
        if len(mlil_call_insts) <= 0:
            log.warn(
                tag,
                "Selected instruction could not be mapped to a MLIL call instruction",
            )
            return None
        inst: bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa = mlil_call_insts[
            0
        ].ssa_form
        inst_info = InstructionHelper.get_inst_info(inst)
        log.info(tag, f"Selected MLIL call instruction '{inst_info:s}'")
        # Function information
        name, synopsis = InstructionHelper.get_func_signature(bv, inst)
        name = name if name else "unknown"
        symbols = [name] if name else []
        par_cnt = f"i == {len(inst.params):d}"
        # Create popup dialog
        dialog = ManualConfigDialog(
            is_src, is_from_manual_func, synopsis, "Default", par_cnt
        )

        def _create_fun(
            synopsis: str, par_cnt: str, par_slice: str
        ) -> Tuple[Optional[SourceFunction | SinkFunction], str]:
            parser = LogicalExpressionParser()
            par_cnt_fun = parser.parse(par_cnt)
            if par_cnt_fun is None:
                return None, "Invalid par_cnt..."
            par_slice_fun = parser.parse(par_slice)
            if par_slice_fun is None:
                return None, "Invalid par_slice..."
            # Create manual source function
            if is_src:
                fun = SourceFunction(
                    name=name,
                    symbols=symbols,
                    synopsis=synopsis,
                    enabled=False,
                    par_cnt=par_cnt,
                    par_cnt_fun=par_cnt_fun,
                    par_slice=par_slice,
                    par_slice_fun=par_slice_fun,
                )
            # Create manual sink function
            else:
                fun = SinkFunction(
                    name=name,
                    symbols=symbols,
                    synopsis=synopsis,
                    enabled=False,
                    par_cnt=par_cnt,
                    par_cnt_fun=par_cnt_fun,
                    par_slice=par_slice,
                    par_slice_fun=par_slice_fun,
                )
            return fun, ""

        def _find_paths_from_manual_inst(
            synopsis: str, par_cnt: str, par_slice: str, all_code_xrefs: bool
        ) -> None:
            # Create manual function
            if is_from_manual_func and not all_code_xrefs:
                par_slice = "True"
            manual_fun, msg = _create_fun(synopsis, par_cnt, par_slice)
            # Give user feedback if function creating failed
            if manual_fun is None:
                dialog.signal_find_feedback.emit(msg)
            # Find paths using manual function
            else:
                self.find_paths(
                    manual_fun=manual_fun,
                    manual_fun_inst=inst,
                    manual_fun_all_code_xrefs=all_code_xrefs,
                )
                dialog.accept()
            return

        def _save_paths_from_manual_inst(
            category: str, synopsis: str, par_cnt: str, par_slice: str
        ) -> None:
            # Create manual function
            manual_fun, msg = _create_fun(synopsis, par_cnt, par_slice)
            # Give user feedback if function creating failed
            if manual_fun is None:
                dialog.signal_add_feedback.emit(msg)
            # Save manual function
            else:
                self.config_ctr.save_manual_fun(manual_fun, category)
                dialog.accept()
            return

        # Connect signals and execute dialog
        dialog.signal_find.connect(_find_paths_from_manual_inst)
        dialog.signal_add.connect(_save_paths_from_manual_inst)
        dialog.exec()
        return

    def find_paths_from_manual_func(
        self,
        bv: bn.BinaryView,
        func: bn.HighLevelILFunction | bn.MediumLevelILFunction | bn.LowLevelILFunction,
        is_src: bool = True,
    ) -> None:
        """
        This method analyzes the entire binary for interesting looking code paths using `func` as
        the only source or sink (based on `is_src`).
        """
        # Ensure function is in MLIL SSA form
        if not isinstance(func, bn.MediumLevelILFunction):
            func = func.mlil
        if func is None or func.ssa_form is None:
            log.warn(tag, "Selected function has no SSA form")
            return
        func = func.ssa_form
        # Build a synthetic call instruction
        call_inst = FunctionHelper.get_mlil_synthetic_call_inst(bv, func)
        if call_inst is None:
            log.warn(
                tag, "Could not create synthetic call instruction for selected function"
            )
            return
        # Find paths using the synthetic call instruction
        return self.find_paths_from_manual_inst(bv, call_inst, is_src, True)

    def load_paths(self) -> None:
        """
        This method loads paths from the binary's database.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv(["Raw"], "Load"):
            return
        # Require previous background threads to have completed
        if self._thread and not self._thread.finished:
            log.warn(tag, "Wait for previous background thread to complete first")
            self._give_feedback("Load", "Other Task Running...")
            return
        # Remove all paths
        self.path_tree_view.clear_all_paths()

        # Load paths in a background task
        def _load_paths() -> None:
            cnt_loaded_paths = 0
            try:
                # Calculate SHA1 hash
                sha1_hash = hashlib.sha1(
                    self._bv.file.raw.read(0, self._bv.file.raw.end)
                ).hexdigest()
                # Load paths from database
                s_paths: List[Dict] = json.loads(self._bv.query_metadata("mole_paths"))
                for i, s_path in enumerate(s_paths):
                    try:
                        # Check if user cancelled the background task
                        if self._thread.cancelled:
                            break
                        # Compare SHA1 hashes
                        if s_path["sha1_hash"] != sha1_hash:
                            log.warn(
                                tag,
                                f"Path #{i + 1:d} seems to origin from another binary",
                            )
                        # Deserialize and add path
                        path = Path.from_dict(self._bv, s_path)
                        self.add_path_to_view(path)
                        # Increment loaded path counter
                        cnt_loaded_paths += 1
                    except Exception as e:
                        log.error(tag, f"Failed to load path #{i + 1:d}: {str(e):s}")
                    finally:
                        self._thread.progress = (
                            f"Mole loaded path: {i + 1:d}/{len(s_paths):d}"
                        )
            except KeyError:
                pass
            except Exception as e:
                log.error(tag, f"Failed to load paths: {str(e):s}")
            self._give_feedback("Save", "Save", "Save", 0)
            log.info(tag, f"Loaded {cnt_loaded_paths:d} path(s)")
            return

        # Start a background task
        self._give_feedback("Load", "Loading...")
        self._thread = BackgroundTask(
            initial_progress_text="Mole loads paths...",
            can_cancel=True,
            run=_load_paths,
        )
        self._thread.start()
        return

    def save_paths(self) -> None:
        """
        This method saves paths to the binary's database.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv(["Raw"], "Save"):
            return
        # Require previous background threads to have completed
        if self._thread and not self._thread.finished:
            log.warn(tag, "Wait for previous background thread to complete first")
            return

        # Save paths in a background task
        def _save_paths() -> None:
            cnt_saved_paths = 0
            try:
                # Save paths to database
                paths = self.path_tree_view.get_all_paths()
                s_paths: List[Dict] = []
                for i, path in enumerate(paths):
                    try:
                        # Check if user cancelled the background task
                        if self._thread.cancelled:
                            break
                        # Serialize paths
                        s_path = path.to_dict()
                        s_paths.append(s_path)
                        # Increment exported path counter
                        cnt_saved_paths += 1
                    except Exception as e:
                        log.error(tag, f"Failed to save path #{i + 1:d}: {str(e):s}")
                    finally:
                        self._thread.progress = (
                            f"Mole saved path: {i + 1:d}/{len(paths):d}"
                        )
                self._bv.store_metadata("mole_paths", json.dumps(s_paths))
            except Exception as e:
                log.error(tag, f"Failed to save paths: {str(e):s}")
            log.info(tag, f"Saved {cnt_saved_paths:d} path(s)")
            return

        # Start a background task
        self._give_feedback("Save", "Saving...", "Save")
        self._thread = BackgroundTask(
            initial_progress_text="Mole saves paths...",
            can_cancel=True,
            run=_save_paths,
        )
        self._thread.start()
        return

    def import_paths(self) -> None:
        """
        This method imports paths from a file.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv(["Raw"]):
            return
        # Open dialog to select file
        filepath, _ = qtw.QFileDialog.getOpenFileName(
            caption="Open File", filter="JSON Files (*.json);;All Files (*)"
        )
        if not filepath:
            log.warn(tag, "No paths imported")
            return
        # Expand file path
        filepath = os.path.abspath(os.path.expanduser(os.path.expandvars(filepath)))
        # Require previous background threads to have completed
        if self._thread and not self._thread.finished:
            log.warn(tag, "Wait for previous background thread to complete first")
            self._give_feedback("Find", "Other Task Running...")
            return

        # Import paths in a background task
        def _import_paths() -> None:
            cnt_imported_paths = 0
            try:
                # Calculate SHA1 hash
                sha1_hash = hashlib.sha1(
                    self._bv.file.raw.read(0, self._bv.file.raw.end)
                ).hexdigest()
                # Count the total number of paths to be imported
                cnt_total_paths = 0
                with open(filepath, "r") as f:
                    for _ in ijson.items(f, "item"):
                        cnt_total_paths += 1
                # Iteratively import paths from the JSON file
                with open(filepath, "r") as f:
                    for i, s_path in enumerate(ijson.items(f, "item")):
                        try:
                            # Check if user cancelled the background task
                            if self._thread.cancelled:
                                break
                            # Compare SHA1 hashes
                            if s_path["sha1_hash"] != sha1_hash:
                                log.warn(
                                    tag,
                                    f"Path #{i + 1:d} seems to origin from another binary",
                                )
                            # Deserialize and add path
                            path = Path.from_dict(self._bv, s_path)
                            self.add_path_to_view(path)
                            # Increment imported path counter
                            cnt_imported_paths += 1
                        except Exception as e:
                            log.error(
                                tag, f"Failed to import path #{i + 1:d}: {str(e):s}"
                            )
                        finally:
                            self._thread.progress = (
                                f"Mole imported path: {i + 1:d}/{cnt_total_paths:d}"
                            )
            except Exception as e:
                log.error(tag, f"Failed to import paths: {str(e):s}")
            log.info(tag, f"Imported {cnt_imported_paths:d} path(s)")
            return

        # Start background task
        self._thread = BackgroundTask(
            initial_progress_text="Mole imports paths...",
            can_cancel=True,
            run=_import_paths,
        )
        self._thread.start()
        return

    def export_paths(self, path_ids: List[int]) -> None:
        """
        This method exports paths to a file.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv(["Raw"]):
            return
        # Open dialog to select file
        filepath, _ = qtw.QFileDialog.getSaveFileName(
            caption="Save As", filter="JSON Files (*.json);;All Files (*)"
        )
        if not filepath:
            log.info(tag, "No paths exported")
            return
        # Expand file path
        filepath = os.path.abspath(os.path.expanduser(os.path.expandvars(filepath)))
        # Require previous background threads to have completed
        if self._thread and not self._thread.finished:
            log.warn(tag, "Wait for previous background thread to complete first")
            return

        # Export paths in a background task
        def _export_paths() -> None:
            nonlocal path_ids
            ident = 2
            cnt_exported_paths = 0
            try:
                # Iteratively export paths to the JSON file
                with open(filepath, "w") as f:
                    path_ids = (
                        path_ids
                        if path_ids
                        else list(self.path_tree_view.model.path_map.keys())
                    )
                    f.write("[\n")
                    for i, path_id in enumerate(path_ids):
                        try:
                            # Check if user cancelled the background task
                            if self._thread.cancelled:
                                break
                            # Get path (filtering out headers/groups)
                            path = self.path_tree_view.get_path(path_id)
                            if not path:
                                continue
                            # Serialize and dump path
                            s_path = path.to_dict(debug=True)
                            if i != 0:
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
                            log.error(
                                tag, f"Failed to export path #{i + 1:d}: {str(e):s}"
                            )
                        finally:
                            self._thread.progress = (
                                f"Mole exported path: {i + 1:d}/{len(path_ids):d}"
                            )
                    f.write("\n]")
            except Exception as e:
                log.error(tag, f"Failed to export paths: {str(e):s}")
            log.info(tag, f"Exported {cnt_exported_paths:d} path(s)")
            return

        # Start background task
        self._thread = BackgroundTask(
            initial_progress_text="Mole exports paths...",
            can_cancel=True,
            run=_export_paths,
        )
        self._thread.start()
        return

    def log_path(self, path_ids: List[int], reverse: bool = False) -> None:
        """
        This method logs information about a path.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv():
            return
        # Ensure expected number of selected paths
        if len(path_ids) != 1:
            return
        # Print selected path to log
        path_id = path_ids[0]
        path = self.path_tree_view.get_path(path_ids[0])
        if not path:
            return
        path_str = str(path)
        if reverse:
            snk, src = [part.strip() for part in path_str.split("<--")]
            path_str = f"{src:s} --> {snk:s}"
        msg = f"Path {path_id:d}: {path_str:s}"
        msg = f"{msg:s} [L:{len(path.insts):d},P:{len(path.phiis):d},B:{len(path.bdeps):d}]!"
        log.info(tag, msg)
        if reverse:
            log.debug(tag, "--- Forward  Slice ---")
            src_inst_idx = len(path.insts) - path.src_inst_idx
            insts = reversed(path.insts)
        else:
            log.debug(tag, "--- Backward Slice ---")
            src_inst_idx = path.src_inst_idx
            insts = path.insts
        basic_block = None
        for i, inst in enumerate(insts):
            call_level = path.call_graph.nodes[inst.function]["call_level"]
            if (not reverse and i < src_inst_idx) or (reverse and i >= src_inst_idx):
                custom_tag = f"{tag}] [Snk] [{call_level:+d}"
            else:
                custom_tag = f"{tag}] [Src] [{call_level:+d}"
            try:
                inst_basic_block = inst.il_basic_block
                if inst_basic_block != basic_block:
                    basic_block = inst_basic_block
                    fun_name = basic_block.function.name
                    bb_addr = basic_block[0].address
                    log.debug(custom_tag, f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}")
            except Exception:
                pass
            log.debug(custom_tag, InstructionHelper.get_inst_info(inst))
        log.debug(tag, "----------------------")
        log.debug(tag, msg)
        return

    def log_path_diff(self, path_ids: List[int]) -> None:
        """
        This method logs the difference between two paths.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv():
            return
        # Ensure expected number of selected paths
        if len(path_ids) != 2:
            return
        max_msg_size = 0
        # Get instructions of path 0
        path_0 = self.path_tree_view.get_path(path_ids[0])
        if not path_0:
            return
        path_0_id = path_ids[0]
        path_0_insts = []
        for i, inst in enumerate(path_0.insts):
            call_level = path_0.call_graph.nodes[inst.function]["call_level"]
            if i < path_0.src_inst_idx:
                ori = f"[Snk] [{call_level:+d}]"
            else:
                ori = f"[Src] [{call_level:+d}]"
            info = InstructionHelper.get_inst_info(inst, False)
            msg = f"{ori:s} {info:s}"
            max_msg_size = max(max_msg_size, len(msg))
            path_0_insts.append(msg)
        # Get instructions of path 1
        path_1 = self.path_tree_view.get_path(path_ids[1])
        if not path_1:
            return
        path_1_id = path_ids[1]
        path_1_insts = []
        for i, inst in enumerate(path_1.insts):
            call_level = path_1.call_graph.nodes[inst.function]["call_level"]
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
            log.debug(tag, f"{lft:<{max_msg_size}} | {rgt:<{max_msg_size}}")
        return

    def log_call(self, path_ids: List[int], reverse: bool = False) -> None:
        """
        This method logs the calls of a path.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv():
            return
        # Ensure expected number of selected paths
        if len(path_ids) != 1:
            return
        # Print selected path to log
        path = self.path_tree_view.get_path(path_ids[0])
        if not path:
            return
        path_id = path_ids[0]
        path_str = str(path)
        if reverse:
            snk, src = [part.strip() for part in path_str.split("<--")]
            path_str = f"{src:s} --> {snk:s}"
        msg = f"Path {path_id:d}: {path_str:s}"
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
            log.debug(tag, f"{'>' * indent:s} 0x{call_addr:x} {call_name:s}")
        log.debug(tag, "----------------------")
        log.debug(tag, msg)
        return

    def highlight_path(self, path_ids: List[int]) -> None:
        """
        This method highlights all instructions in a path.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv():
            return
        # Ensure expected number of selected paths
        if len(path_ids) != 1:
            return
        # Get path
        path = self.path_tree_view.get_path(path_ids[0])
        if not path:
            return
        undo_action = self._bv.begin_undo_actions()
        highlighted_path, insts_colors = self._paths_highlight
        # Undo previous path highlighting
        for addr, (inst, old_color) in insts_colors.items():
            func = inst.function.source_function
            func.set_user_instr_highlight(addr, old_color)
        # Clear the highlight tracking data
        self._paths_highlight = (None, {})
        # If the clicked path was already highlighted, just log and return (it's now unhighlighted)
        if path == highlighted_path:
            log.info(tag, f"Un-highlighted instructions of path {path_ids[0]:d}")
            if hasattr(self._bv, "forget_undo_actions"):
                self._bv.forget_undo_actions(undo_action)
            return
        # Add new path highlighting
        highlighted_path = path
        insts_colors = {}
        try:
            setting = self.config_ctr.get_setting("src_highlight_color")
            color_name = setting.widget.currentText().capitalize()
            src_color = bn.HighlightStandardColor[f"{color_name:s}HighlightColor"]
        except Exception as _:
            src_color = bn.HighlightStandardColor.RedHighlightColor
        try:
            setting = self.config_ctr.get_setting("snk_highlight_color")
            color_name = setting.widget.currentText().capitalize()
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
        log.info(tag, f"Highlighted instructions of path {path_ids[0]:d}")
        self._paths_highlight = (highlighted_path, insts_colors)
        if hasattr(self._bv, "forget_undo_actions"):
            self._bv.forget_undo_actions(undo_action)
        return

    def show_call_graph(self, path_ids: List[int], wid: qtw.QTabWidget) -> None:
        """
        This method shows the call graph of a path.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv():
            return
        # Ensure expected number of selected paths
        if len(path_ids) != 1:
            return
        # Show call graph of selected path
        path = self.path_tree_view.get_path(path_ids[0])
        if not path:
            return
        for idx in range(wid.count()):
            if wid.tabText(idx) == "Graph":
                graph_widget: GraphWidget = wid.widget(idx)
                graph_widget.load_path(self._bv, path, path_ids[0])
                wid.setCurrentWidget(graph_widget)
                return
        log.info(tag, f"Showing call graph of path {path_ids[0]:d}")
        return

    def analyze_paths(self, path_ids: List[int]) -> None:
        """
        This method analyzes paths using AI.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv():
            return
        # Require previous background threads to have completed
        if self._thread and not self._thread.finished:
            log.warn(tag, "Wait for previous background thread to complete first")
            return
        # Get selected paths
        paths = [
            (path_id, self.path_tree_view.get_path(path_id)) for path_id in path_ids
        ]
        # Start background thread analyzing paths using AI
        self._thread = self.ai_ctr.analyze_paths(
            self._bv, paths, self.path_tree_view.model.update_path_report
        )
        return

    def show_ai_report(self, path_ids: List[int]) -> None:
        """
        This method shows the AI-generated vulnerability report of a path.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv():
            return
        # Ensure expected number of selected paths
        if len(path_ids) != 1:
            return
        # Get selected path
        path = self.path_tree_view.get_path(path_ids[0])
        if not path:
            return
        # Show the path's AI-generated report if available
        if path.ai_report:
            self.ai_ctr.show_report(path.ai_report)
            self.path_view.show_ai_report_tab()
        return

    def remove_selected_paths(self, path_ids: List[int]) -> None:
        """
        This method removes selected paths from the view.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv():
            return
        # Remove selected paths
        cnt = self.path_tree_view.remove_selected_paths(path_ids)
        log.info(tag, f"Removed {cnt:d} path(s)")
        return

    def clear_all_paths(self) -> None:
        """
        This method clears all paths from the view.
        """
        # Detect newly attached debuggers
        log.find_attached_debugger()
        # Ensure correct view
        if not self._validate_bv():
            return
        # Clear all paths
        cnt = self.path_tree_view.clear_all_paths()
        log.info(tag, f"Cleared {cnt:d} path(s)")
        return

    def setup_path_tree(
        self, bv: bn.BinaryView, ptv: PathTreeView, wid: qtw.QTabWidget
    ) -> None:
        """
        This method sets up the path tree view with controller callbacks.
        """
        # Store references
        self._bv = bv
        self.path_tree_view = ptv
        # Set up signals
        if self.path_tree_view:
            self.path_tree_view.signal_show_ai_report.connect(self.show_ai_report)
        # Set up context menu
        ptv.setup_context_menu(
            on_log_path=self.log_path,
            on_log_path_diff=self.log_path_diff,
            on_log_call=self.log_call,
            on_highlight_path=lambda rows: self.highlight_path(rows),
            on_show_call_graph=lambda rows: self.show_call_graph(rows, wid),
            on_import_paths=self.import_paths,
            on_export_paths=lambda rows: self.export_paths(rows),
            on_remove_selected=self.remove_selected_paths,
            on_clear_all=self.clear_all_paths,
            on_analyze_paths=self.analyze_paths,
            on_show_ai_report=self.show_ai_report,
            bv=bv,
        )
        # Set up navigation
        ptv.setup_navigation(bv)
        # Expand all nodes by default
        ptv.expandAll()
        # Apply current path grouping strategy to any existing paths
        setting = self.config_ctr.get_setting("path_grouping")
        if setting and len(self.path_tree_view.model.path_map) > 0:
            self.path_tree_view.model.regroup_paths(setting.value)
        return
