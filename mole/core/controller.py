from __future__        import annotations
from ..common.parse    import LogicalExpressionParser
from ..common.log      import Logger
from ..ui.graph        import GraphWidget
from ..ui.utils        import IntTableWidgetItem
from .data             import *
from typing            import Dict, List, Literal
import binaryninja       as bn
import copy              as copy
import difflib           as difflib
import fnmatch           as fn
import hashlib           as hashlib
import json              as json
import os                as os
import PySide6.QtCore    as qtc
import PySide6.QtWidgets as qtw
import shutil            as shu
import yaml              as yaml


class Controller:
    """
    This class implements the plugin's controller.
    """

    def __init__(
            self,
            tag: str = "Mole",
            log: Logger = Logger(level="debug"),
            runs_headless: bool = False,
        ) -> None:
        """
        This method initializes a controller (MVC pattern).
        """
        self._tag: str = tag
        self._log: Logger = log
        self._runs_headless: bool = runs_headless
        self._thread: MediumLevelILBackwardSlicerThread = None
        self._parser: LogicalExpressionParser = LogicalExpressionParser(self._tag, self._log)
        self._paths: List[Path] = []
        self._paths_widget: qtw.QTableWidget = None
        self._paths_highlight: Tuple[
            Path,
            Dict[int, Tuple[bn.MediumLevelILInstruction, bn.HighlightColor]]
        ] = (None, {})
        self._conf_path: str = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "../../conf/"
        )
        return
    
    def init(self) -> Controller:
        """
        This method initializes the plugin's model and view.
        """
        from .model import SidebarModel
        self._model: SidebarModel = SidebarModel(self, self._tag, self._log).init()
        if not self._runs_headless:
            from .view import SidebarView
            self._view: SidebarView = SidebarView(self, self._tag, self._log).init()
        self.load_custom_conf_files()
        self.load_main_conf_file()
        return self
    
    def __give_feedback(self, button: qtw.QPushButton, text: str, msec: int = 1000) -> None:
        """
        This method provides user feedback using a `QPushButton`'s text.
        """
        def __reset_button(text: str) -> None:
            button.setText(text)
            button.setEnabled(True)
            return
        
        if button:
            button.setEnabled(False)
            old_text = button.text()
            button.setText(text)
            qtc.QTimer.singleShot(msec, lambda text=old_text: __reset_button(text=text))
        return
    
    def load_custom_conf_files(self) -> None:
        """
        This method loads the custom configuration files.
        """
        for conf_file in sorted(os.listdir(self._conf_path)):
            if not fn.fnmatch(conf_file, "*.yml") or conf_file == "000-mole.yml": continue
            # Open configuration file
            try:
                with open(os.path.join(self._conf_path, conf_file), "r") as f:
                    conf = yaml.safe_load(f)
            except Exception as e:
                self._log.warn(
                    self._tag,
                    f"Failed to open configuration file '{conf_file:s}': '{str(e):s}'"
                )
                continue
            # Parse configuration file
            conf = self.parse_conf(conf)
            # Update model
            self._model.update(conf)
        return
    
    def load_main_conf_file(self) -> None:
        """
        This method loads the main configuration file.
        """
        # Open configuration file
        try:
            with open(os.path.join(self._conf_path, "000-mole.yml")) as f:
                conf = yaml.safe_load(f)
        except FileNotFoundError:
            return
        except Exception as e:
            self._log.warn(
                    self._tag,
                    f"Failed to open configuration file '000-mole.yml': '{str(e):s}'"
                )
            return
        # Parse configuration file
        conf = self.parse_conf(conf)
        # Update model
        self._model.update(conf)

    def parse_conf(self, conf: Dict) -> Configuration:
        """
        This method parse the plain configuration `conf` into a `Configuration` instance.
        """
        parsed_conf = {
            "sources": {},
            "sinks": {},
            "settings": {}
        }
        if not conf: return Configuration(**parsed_conf)
        try:
            # Parse sources and sinks
            for type in ["sources", "sinks"]:
                libs = conf.get(type, {})
                for lib_name, lib in libs.items():
                    lib_categories = {}
                    categories = lib.get("categories", {})
                    for cat_name, cat in categories.items():
                        cat_functions = {}
                        functions = cat.get("functions", {})
                        for fun_name, fun in functions.items():
                            match type:
                                case "sources":
                                    fun = SourceFunction(**fun)
                                case "sinks":
                                    fun = SinkFunction(**fun)
                                case _:
                                    continue
                            fun.par_cnt_fun = self._parser.parse(fun.par_cnt)
                            fun.par_dataflow_fun = self._parser.parse(fun.par_dataflow)
                            fun.par_slice_fun = self._parser.parse(fun.par_slice)
                            cat_functions[fun_name] = fun
                        lib_categories[cat_name] = Category(cat_name, cat_functions)
                    parsed_conf[type][lib_name] = Library(lib_name, lib_categories)
            # Parse settings
            settings = conf.get("settings", {})
            mfd_name = "max_call_level"
            mfd_settings = settings.get(mfd_name, None)
            if mfd_settings:
                mfd_value = int(mfd_settings.get("value", None))
                mfd_min_value = int(mfd_settings.get("min_value", None))
                mfd_max_value = int(mfd_settings.get("max_value", None))
                mfd_value = min(max(mfd_value, mfd_min_value), mfd_max_value)
                mfd_help = mfd_settings.get("help", "")
                parsed_conf["settings"].update({
                    mfd_name: SpinboxSetting(
                        name=mfd_name,
                        value=mfd_value,
                        help=mfd_help,
                        min_value=mfd_min_value,
                        max_value=mfd_max_value
                    )
                })
            msd_name = "max_slice_depth"
            msd_settings = settings.get(msd_name, None)
            if msd_settings:
                msd_value = int(msd_settings.get("value", None))
                msd_min_value = int(msd_settings.get("min_value", None))
                msd_max_value = int(msd_settings.get("max_value", None))
                msd_value = min(max(msd_value, msd_min_value), msd_max_value)
                msd_help = msd_settings.get("help", "")
                parsed_conf["settings"].update({
                    msd_name: SpinboxSetting(
                        name=msd_name,
                        value=msd_value,
                        help=msd_help,
                        min_value=msd_min_value,
                        max_value=msd_max_value
                    )
                })
            col_name = "highlight_color"
            col_settings = settings.get(col_name, None)
            if col_settings:
                col_value = col_settings.get("value", "")
                col_help = col_settings.get("help", "")
                col_items = col_settings.get("items", [])
                parsed_conf["settings"].update({
                    col_name: ComboboxSetting(
                        name=col_name,
                        value=col_value,
                        help=col_help,
                        items=col_items
                    )
                })
        except Exception as e:
            self._log.warn(
                self._tag,
                f"Failed to parse configuration file: '{str(e):s}'"
            )
        return Configuration(**parsed_conf)
    
    def store_main_conf_file(self, button: qtw.QPushButton = None) -> None:
        """
        This method stores the main configuration file.
        """
        # Store model
        model = self._model.get()
        with open(os.path.join(self._conf_path, "000-mole.yml"), "w") as f:
            yaml.safe_dump(
                model.to_dict(),
                f,
                sort_keys=False,
                default_style=None,
                default_flow_style=False,
                encoding="utf-8"
            )
        # User feedback
        self.__give_feedback(button, "Saving...")
        return
    
    def reset_conf(self, button: qtw.QPushButton = None) -> None:
        """
        This method resets the configuration.
        """
        # Store input elements
        old_model = self._model.get()
        sources_ie = {}
        for lib_name, lib in old_model.sources.items():
            sources_ie_lib = sources_ie.setdefault(lib_name, {})
            for cat_name, cat in lib.categories.items():
                sources_ie_cat = sources_ie_lib.setdefault(cat_name, {})
                for fun_name, fun in cat.functions.items():
                    sources_ie_cat[fun_name] = fun.checkbox
        sinks_ie = {}
        for lib_name, lib in old_model.sinks.items():
            sinks_ie_lib = sinks_ie.setdefault(lib_name, {})
            for cat_name, cat in lib.categories.items():
                sinks_ie_cat = sinks_ie_lib.setdefault(cat_name, {})
                for fun_name, fun in cat.functions.items():
                    sinks_ie_cat[fun_name] = fun.checkbox
        settings = {}
        for setting_name, setting in old_model.settings.items():
            settings[setting_name] = setting.widget
        # Reset model
        self.load_custom_conf_files()
        new_model = self._model.get()
        # Restore input elements
        for lib_name, lib in new_model.sources.items():
            sources_ie_lib = sources_ie.get(lib_name, {})
            for cat_name, cat in lib.categories.items():
                sources_ie_cat = sources_ie_lib.get(cat_name, {})
                for fun_name, fun in cat.functions.items():
                    fun.checkbox = sources_ie_cat.get(fun_name, None)
                    fun.checkbox.setChecked(fun.enabled)
        for lib_name, lib in new_model.sinks.items():
            sinks_ie_lib = sinks_ie.get(lib_name, {})
            for cat_name, cat in lib.categories.items():
                sinks_ie_cat = sinks_ie_lib.get(cat_name, {})
                for fun_name, fun in cat.functions.items():
                    fun.checkbox = sinks_ie_cat.get(fun_name, None)
                    fun.checkbox.setChecked(fun.enabled)
        for setting_name, setting in new_model.settings.items():
            setting.widget = settings.get(setting_name, None)
            if isinstance(setting, SpinboxSetting):
                setting.widget.setValue(setting.value)
            elif isinstance(setting, ComboboxSetting):
                if setting.value in setting.items:
                    setting.widget.setCurrentText(setting.value)
        # User feedback
        self.__give_feedback(button, "Resetting...")
        return

    def get_libraries(self, type: Literal["Sources", "Sinks"]) -> Dict[str, Library]:
        """
        This method returns all libraries.
        """
        model = self._model.get()
        match type:
            case "Sources":
                return model.sources
            case "Sinks":
                return model.sinks
        return {}
    
    def get_functions(
            self,
            type: Literal["Sources", "Sinks"],
            enabled_only: bool = False
        ) -> List[SourceFunction] | List[SinkFunction]:
        """
        This method returns all (enabled) source or sink functions.
        """
        funs = []
        model = self._model.get()
        match type:
            case "Sources":
                libs = model.sources
            case "Sinks":
                libs = model.sinks
            case _:
                libs = {}
        for lib in libs.values():
            for cat in lib.categories.values():
                for fun in cat.functions.values():
                    if not enabled_only or fun.enabled:
                        funs.append(fun)
        return funs
    
    def get_settings(self) -> Dict[str, WidgetSetting]:
        """
        This method returns all settings.
        """
        return self._model.get().settings
    
    def checkbox_toggle(self, fun: Function) -> None:
        """
        This method updates the model to reflect a changing value of the checkbox associated with a
        given function.
        """
        fun.enabled = not fun.enabled
        return
    
    def checkboxes_check(self, cat: Category, checked: bool) -> None:
        """
        This method updates the model to reflect a changing value of all checkboxes in a given
        category.
        """
        for fun in cat.functions.values():
            fun.enabled = checked
            fun.checkbox.setChecked(checked)
        return
    
    def spinbox_change_value(self, setting: SpinboxSetting, value: int) -> None:
        """
        This method updates the model to reflect spinbox value changes.
        """
        setting.value = value
        return
    
    def combobox_change_value(self, setting: ComboboxSetting, value: str) -> None:
        """
        This method updates the model to reflect combobox value changes.
        """
        setting.value = value
        return
    
    def add_path_to_view(
            self,
            path: Path,
            comment: str = ""
        ) -> None:
        """
        This method updates the UI with a newly identified path.
        """
        def update_paths_widget() -> None:
            if not self._paths_widget:
                return
            self._paths.append(path)
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
            snk_parm = qtw.QTableWidgetItem(f"arg#{path.snk_par_idx+1:d}:{str(path.snk_par_var):s}")
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
            max_call_level: int = None,
            max_slice_depth: int = None,
            enable_all_funs: bool = False,
            but: qtw.QPushButton = None,
            tbl: qtw.QTableWidget = None
        ) -> None | List[Path]:
        """
        This method analyzes the entire binary for interesting looking code paths.
        """
        # Require a binary to be loaded
        if not bv:
            self._log.warn(self._tag, "No binary loaded.")
            self.__give_feedback(but, "No Binary Loaded...")
            return
        # Require the binary to be in mapped view
        if bv.view_type == "Raw":
            self._log.warn(self._tag, "Binary is in Raw view.")
            self.__give_feedback(but, "Binary is in Raw View...")
            return
        # Require previous analyses to complete
        if self._thread and not self._thread.finished:
            self._log.warn(self._tag, "Analysis already running.")
            self.__give_feedback(but, "Analysis Already Running...")
            return
        # Initialize new logger to detect newly attached debugger
        self._log = Logger(self._log.get_level(), self._runs_headless)
        self.__give_feedback(but, "Finding Paths...")
        # Initialize data structures
        if tbl:
            self._paths_widget = tbl
        # Run background thread
        self._thread = MediumLevelILBackwardSlicerThread(
            bv=bv,
            ctr=self,
            tag=self._tag,
            log=self._log,
            runs_headless=self._runs_headless,
            max_call_level=max_call_level,
            max_slice_depth=max_slice_depth,
            enable_all_funs=enable_all_funs
        )
        self._thread.start()
        if self._runs_headless:
            return self._thread.get_paths()
        return None
    
    def load_paths(
            self,
            bv: bn.BinaryView,
            but: qtw.QPushButton,
            tbl: qtw.QTableWidget
        ) -> None:
        """
        This method loads paths from the binary's database.
        """
        if not tbl: return
        self.__give_feedback(but, "Loading Paths...")
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
                    self._log.warn(self._tag, f"Loaded path seems to origin from another binary")
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
        if not tbl: return
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
                    self._log.warn(self._tag, f"Loaded path seems to origin from another binary")
                path = Path.from_dict(bv, s_path)
                self.add_path_to_view(path, s_path["comment"])
            self._log.info(self._tag, f"Imported {len(s_paths):d} path(s)")
        except Exception as e:
            self._log.error(self._tag, f"Failed to import paths: {str(e):s}")
        return
    
    def save_paths(
            self,
            bv: bn.BinaryView,
            but: qtw.QPushButton,
            tbl: qtw.QTableWidget
        ) -> None:
        """
        This method stores paths to the binary's database.
        """
        if not tbl: return
        self.__give_feedback(but, "Saving Paths...")
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
        if not tbl: return
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
        if not tbl: return
        if len(rows) != 1: return
        path_id = tbl.item(rows[0], 0).data(qtc.Qt.ItemDataRole.UserRole)
        path = self._paths[path_id]
        if not path: return
        msg = f"Path {path_id:d}: {str(path):s}"
        msg = f"{msg:s} [L:{len(path.insts):d},P:{len(path.phiis):d},B:{len(path.bdeps):d}]!"
        self._log.info(self._tag, msg)
        self._log.debug(self._tag, "--- Backward Slice ---")
        basic_block = None
        insts = path.insts if not reverse else reversed(path.insts)
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
        if not tbl: return
        if len(rows) != 2: return

        # Get instructions of path 0
        path_0_id = tbl.item(rows[0], 0).data(qtc.Qt.ItemDataRole.UserRole)
        path_0: Path = self._paths[path_0_id]
        if not path_0: return
        path_0_insts = [InstructionHelper.get_inst_info(inst, False) for inst in path_0.insts] 

        # Get instructions of path 1
        path_1_id = tbl.item(rows[1], 0).data(qtc.Qt.ItemDataRole.UserRole)
        path_1: Path = self._paths[path_1_id]
        if not path_1: return
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
        if not tbl: return
        if len(rows) != 1: return
        path_id = tbl.item(rows[0], 0).data(qtc.Qt.ItemDataRole.UserRole)
        path = self._paths[path_id]
        if not path: return
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
            except:
                color = bn.HighlightStandardColor.RedHighlightColor
            for inst in path.insts:
                func = inst.function.source_function
                addr = inst.address
                if not addr in insts_colors:
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
        if not tbl: return
        if len(rows) != 1: return
        path_id = tbl.item(rows[0], 0).data(qtc.Qt.ItemDataRole.UserRole)
        path = self._paths[path_id]
        if not path: return
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
        if not tbl: return
        for c, row in enumerate(sorted(rows, reverse=True)):
            if row < 0: continue
            path_id = tbl.item(row, 0).data(qtc.Qt.ItemDataRole.UserRole)
            del self._paths[path_id-c]
            tbl.removeRow(row)
        for row in range(tbl.rowCount()):
            tbl.setItem(row, 0, IntTableWidgetItem(row, as_hex=False))
        self._log.info(self._tag, f"Removed {len(rows):d} path(s)")
        return
    
    def remove_all_paths(
            self,
            tbl: qtw.QTableWidget
        ) -> None:
        """
        This method removes all paths from the table `tbl`.
        """
        if not tbl: return
        self._paths.clear()
        tbl.setRowCount(0)
        self._log.info(self._tag, "Removed all path(s)")
        return
        

class MediumLevelILBackwardSlicerThread(bn.BackgroundTaskThread):
    """
    This class implements a background thread that runs backward slicing for MLIL instructions.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            ctr: Controller,
            tag: str,
            log: Logger,
            runs_headless: bool = False,
            max_call_level: int = None,
            max_slice_depth: int = None,
            enable_all_funs: bool = False
        ) -> None:
        """
        This method initializes a background task that backward slices MLIL instructions.
        """
        super().__init__(initial_progress_text="Start slicing...", can_cancel=True)
        self._bv: bn.BinaryView = bv
        self._ctr: Controller = ctr
        self._tag: str = tag
        self._log: Logger = log
        self._runs_headless: bool = runs_headless
        self._max_call_level: int = max_call_level
        self._max_slice_depth: int = max_slice_depth
        self._enable_all_funs: bool = enable_all_funs
        return
    
    def run(self) -> None:
        """
        This method tries to identify intersting code paths using static backward slicing.
        """
        self._paths: List[Path] = []
        self._log.info(self._tag, "Starting analysis")

        # Source functions
        src_funs = self._ctr.get_functions("Sources", not self._enable_all_funs)
        if not src_funs:
            self._log.warn(self._tag, "No source functions configured")
        else:
            for i, src_fun in enumerate(src_funs):
                if self.cancelled: break
                self.progress = f"Find targets for source function {i+1:d}/{len(src_funs):d}..."
                src_fun.find_targets(self._bv, lambda: self.cancelled, self._tag, self._log)

        # Sink functions
        snk_funs = self._ctr.get_functions("Sinks", not self._enable_all_funs)
        if not snk_funs:
            self._log.warn(self._tag, "No sink functions configured")

        # Settings
        settings = self._ctr.get_settings()
        max_call_level = self._max_call_level if self._max_call_level is not None else settings.get("max_call_level").value
        max_slice_depth = self._max_slice_depth if self._max_slice_depth is not None else settings.get("max_slice_depth").value
        
        # Find paths
        if src_funs and snk_funs:
            for i, snk_fun in enumerate(snk_funs):
                if self.cancelled: break
                self.progress = f"Find paths for sink function {i+1:d}/{len(snk_funs):d}..."
                paths = snk_fun.find_paths(
                    bv=self._bv,
                    sources=src_funs,
                    max_call_level=max_call_level,
                    max_slice_depth=max_slice_depth,
                    found_path=self._ctr.add_path_to_view,
                    canceled=lambda:self.cancelled,
                    tag=self._tag,
                    log=self._log
                )
                self._paths.extend(paths)
        self._log.info(self._tag, "Analysis finished")
        return
    
    def get_paths(self) -> List[Path]:
        """
        This method blocks until backward slicing finished and then returns all identified
        interesting looking code paths.
        """
        self.join()
        return self._paths