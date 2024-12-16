from __future__        import annotations
from ..common.parse    import LogicalExpressionParser
from ..common.log      import Logger
from .data             import *
from typing            import Dict, List, Literal, Union
import binaryninja       as bn
import copy              as copy
import fnmatch           as fn
import os                as os
import PySide6.QtCore    as qtc
import PySide6.QtWidgets as qtw
import yaml              as yaml


class Controller:
    """
    This class implements the plugin's controller.
    """

    def __init__(
            self,
            runs_headless: bool = False,
            tag: str = "Controller",
            log: Logger = Logger(level="debug")
        ) -> None:
        self._runs_headless = runs_headless
        self._tag = tag
        self._log = log
        self._thread = None
        self._model = None
        self._view = None
        self._conf_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "../../conf/"
        )
        self._parser = LogicalExpressionParser(log=log)
        self._paths = {}
        self._paths_widget = None
        return
    
    def init(self) -> Controller:
        """
        This method initializes the plugin's model and view.
        """
        from .model import SidebarModel
        self._model = SidebarModel(self, self._tag, self._log).init()
        if not self._runs_headless:
            from .view import SidebarView
            self._view = SidebarView(self, self._tag, self._log).init()
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
            mfd_name = "max_func_depth"
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
                        help=mfd_help,
                        value=mfd_value,
                        min_value=mfd_min_value,
                        max_value=mfd_max_value
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

    def analyze_binary(
            self,
            bv: bn.BinaryView,
            max_func_depth: int = None,
            enable_all_funs: bool = False,
            button: qtw.QPushButton = None,
            widget: qtw.QListWidget = None
        ) -> None | List[
            Dict[str, Union[str, Dict[str, Union[int, bn.MediumLevelILInstruction]]]]
        ]:
        """
        This method analyzes the entire binary for interesting looking code paths.
        """
        # Require a binary to be loaded
        if not bv:
            self._log.warn(self._tag, "No binary loaded.")
            self.__give_feedback(button, "No binary loaded...")
            return
        # Require previous analyses to complete
        if self._thread and not self._thread.finished:
            self._log.warn(self._tag, "Analysis already running.")
            self.__give_feedback(button, "Analysis already running...")
            return
        # Initialize data structures
        self._paths = {}
        if widget:
            self._paths_widget = widget
            self._paths_widget.clear()
        # Run background thread
        self._thread = MediumLevelILBackwardSlicerThread(
            bv=bv,
            ctr=self,
            runs_headless=self._runs_headless,
            max_func_depth=max_func_depth,
            enable_all_funs=enable_all_funs,
            log=self._log
        )
        self._thread.start()
        if self._runs_headless:
            return self._thread.get_paths()
        return None
    
    def add_path_to_view(
            self,
            path: Path
        ) -> None:
        """
        This method updates the UI with a newly identified path.
        """
        def update_paths_widget() -> None:
            if not self._paths_widget:
                return
            self._paths[str(path)] = path
            self._paths_widget.addItem(str(path))
        
        bn.execute_on_main_thread(update_paths_widget)
        return
    
    def select_path(self, item: qtw.QListWidgetItem) -> None:
        """
        This method logs information about a path.
        """
        if not item: return
        path = self._paths.get(item.text(), None)
        if not path: return
        msg = f"Selected path: {str(path):s}"
        msg = f"{msg:s} [L: {len(path.insts):d}, B:{len(path.bdeps):d}]!"
        self._log.info(self._tag, msg)
        self._log.debug(self._tag, "--- Backward Slice ---")
        basic_block = None
        for inst in path.insts:
            if inst.il_basic_block != basic_block:
                basic_block = inst.il_basic_block
                fun_name = basic_block.function.name
                bb_addr = basic_block[0].address
                self._log.debug(self._tag, f"- FUN: '{fun_name:s}', BB: 0x{bb_addr:x}")
            self._log.debug(self._tag, InstructionHelper.get_inst_info(inst))
        self._log.debug(self._tag, "----------------------")
        return

    def highlight_path(self, item: qtw.QListWidgetItem) -> None:
        """
        TODO: This method highlights all instructions in a path.
        """
        if not item: return
        path = self._paths.get(item.text(), None)
        if not path: return
        msg = f"Highlighted path: {str(path):s}"
        msg = f"{msg:s} [L: {len(path.insts):d}, B:{len(path.bdeps):d}]!"
        self._log.debug(self._tag, msg)
        return


class MediumLevelILBackwardSlicerThread(bn.BackgroundTaskThread):
    """
    This class implements a background thread that runs backward slicing for MLIL instructions.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            ctr: Controller,
            runs_headless: bool = False,
            max_func_depth: int = None,
            enable_all_funs: bool = False,
            tag: str = "BackSlicer",
            log: Logger = Logger()
        ) -> None:
        super().__init__(initial_progress_text="Start slicing...", can_cancel=True)
        self._bv = bv
        self._ctr = ctr
        self._runs_headless = runs_headless
        self._max_func_depth = max_func_depth
        self._enable_all_funs = enable_all_funs
        self._tag = tag
        self._log = log
        return
    
    def run(self) -> None:
        """
        This method tries to identify intersting code paths using static backward slicing.
        """
        self._paths = []

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

        # Find paths
        max_func_depth = self._max_func_depth
        if max_func_depth is None:
            settings = self._ctr.get_settings()
            max_func_depth = settings.get("max_func_depth").value
        if src_funs and snk_funs:
            for i, snk_fun in enumerate(snk_funs):
                if self.cancelled: break
                self.progress = f"Find paths for sink function {i+1:d}/{len(snk_funs):d}..."
                paths = snk_fun.find_paths(
                    bv=self._bv,
                    sources=src_funs,
                    max_func_depth=max_func_depth,
                    found_path=self._ctr.add_path_to_view,
                    canceled=lambda:self.cancelled,
                    tag=self._tag,
                    log=self._log
                )
                self._paths.extend(paths)
        return
    
    def get_paths(self) -> List[Path]:
        """
        This method blocks until backward slicing finished and then returns all identified
        interesting looking code paths.
        """
        self.join()
        return self._paths