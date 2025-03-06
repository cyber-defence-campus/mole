from __future__ import annotations
from typing import Dict, Any, TYPE_CHECKING, List
import os
import yaml
import fnmatch as fn

from ..models.config import ConfigModel
from ..common.log import Logger
from ..common.parse import LogicalExpressionParser
from ..core.data import Function, Configuration, SourceFunction, SinkFunction, Category, Library, SpinboxSetting, ComboboxSetting
from ..views.config import ConfigView

if TYPE_CHECKING:
    import PySide6.QtWidgets as qtw

class ConfigController:
    """
    This class implements the controller for the configuration.
    """
    
    def __init__(self, model: ConfigModel, view: ConfigView, log: Logger) -> None:
        """
        This method initializes the configuration controller.
        """
        self._model = model
        self._view = view
        self._log = log
        self._parser = LogicalExpressionParser(tag="Config", log=log)
        self._conf_path: str = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "../../conf/"
        )
        
    def get_libraries(self, type_name: str) -> Dict[str, Any]:
        """
        This method returns the libraries of the given type.
        """
        return self._model.get_libraries(type_name)
    
    def get_settings(self) -> Dict[str, Any]:
        """
        This method returns the settings.
        """
        return self._model.get_settings()
    
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
                    "Config",
                    f"Failed to open configuration file '{conf_file:s}': '{str(e):s}'"
                )
                continue
            # Parse configuration file
            conf = self.parse_conf(conf)
            # Update model
            self._model.update_configuration(conf)
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
                    "Config",
                    f"Failed to open configuration file '000-mole.yml': '{str(e):s}'"
                )
            return
        # Parse configuration file
        conf = self.parse_conf(conf)
        # Update model
        self._model.update_configuration(conf)

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
            settings: Dict[str, Dict] = conf.get("settings", {})
            for name in ["max_workers", "max_call_level", "max_slice_depth"]:
                setting: Dict = settings.get(name, None)
                if not setting:
                    continue
                value = setting.get("value", None)
                min_value = int(setting.get("min_value", None))
                max_value = int(setting.get("max_value", None))
                value = min(max(value, min_value), max_value)
                help = setting.get("help", "")
                parsed_conf["settings"].update({
                    name: SpinboxSetting(
                        name=name,
                        value=value,
                        help=help,
                        min_value=min_value,
                        max_value=max_value
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
                "Config",
                f"Failed to parse configuration file: '{str(e):s}'"
            )
        return Configuration(**parsed_conf)
    
    def checkbox_toggle(self, function: Function) -> None:
        """
        This method handles checkbox toggle events.
        """
        function.enabled = not function.enabled
        
    def checkboxes_check(self, cat: Category, checked: bool) -> None:
        """
        This method handles selecting/deselecting all checkboxes.
        """
        for fun in cat.functions.values():
            fun.enabled = checked
            fun.checkbox.setChecked(checked)
        
    def spinbox_change_value(self, setting: SpinboxSetting, value: int) -> None:
        """
        This method updates the model to reflect spinbox value changes.
        """
        setting.value = value
        
    def combobox_change_value(self, setting: ComboboxSetting, value: str) -> None:
        """
        This method updates the model to reflect combobox value changes.
        """
        setting.value = value
        
    def store_main_conf_file(self) -> None:
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
        self._view.give_feedback("Saving...")
        
    def reset_conf(self) -> None:
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
        self._view.give_feedback("Resetting...")