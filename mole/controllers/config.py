from __future__ import annotations
from ..models.config import ConfigModel
from ..common.log import Logger
from ..common.parse import LogicalExpressionParser
from ..core.data import Configuration, SourceFunction, SinkFunction, Category, Library, SpinboxSetting, ComboboxSetting
from typing import Dict, Any, TYPE_CHECKING, List
import os
import yaml
import fnmatch as fn

if TYPE_CHECKING:
    import PySide6.QtWidgets as qtw

class ConfigController:
    """
    This class implements the controller for the configuration.
    """
    
    def __init__(self, model: ConfigModel, main_controller: Any, log: Logger) -> None:
        """
        This method initializes the configuration controller.
        """
        self._model = model
        self._main_controller = main_controller
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
    
    def get_functions(self, type: str, enabled_only: bool = False) -> List[Any]:
        """
        This method returns all (enabled) source or sink functions.
        """
        funs = []
        libs = self.get_libraries(type)
        for lib in libs.values():
            for cat in lib.categories.values():
                for fun in cat.functions.values():
                    if not enabled_only or fun.enabled:
                        funs.append(fun)
        return funs
    
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
    
    def checkbox_toggle(self, function: Any) -> None:
        """
        This method handles checkbox toggle events.
        """
        self._main_controller.checkbox_toggle(function)
        
    def checkboxes_check(self, category: Any, checked: bool) -> None:
        """
        This method handles selecting/deselecting all checkboxes.
        """
        self._main_controller.checkboxes_check(category, checked)
        
    def spinbox_change_value(self, setting: Any, value: int) -> None:
        """
        This method handles spinbox value changes.
        """
        self._main_controller.spinbox_change_value(setting, value)
        
    def combobox_change_value(self, setting: Any, value: str) -> None:
        """
        This method handles combobox value changes.
        """
        self._main_controller.combobox_change_value(setting, value)
        
    def store_main_conf_file(self, button: "qtw.QPushButton") -> None:
        """
        This method stores the configuration to a file.
        """
        self._main_controller.store_main_conf_file(button)
        
    def reset_conf(self, button: "qtw.QPushButton") -> None:
        """
        This method resets the configuration.
        """
        self._main_controller.reset_conf(button)