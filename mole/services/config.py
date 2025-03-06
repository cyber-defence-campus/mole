from __future__ import annotations
from typing import Dict, List, Optional
import os
import yaml
import fnmatch as fn

from ..core.data import SourceFunction, SinkFunction, Configuration, Library, Category, SpinboxSetting, ComboboxSetting
from ..common.parse import LogicalExpressionParser

class ConfigService:
    def __init__(self, logger):
        self._conf_path: str = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "../../conf/"
        )
        self._log = logger
        self._parser = LogicalExpressionParser(tag="Config", log=logger)
    
    def load_configuration(self) -> Configuration:
        """
        Load all configuration files and return a complete Configuration object
        """
        # Initialize with an empty configuration
        configuration = Configuration(sources={}, sinks={}, settings={})
        
        # Load main configuration first
        main_conf = self._load_main_conf_file()
        if main_conf:
            configuration = main_conf
            
        # Load custom configuration files
        custom_confs = self._load_custom_conf_files()
        for conf in custom_confs:
            self._update_configuration(configuration, conf)
            
        return configuration
    
    
    def _load_custom_conf_files(self) -> List[Configuration]:
        """
        Load the custom configuration files and return a list of Configuration objects.
        """
        configurations = []
        for conf_file in sorted(os.listdir(self._conf_path)):
            if not fn.fnmatch(conf_file, "*.yml") or conf_file == "000-mole.yml": continue
            # Open configuration file
            try:
                with open(os.path.join(self._conf_path, conf_file), "r") as f:
                    conf_dict = yaml.safe_load(f)
            except Exception as e:
                if hasattr(self, '_log'):
                    self._log.warn(
                        "Config",
                        f"Failed to open configuration file '{conf_file:s}': '{str(e):s}'"
                    )
                continue
            # Parse configuration file
            conf = self._parse_conf(conf_dict)
            if conf:
                configurations.append(conf)
        return configurations
    
    def _load_main_conf_file(self) -> Optional[Configuration]:
        """
        Load the main configuration file and return a Configuration object or None.
        """
        # Open configuration file
        try:
            with open(os.path.join(self._conf_path, "000-mole.yml")) as f:
                conf_dict = yaml.safe_load(f)
        except FileNotFoundError:
            return None
        except Exception as e:
            if hasattr(self, '_log'):
                self._log.warn(
                        "Config",
                        f"Failed to open configuration file '000-mole.yml': '{str(e):s}'"
                    )
            return None
        # Parse configuration file
        return self._parse_conf(conf_dict)

    def store_configuration(self, configuration: Configuration) -> None:
        """
        Store the main configuration file based on the provided Configuration object.
        """
        # Store model
        with open(os.path.join(self._conf_path, "000-mole.yml"), "w") as f:
            yaml.safe_dump(
                configuration.to_dict(),
                f,
                sort_keys=False,
                default_style=None,
                default_flow_style=False,
                encoding="utf-8"
            )

    def _update_configuration(self, target: Configuration, source: Configuration) -> None:
        """
        Update target configuration with data from source configuration.
        """
        if not source: return
        
        # Update sources and sinks
        for type in ["sources", "sinks"]:
            match type:
                case "sources":
                    new_libs = source.sources
                    old_libs = target.sources
                case "sinks":
                    new_libs = source.sinks
                    old_libs = target.sinks
                case _:
                    new_libs = {}
                    old_libs = {}
            for new_lib_name, new_lib in new_libs.items():
                if new_lib_name not in old_libs:
                    old_libs[new_lib_name] = new_lib
                    continue
                old_lib = old_libs[new_lib_name]
                for new_cat_name, new_cat in new_lib.categories.items():
                    if new_cat_name not in old_lib.categories:
                        old_lib.categories[new_cat_name] = new_cat
                        continue
                    old_cat = old_lib.categories[new_cat_name]
                    for new_fun_name, new_fun in new_cat.functions.items():
                        old_cat.functions[new_fun_name] = new_fun
        # Update settings
        new_settings = source.settings
        old_settings = target.settings
        for new_setting_name, new_setting in new_settings.items():
            old_settings[new_setting_name] = new_setting

    def _parse_conf(self, conf: Dict) -> Configuration:
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