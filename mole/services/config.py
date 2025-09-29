from __future__ import annotations
from mole.common.log import log
from mole.common.parse import LogicalExpressionParser
from mole.core.data import (
    Category,
    ComboboxSetting,
    Configuration,
    DoubleSpinboxSetting,
    Library,
    SinkFunction,
    SourceFunction,
    SpinboxSetting,
    TextSetting,
)
from mole.grouping import get_all_grouping_strategies
from typing import Dict
import fnmatch as fn
import os as os
import yaml as yaml


tag = "Mole.Config"


class ConfigService:
    """
    This class implements a service to handle Mole's configuration.
    """

    def __init__(self, config_file: str = "") -> None:
        """
        This method initializes a configuration service.
        """
        self._config_file = config_file
        self._config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "../conf/"
        )
        self._parser = LogicalExpressionParser()
        return

    def load_config(self) -> Configuration:
        """
        This method loads all configuration files and returns a complete `Configuration` object.
        """
        # Initialize empty configuration
        config = Configuration(
            sources={
                "manual": Library(
                    name="manual",
                )
            },
            sinks={
                "manual": Library(
                    name="manual",
                )
            },
        )
        # Load custom configuration files
        custom_config = self.load_custom_config()
        self.update_config(config, custom_config)
        # Load main configuration file
        main_config = self.load_main_config()
        self.update_config(config, main_config)
        return config

    def load_custom_config(self) -> Configuration:
        """
        This method loads all custom configuration files.
        """
        config = Configuration()
        config_files = sorted(os.listdir(self._config_path))
        for config_file in config_files:
            if (
                not (
                    fn.fnmatch(config_file, "*.yml")
                    or fn.fnmatch(config_file, "*.yaml")
                )
                or config_file == "000-mole.yml"
            ):
                continue
            # Open configuration file
            try:
                with open(os.path.join(self._config_path, config_file), "r") as f:
                    config_dict = yaml.safe_load(f)
            except Exception as e:
                log.warn(
                    tag,
                    f"Failed to open configuration file '{config_file:s}': '{str(e):s}'",
                )
                continue
            # Parse configuration file
            custom_config = self._parse_config(config_dict)
            self.update_config(config, custom_config)
        return config

    def load_main_config(self) -> Configuration:
        """
        This method loads the main configuration file.
        """
        config = Configuration()
        config_files = [os.path.join(self._config_path, "000-mole.yml")]
        if self._config_file:
            config_files.append(self._config_file)
        for config_file in config_files:
            # Open configuration file
            try:
                with open(config_file) as f:
                    config_dict = yaml.safe_load(f)
            except Exception as e:
                log.warn(
                    tag,
                    f"Failed to open configuration file '{config_file:s}': '{str(e):s}'",
                )
                continue
            # Parse configuration file
            main_config = self._parse_config(config_dict)
            self.update_config(config, main_config)
        return config

    def save_config(self, configuration: Configuration, config_file: str = "") -> None:
        """
        This method save the given configuration to the specified file. If no file is given, the
        configuration is saved to the default main configuration file.
        """
        if not config_file:
            config_file = os.path.join(self._config_path, "000-mole.yml")
        with open(config_file, "w") as f:
            yaml.safe_dump(
                configuration.to_dict(),
                f,
                sort_keys=False,
                default_style=None,
                default_flow_style=False,
                encoding="utf-8",
            )
        return

    def update_config(self, target: Configuration, source: Configuration) -> None:
        """
        This method updates the `target` `Configuration` with data from `source` `Configuration`.
        """
        if not source:
            return
        # Update sources and sinks
        for type in ["sources", "sinks"]:
            match type:
                case "sources":
                    new_libs = source.sources
                    old_libs = target.sources
                case "sinks":
                    new_libs = source.sinks
                    old_libs = target.sinks
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
        return

    def _parse_config(self, config: Dict) -> Configuration:
        """
        This method parse the plain configuration `conf` into a `Configuration` instance.
        """
        parsed_config = {"sources": {}, "sinks": {}, "settings": {}}
        if not config:
            return Configuration(**parsed_config)
        try:
            # Parse sources and sinks
            for type in ["sources", "sinks"]:
                libs = config.get(type, {})
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
                    parsed_config[type][lib_name] = Library(lib_name, lib_categories)
            # Parse settings
            settings: Dict[str, Dict] = config.get("settings", {})
            for name in [
                "max_workers",
                "max_call_level",
                "max_slice_depth",
                "max_memory_slice_depth",
                "max_turns",
                "max_completion_tokens",
            ]:
                setting: Dict = settings.get(name, None)
                if not setting:
                    continue
                value = setting.get("value", None)
                min_value = int(setting.get("min_value", None))
                max_value = int(setting.get("max_value", None))
                value = min(max(value, min_value), max_value)
                help = setting.get("help", "")
                parsed_config["settings"].update(
                    {
                        name: SpinboxSetting(
                            name=name,
                            value=value,
                            help=help,
                            min_value=min_value,
                            max_value=max_value,
                        )
                    }
                )
            for name in ["temperature"]:
                setting: Dict = settings.get(name, None)
                if not setting:
                    continue
                value = setting.get("value", None)
                min_value = float(setting.get("min_value", None))
                max_value = float(setting.get("max_value", None))
                value = min(max(value, min_value), max_value)
                help = setting.get("help", "")
                parsed_config["settings"].update(
                    {
                        name: DoubleSpinboxSetting(
                            name=name,
                            value=value,
                            help=help,
                            min_value=min_value,
                            max_value=max_value,
                        )
                    }
                )
            for name in ["src_highlight_color", "snk_highlight_color", "path_grouping"]:
                setting = settings.get(name, None)
                if not setting:
                    continue
                value = setting.get("value", "")
                help = setting.get("help", "")
                if name == "path_grouping":
                    items = get_all_grouping_strategies()
                else:
                    items = setting.get("items", [])
                parsed_config["settings"].update(
                    {
                        name: ComboboxSetting(
                            name=name, value=value, help=help, items=items
                        )
                    }
                )
            for name in ["openai_base_url", "openai_api_key", "openai_model"]:
                setting = settings.get(name, None)
                if not setting:
                    continue
                value = setting.get("value", "")
                help = setting.get("help", "")
                parsed_config["settings"].update(
                    {name: TextSetting(name=name, value=value, help=help)}
                )
        except Exception as e:
            log.warn(tag, f"Failed to parse configuration file: '{str(e):s}'")
        return Configuration(**parsed_config)
