from __future__ import annotations
from mole.common.log import log
from mole.common.parse import LogicalExpressionParser
from mole.core.data import (
    Category,
    CheckboxSetting,
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

    def _parse_config(
        self, config: Dict, ignore_enabled: bool = False
    ) -> Configuration:
        """
        This method parses the plain configuration `conf` into a `Configuration` instance. If
        `ignore_enabled` is `True`, all functions will be disabled.
        """
        parsed_config = {"sources": {}, "sinks": {}, "settings": {}}
        if not config:
            return Configuration(**parsed_config)
        try:
            # Parse sources and sinks
            for type in ["sources", "sinks"]:
                libs: Dict[str, Dict] = config.get(type, {})
                for lib_name, lib in libs.items():
                    lib_categories = {}
                    categories: Dict[str, Dict] = lib.get("categories", {})
                    for cat_name, cat in categories.items():
                        cat_functions = {}
                        functions: Dict[str, Dict] = cat.get("functions", {})
                        for fun_name, fun in functions.items():
                            match type:
                                case "sources":
                                    fun = SourceFunction(name=fun_name, **fun)
                                case "sinks":
                                    fun = SinkFunction(name=fun_name, **fun)
                                case _:
                                    continue
                            fun.par_cnt_fun = self._parser.parse(fun.par_cnt)
                            fun.par_dataflow_fun = self._parser.parse(fun.par_dataflow)
                            fun.par_slice_fun = self._parser.parse(fun.par_slice)
                            fun.enabled = fun.enabled if not ignore_enabled else False
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
                try:
                    min_value = int(setting["min_value"])
                    max_value = int(setting["max_value"])
                    value = min(max(setting["value"], min_value), max_value)
                    help = setting["help"]
                except KeyError as e:
                    log.warn(
                        tag,
                        f"Failed to parse setting '{name:s}' due to a missing key: {str(e):s}",
                    )
                    continue
                except Exception as e:
                    log.warn(tag, f"Failed to parse setting '{name:s}': {str(e):s}")
                    continue
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
            for name in ["fix_func_type"]:
                setting: Dict = settings.get(name, None)
                if not setting:
                    continue
                try:
                    value = setting["value"]
                    help = setting["help"]
                except KeyError as e:
                    log.warn(
                        tag,
                        f"Failed to parse setting '{name:s}' due to a missing key: {str(e):s}",
                    )
                    continue
                except Exception as e:
                    log.warn(tag, f"Failed to parse setting '{name:s}': {str(e):s}")
                    continue
                parsed_config["settings"].update(
                    {
                        name: CheckboxSetting(
                            name=name,
                            value=value,
                            help=help,
                        )
                    }
                )
            for name in ["temperature"]:
                setting: Dict = settings.get(name, None)
                if not setting:
                    continue
                try:
                    min_value = float(setting["min_value"])
                    max_value = float(setting["max_value"])
                    value = min(max(setting["value"], min_value), max_value)
                    help = setting["help"]
                except KeyError as e:
                    log.warn(
                        tag,
                        f"Failed to parse setting '{name:s}' due to a missing key: {str(e):s}",
                    )
                    continue
                except Exception as e:
                    log.warn(tag, f"Failed to parse setting '{name:s}': {str(e):s}")
                    continue
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
                try:
                    value = setting["value"]
                    help = setting["help"]
                except KeyError as e:
                    log.warn(
                        tag,
                        f"Failed to parse setting '{name:s}' due to a missing key: {str(e):s}",
                    )
                    continue
                except Exception as e:
                    log.warn(tag, f"Failed to parse setting '{name:s}': {str(e):s}")
                    continue
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
                try:
                    value = setting["value"]
                    help = setting["help"]
                except KeyError as e:
                    log.warn(
                        tag,
                        f"Failed to parse setting '{name:s}' due to a missing key: {str(e):s}",
                    )
                    continue
                except Exception as e:
                    log.warn(tag, f"Failed to parse setting '{name:s}': {str(e):s}")
                    continue
                parsed_config["settings"].update(
                    {name: TextSetting(name=name, value=value, help=help)}
                )
        except Exception as e:
            log.warn(tag, f"Failed to parse configuration: '{str(e):s}'")
        return Configuration(**parsed_config)

    def load_config(self) -> Configuration:
        """
        This method loads all configuration files and returns a complete `Configuration` object.
        """
        # Use dedicated configuration file (CLI option)
        if self._config_file:
            custom_config = self.load_custom_config(ignore_enabled=True)
            import_config = self.import_config(self._config_file)
            self.update_config(custom_config, import_config)
        # Use default configuration file
        else:
            custom_config = self.load_custom_config(ignore_enabled=False)
            stored_config = self.load_main_config()
            self.update_config(custom_config, stored_config)
        return custom_config

    def load_custom_config(self, ignore_enabled: bool = False) -> Configuration:
        """
        This method loads all custom configuration files. If `ignore_enabled` is `True`, all
        functions will be disabled.
        """
        config = Configuration()
        config_files = sorted(os.listdir(self._config_path))
        for config_file in config_files:
            # Filter configuration files
            if (
                not (
                    fn.fnmatch(config_file, "*.yml")
                    or fn.fnmatch(config_file, "*.yaml")
                )
                or config_file == "000-mole.yml"
            ):
                continue
            # Load configuration file
            custom_config = self.import_config(
                os.path.join(self._config_path, config_file), ignore_enabled
            )
            # Update configuration
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
            # Load configuration file
            main_config = self.import_config(config_file)
            # Update configuration
            self.update_config(config, main_config)
        return config

    def save_config(self, config: Configuration) -> None:
        """
        This method saves the given configuration.
        """
        # Serialize configuration to dictionary
        config_dict = config.to_dict()
        # Write configuration to file
        config_file = os.path.join(self._config_path, "000-mole.yml")
        with open(config_file, "w") as f:
            yaml.safe_dump(
                config_dict,
                f,
                sort_keys=False,
                default_style=None,
                default_flow_style=False,
                encoding="utf-8",
            )
        # Write manual functions to file
        manual_file = os.path.join(self._config_path, "002-manual.yml")
        with open(manual_file, "w") as f:
            sources: Dict[str, Dict] = config_dict.get("sources", {})
            sinks: Dict[str, Dict] = config_dict.get("sinks", {})
            yaml.safe_dump(
                {
                    "sources": {"manual": sources.get("manual", {})},
                    "sinks": {"manual": sinks.get("manual", {})},
                },
                f,
                sort_keys=False,
                default_style=None,
                default_flow_style=False,
                encoding="utf-8",
            )
        return

    def import_config(
        self, config_file: str, ignore_enabled: bool = False
    ) -> Configuration:
        """
        This method loads a configuration from the given file (open and parse). If `ignore_enabled`
        is `True`, all functions will be disabled.
        """
        try:
            # Open configuration file
            with open(config_file) as f:
                config_dict = yaml.safe_load(f)
            # Parse configuration file
            config = self._parse_config(config_dict, ignore_enabled)
            return config
        except FileNotFoundError:
            log.warn(tag, f"Configuration file '{config_file:s}' not found")
        except Exception as e:
            log.warn(
                tag,
                f"Failed to parse configuration file '{config_file:s}': '{str(e):s}'",
            )
        # Parse configuration file
        return Configuration()

    def export_config(self, config: Configuration, config_file: str) -> None:
        """
        This method exports the given configuration to the specified file.
        """
        # Serialize configuration to dictionary
        config_dict = config.to_dict()
        # Write configuration to file
        with open(config_file, "w") as f:
            yaml.safe_dump(
                config_dict,
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
