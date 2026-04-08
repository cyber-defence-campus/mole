from __future__ import annotations
from mole.common.log import Logger
from mole.data.config import (
    Category,
    ComboboxSetting,
    Configuration,
    DoubleSpinboxSetting,
    Function,
    Library,
    SpinboxSetting,
    TextSetting,
)
from mole.grouping import get_all_grouping_strategies
from typing import Dict
import fnmatch as fn
import json
import os


tag = "Config"


class ConfigService:
    """
    This class implements a service for Mole's configuration.
    """

    def __init__(self, log: Logger, config_file: str = "") -> None:
        """
        This method initializes the configuration service.
        """
        self.log = log
        self._config_file = config_file
        self._config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "../conf/"
        )
        return

    def _parse_config(
        self, config: Dict, ignore_enabled: bool = False
    ) -> Configuration:
        """
        This method parses the plain configuration `config` into a `Configuration` instance. If
        `ignore_enabled` is `True`, all functions will be disabled.
        """
        cfg = Configuration()
        try:
            # Parse taint model
            taint_model_dict = config.get("taint_model", None)
            if not isinstance(taint_model_dict, dict):
                taint_model_dict = {}
            for lib_name, lib_dict in taint_model_dict.items():
                if not lib_name or not isinstance(lib_dict, dict):
                    continue
                for cat_name, cat_dict in lib_dict.items():
                    if not cat_name or not isinstance(cat_dict, dict):
                        continue
                    for fun_name, fun_dict in cat_dict.items():
                        if not fun_name or not isinstance(fun_dict, dict):
                            continue
                        aliases = fun_dict.get("aliases", None)
                        if not isinstance(aliases, list):
                            aliases = []
                        synopsis = fun_dict.get("synopsis", None)
                        if not isinstance(synopsis, str):
                            synopsis = ""
                        roles = fun_dict.get("roles", None)
                        if not isinstance(roles, dict):
                            roles = {}
                        src_role = roles.get("source", None)
                        if not isinstance(src_role, dict):
                            src_role = {}
                        src_enabled = src_role.get("enabled", None)
                        if not isinstance(src_enabled, bool):
                            src_enabled = False
                        src_par_slice = src_role.get("par_slice", None)
                        if not isinstance(src_par_slice, str):
                            src_par_slice = "False"
                        snk_role = roles.get("sink", None)
                        if not isinstance(snk_role, dict):
                            snk_role = {}
                        snk_enabled = snk_role.get("enabled", None)
                        if not isinstance(snk_enabled, bool):
                            snk_enabled = False
                        snk_par_slice = snk_role.get("par_slice", None)
                        if not isinstance(snk_par_slice, str):
                            snk_par_slice = "False"
                        fix_role = roles.get("fixer", None)
                        if not isinstance(fix_role, dict):
                            fix_role = {}
                        fix_enabled = fix_role.get("enabled", None)
                        if not isinstance(fix_enabled, bool):
                            fix_enabled = False
                        lib = cfg.taint_model.setdefault(lib_name, Library(lib_name))
                        cat = lib.categories.setdefault(cat_name, Category(cat_name))
                        fun = Function(
                            name=fun_name,
                            symbols=[fun_name] + aliases,
                            synopsis=synopsis,
                            src_enabled=False if ignore_enabled else src_enabled,
                            src_par_slice=src_par_slice,
                            snk_enabled=False if ignore_enabled else snk_enabled,
                            snk_par_slice=snk_par_slice,
                            fix_enabled=False if ignore_enabled else fix_enabled,
                        )
                        cat.functions[fun_name] = fun
            # Parse settings
            sets_dict = config.get("settings", None)
            if not isinstance(sets_dict, dict):
                sets_dict = {}
            for set_name in [
                "max_workers",
                "max_call_level",
                "max_slice_depth",
                "max_memory_slice_depth",
                "max_turns",
                "max_completion_tokens",
            ]:
                set_dict = sets_dict.get(set_name, None)
                if not isinstance(set_dict, dict):
                    continue
                try:
                    min_value = int(set_dict["min_value"])
                    max_value = int(set_dict["max_value"])
                    value = min(max(set_dict["value"], min_value), max_value)
                    help = set_dict["help"]
                except KeyError as e:
                    self.log.warn(
                        tag,
                        f"Failed to parse setting '{set_name:s}' due to a missing key: {str(e):s}",
                    )
                    continue
                except Exception as e:
                    self.log.warn(
                        tag, f"Failed to parse setting '{set_name:s}': {str(e):s}"
                    )
                    continue
                cfg.settings[set_name] = SpinboxSetting(
                    name=set_name,
                    value=value,
                    help=help,
                    min_value=min_value,
                    max_value=max_value,
                )
            for set_name in ["temperature"]:
                set_dict = sets_dict.get(set_name, None)
                if not isinstance(set_dict, dict):
                    continue
                try:
                    min_value = float(set_dict["min_value"])
                    max_value = float(set_dict["max_value"])
                    value = min(max(set_dict["value"], min_value), max_value)
                    help = set_dict["help"]
                except KeyError as e:
                    self.log.warn(
                        tag,
                        f"Failed to parse setting '{set_name:s}' due to a missing key: {str(e):s}",
                    )
                    continue
                except Exception as e:
                    self.log.warn(
                        tag, f"Failed to parse setting '{set_name:s}': {str(e):s}"
                    )
                    continue
                cfg.settings[set_name] = DoubleSpinboxSetting(
                    name=set_name,
                    value=value,
                    help=help,
                    min_value=min_value,
                    max_value=max_value,
                )
            for set_name in [
                "src_highlight_color",
                "snk_highlight_color",
                "path_grouping",
            ]:
                set_dict = sets_dict.get(set_name, None)
                if not isinstance(set_dict, dict):
                    continue
                try:
                    value = set_dict["value"]
                    help = set_dict["help"]
                except KeyError as e:
                    self.log.warn(
                        tag,
                        f"Failed to parse setting '{set_name:s}' due to a missing key: {str(e):s}",
                    )
                    continue
                except Exception as e:
                    self.log.warn(
                        tag, f"Failed to parse setting '{set_name:s}': {str(e):s}"
                    )
                    continue
                if set_name == "path_grouping":
                    items = get_all_grouping_strategies()
                else:
                    items = set_dict.get("items", [])
                    if not isinstance(items, list):
                        items = []
                cfg.settings[set_name] = ComboboxSetting(
                    name=set_name, value=value, help=help, items=items
                )
            for set_name in ["base_url", "api_key", "model"]:
                set_dict = sets_dict.get(set_name, None)
                if not isinstance(set_dict, dict):
                    continue
                try:
                    value = set_dict["value"]
                    help = set_dict["help"]
                except KeyError as e:
                    self.log.warn(
                        tag,
                        f"Failed to parse setting '{set_name:s}' due to a missing key: {str(e):s}",
                    )
                    continue
                except Exception as e:
                    self.log.warn(
                        tag, f"Failed to parse setting '{set_name:s}': {str(e):s}"
                    )
                    continue
                cfg.settings[set_name] = TextSetting(
                    name=set_name, value=value, help=help
                )
        except Exception as e:
            self.log.warn(tag, f"Failed to parse configuration: '{str(e):s}'")
        return cfg

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
        config = Configuration(
            taint_model={
                "manual": Library(
                    name="manual",
                    categories={"Default": Category(name="Default", functions={})},
                )
            },
            settings={},
        )
        config_files = sorted(os.listdir(self._config_path))
        for config_file in config_files:
            # Filter configuration files
            if not fn.fnmatch(config_file, "*.json") or config_file == "000-mole.json":
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
        config_files = [os.path.join(self._config_path, "000-mole.json")]
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
        config_file = os.path.join(self._config_path, "000-mole.json")
        with open(config_file, "w") as f:
            json.dump(config_dict, f, indent=2)
        # Write manual functions to file
        manual_file = os.path.join(self._config_path, "002-manual.json")
        with open(manual_file, "w") as f:
            taint_model_dict = config_dict.get("taint_model", None)
            if not isinstance(taint_model_dict, dict):
                taint_model_dict = {}
            lib_dict = taint_model_dict.get("manual", None)
            if not isinstance(lib_dict, dict):
                lib_dict = {}
            json.dump({"taint_model": {"manual": lib_dict}}, f, indent=2)
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
                config_dict = json.load(f)
            # Parse configuration file
            config = self._parse_config(config_dict, ignore_enabled)
            return config
        except FileNotFoundError:
            self.log.warn(tag, f"Configuration file '{config_file:s}' not found")
        except Exception as e:
            self.log.warn(
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
            json.dump(config_dict, f, indent=2)
        return

    def update_config(self, target: Configuration, source: Configuration) -> None:
        """
        This method updates the `target` `Configuration` with data from `source` `Configuration`.
        """
        # Update taint model
        for new_lib_name, new_lib in source.taint_model.items():
            if new_lib_name not in target.taint_model:
                target.taint_model[new_lib_name] = new_lib
                continue
            old_lib = target.taint_model[new_lib_name]
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

    def clear_main_config_file(self) -> None:
        """
        This method clears the main configuration file.
        """
        config_file = os.path.join(self._config_path, "000-mole.json")
        with open(config_file, "w") as f:
            json.dump({}, f, indent=2)
        return
