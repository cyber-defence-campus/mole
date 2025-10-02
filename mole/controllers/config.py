from __future__ import annotations
from mole.core.data import (
    Category,
    ComboboxSetting,
    Configuration,
    DoubleSpinboxSetting,
    Function,
    Library,
    SinkFunction,
    SourceFunction,
    SpinboxSetting,
    TextSetting,
    WidgetSetting,
)
from mole.models.config import ConfigModel
from mole.services.config import ConfigService
from mole.views.config import ConfigView
from typing import Any, Dict, List, Literal, Optional
import os
import PySide6.QtWidgets as qtw


class ConfigController:
    """
    This class implements a controller to handle Mole's configuration.
    """

    def __init__(
        self,
        config_service: ConfigService,
        config_model: ConfigModel,
        config_view: ConfigView,
    ) -> None:
        """
        This method initializes the configuration controller.
        """
        # Initialization
        self.config_service = config_service
        self.config_model = config_model
        self.config_view = config_view
        self.config_view.init(self)
        # Connect signals
        self.config_view.signal_save_config.connect(self.save_config)
        self.config_view.signal_reset_config.connect(self.reset_config)
        self.config_view.signal_import_config.connect(self.import_config)
        self.config_view.signal_export_config.connect(self.export_config)
        self.config_view.signal_check_functions.connect(self.check_functions)
        self.config_view.signal_clear_manual_functions.connect(
            self.clear_manual_functions
        )
        self.config_view.signal_change_setting.connect(self.change_setting)
        return

    def get_libraries(
        self, fun_type: Literal["Sources", "Sinks"]
    ) -> Dict[str, Library]:
        """
        This method returns all libraries matching the given type.
        """
        return self.config_model.get_libraries(fun_type)

    def get_functions(
        self,
        lib_name: str = None,
        cat_name: str = None,
        fun_name: str = None,
        fun_type: Optional[Literal["Sources", "Sinks"]] = None,
        fun_enabled: bool = None,
    ) -> List[Function]:
        """
        This method returns all functions matching the given attributes. An attribute of `None`
        indicates that this attribute is irrelevant and all functions should be included.
        """
        return self.config_model.get_functions(
            lib_name, cat_name, fun_name, fun_type, fun_enabled
        )

    def get_setting(self, name: str) -> Optional[WidgetSetting]:
        """
        This method returns the setting with name `name`.
        """
        return self.config_model.get_setting(name)

    def save_config(self) -> None:
        """
        This method saves the configuration.
        """
        # Save configuration
        config = self.config_model.get()
        self.config_service.save_config(config)
        # Update view
        self.config_view.give_feedback("Save", "Saving...", "Save")
        return

    def save_manual_fun(
        self, fun: SourceFunction | SinkFunction, category_name: str = "Default"
    ) -> None:
        """
        This method saves the given function `fun` as a manual source or sink.
        """
        # Update configuration
        config = self.config_model.get()
        manual_config = Configuration(
            sources={
                "manual": Library(
                    name="manual",
                    categories={
                        category_name: Category(
                            name=category_name, functions={fun.name: fun}
                        )
                    },
                )
            }
            if isinstance(fun, SourceFunction)
            else {},
            sinks={
                "manual": Library(
                    name="manual",
                    categories={
                        category_name: Category(
                            name=category_name, functions={fun.name: fun}
                        )
                    },
                )
            }
            if isinstance(fun, SinkFunction)
            else {},
        )
        self.config_service.update_config(config, manual_config)
        # Update view
        self.config_view.refresh_tabs(1 if isinstance(fun, SinkFunction) else 0)
        self.config_view.give_feedback("Save", "Save*", "Save*", 0)
        return

    def reset_config(self) -> None:
        """
        This method resets the configuration.
        """
        # Store input elements
        old_model = self.config_model.get()
        sources_ie: Dict[str, Dict] = {}
        for lib_name, lib in old_model.sources.items():
            sources_ie_lib: Dict[str, Dict] = sources_ie.setdefault(lib_name, {})
            for cat_name, cat in lib.categories.items():
                sources_ie_cat: Dict = sources_ie_lib.setdefault(cat_name, {})
                for fun_name, fun in cat.functions.items():
                    sources_ie_cat[fun_name] = fun.checkbox
        sinks_ie: Dict[str, Dict] = {}
        for lib_name, lib in old_model.sinks.items():
            sinks_ie_lib: Dict[str, Dict] = sinks_ie.setdefault(lib_name, {})
            for cat_name, cat in lib.categories.items():
                sinks_ie_cat: Dict = sinks_ie_lib.setdefault(cat_name, {})
                for fun_name, fun in cat.functions.items():
                    sinks_ie_cat[fun_name] = fun.checkbox
        settings = {}
        for setting_name, setting in old_model.settings.items():
            settings[setting_name] = setting.widget
        # Load configuration
        new_config = self.config_service.load_custom_config()
        # Restore input elements
        for lib_name, lib in new_config.sources.items():
            sources_ie_lib = sources_ie.get(lib_name, {})
            for cat_name, cat in lib.categories.items():
                sources_ie_cat = sources_ie_lib.get(cat_name, {})
                for fun_name, fun in cat.functions.items():
                    fun.checkbox = sources_ie_cat.get(fun_name, None)
                    fun.checkbox.setChecked(fun.enabled)
        for lib_name, lib in new_config.sinks.items():
            sinks_ie_lib = sinks_ie.get(lib_name, {})
            for cat_name, cat in lib.categories.items():
                sinks_ie_cat = sinks_ie_lib.get(cat_name, {})
                for fun_name, fun in cat.functions.items():
                    fun.checkbox = sinks_ie_cat.get(fun_name, None)
                    fun.checkbox.setChecked(fun.enabled)
        for setting_name, setting in new_config.settings.items():
            setting.widget = settings.get(setting_name, None)
            if isinstance(setting, SpinboxSetting) or isinstance(
                setting, DoubleSpinboxSetting
            ):
                setting.widget.setValue(setting.value)
            elif isinstance(setting, ComboboxSetting):
                if setting.value in setting.items:
                    setting.widget.setCurrentText(setting.value)
            elif isinstance(setting, TextSetting):
                setting.widget.setText(setting.value)
        self.config_model.set(new_config)
        # Update view
        self.config_view.give_feedback("Reset", "Resetting...", "Reset")
        self.config_view.give_feedback("Save", "Save", "Save", 0)
        return

    def import_config(self) -> None:
        """
        This method imports a configuration.
        """
        # Open dialog to select file path
        filepath, _ = qtw.QFileDialog.getOpenFileName(
            caption="Open File", filter="YAML Files (*.yml *.yaml);;All Files (*)"
        )
        if not filepath:
            return
        # Expand file path
        filepath = os.path.abspath(os.path.expanduser(os.path.expandvars(filepath)))
        # Update default configuration with the imported one
        config = self.config_service.load_custom_config(ignore_enabled=True)
        import_config = self.config_service.import_config(filepath)
        self.config_service.update_config(config, import_config)
        self.config_model.set(config)
        # Update view
        self.config_view.refresh_tabs()
        self.config_view.give_feedback("Import", "Importing...", "Import")
        self.config_view.give_feedback("Save", "Save*", "Save*", 0)
        return

    def export_config(self) -> None:
        """
        This method exports the configuration.
        """
        # Open dialog to select file path
        filepath, _ = qtw.QFileDialog.getSaveFileName(
            caption="Save As", filter="YAML Files (*.yml *.yaml);;All Files (*)"
        )
        if not filepath:
            return
        # Expand file path
        filepath = os.path.abspath(os.path.expanduser(os.path.expandvars(filepath)))
        # Export configuration
        config = self.config_model.get()
        self.config_service.export_config(config, filepath)
        # Update view
        self.config_view.give_feedback("Export", "Exporting...", "Export")
        return

    def check_functions(
        self,
        lib_name: Optional[str] = None,
        cat_name: Optional[str] = None,
        fun_name: Optional[str] = None,
        fun_type: Optional[str] = None,
        fun_enabled: Optional[bool] = None,
    ) -> None:
        """
        This method sets the enabled attribute of all functions' checkboxes matching the given
        attributes. An attribute of `None` indicates that the corresponding attribute is irrelevant.
        In case `fun_enabled` is `None` the checkboxes enabled attribute is toggled, otherwise set
        to the given value `fun_enabled`.
        """
        for fun in self.config_model.get_functions(
            lib_name, cat_name, fun_name, fun_type
        ):
            if fun_enabled is None:
                fun.enabled = not fun.enabled
            else:
                fun.enabled = fun_enabled
            fun.checkbox.setChecked(fun.enabled)
        self.config_view.give_feedback("Save", "Save*", "Save*", 0)
        return

    def clear_manual_functions(
        self, cat_name: str, fun_type: Literal["Sources", "Sinks"]
    ) -> None:
        """
        This method clears all manual source or sink functions in the given category name
        `cat_name`.
        """
        config = self.config_model.get()
        match fun_type:
            case "Sources":
                manual_lib = config.sources.get("manual", None)
                index = 0
            case "Sinks":
                manual_lib = config.sinks.get("manual", None)
                index = 1
            case _:
                manual_lib = None
                index = -1
        if manual_lib and cat_name in manual_lib.categories:
            del manual_lib.categories[cat_name]
        self.config_view.refresh_tabs(index)
        self.config_view.give_feedback("Save", "Save*", "Save*", 0)
        return

    def change_setting(self, name: str, value: Any) -> None:
        """
        This method changes setting values.
        """
        setting = self.config_model.get_setting(name)
        if setting:
            setting.value = value
        self.config_view.give_feedback("Save", "Save*", "Save*", 0)
        return
