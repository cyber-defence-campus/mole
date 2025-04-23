from __future__ import annotations
from mole.core.data import (
    ComboboxSetting,
    Function,
    Library,
    SpinboxSetting,
    TextSetting,
    WidgetSetting,
)
from mole.models.config import ConfigModel
from mole.services.config import ConfigService
from mole.views.config import ConfigView
from typing import Dict, List, Literal, Optional


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
        # Connect signals
        self.connect_signal_save_config(self.save_config)
        self.connect_signal_reset_config(self.reset_config)
        self.connect_signal_check_functions(self.check_functions)
        self.connect_signal_change_seting(self.change_setting)
        return

    def connect_signal_save_config(self, slot: object) -> None:
        """
        This method allows connecting to the signal that is triggered when the configuration should
        be saved.
        """
        self.config_view.signal_save_config.connect(slot)
        return

    def connect_signal_reset_config(self, slot: object) -> None:
        """
        This method allows connecting to the signal that is triggered when the configuration should
        be reset.
        """
        self.config_view.signal_reset_config.connect(slot)
        return

    def connect_signal_check_functions(self, slot: object) -> None:
        """
        This method allows connecting to the signal that is triggered when source/sink function
        checkboxes are checked.
        """
        self.config_view.signal_check_functions.connect(slot)
        return

    def connect_signal_change_seting(self, slot: object) -> None:
        """
        This method allows connecting to the signal that is triggered when a setting changes.
        """
        self.config_view.signal_change_setting.connect(slot)
        return

    def connect_signal_change_path_grouping(self, slot: object) -> None:
        """
        This method allows connecting to the signal that is triggered when the path grouping
        strategy changes.
        """
        self.config_view.signal_change_path_grouping.connect(slot)
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
        self.config_service.save_config(self.config_model.get())
        self.config_view.give_feedback("Save", "Saving...")
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
        # Reset model
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
            if isinstance(setting, SpinboxSetting):
                setting.widget.setValue(setting.value)
            elif isinstance(setting, ComboboxSetting):
                if setting.value in setting.items:
                    setting.widget.setCurrentText(setting.value)
            elif isinstance(setting, TextSetting):
                setting.widget.setText(setting.value)
        self.config_model.set(new_config)
        # User feedback
        self.config_view.give_feedback("Reset", "Resetting...")
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
        return

    def change_setting(self, name: str, value: object) -> None:
        """
        This method changes setting values.
        """
        setting = self.config_model.get_setting(name)
        if setting:
            setting.value = value
        return
