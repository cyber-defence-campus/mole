from __future__        import annotations
from ..core.data       import ComboboxSetting, Function, Library, SpinboxSetting, WidgetSetting
from ..models.config   import ConfigModel
from ..services.config import ConfigService
from ..views.config    import ConfigView
from typing            import Dict, List, Literal, Optional


class ConfigController:
    """
    This class implements a controller to handle Mole's configuration.
    """
    
    def __init__(self, model: ConfigModel, view: ConfigView, service: ConfigService) -> None:
        """
        This method initializes the configuration controller.
        """
        self._model = model
        self._view = view
        self._service = service
        return
        
    def get_libraries(
            self,
            fun_type: Literal["Sources", "Sinks"]
        ) -> Dict[str, Library]:
        """
        This method returns all libraries matching the given type.
        """
        return self._model.get_libraries(fun_type)
    
    def get_functions(
            self,
            lib_name: str = None,
            cat_name: str = None,
            fun_name: str = None,
            fun_type: Optional[Literal["Sources", "Sinks"]] = None,
            fun_enabled: bool = None
        ) -> List[Function]:
        """
        This method returns all functions matching the given attributes. An attribute of `None`
        indicates that this attribute is irrelevant and all functions should be included.
        """
        return self._model.get_functions(lib_name, cat_name, fun_name, fun_type, fun_enabled)
    
    def get_setting(self, name: str) -> Optional[WidgetSetting]:
        """
        This method returns the setting with name `name`.
        """
        return self._model.get_setting(name)
    
    def set_function_checkboxes(
            self,
            lib_name: str = None,
            cat_name: str = None,
            fun_name: str = None,
            fun_type: Optional[Literal["Sources", "Sinks"]] = None,
            fun_enabled: bool = None
        ) -> None:
        """
        This method sets the enabled attribute of all functions' checkboxes matching the given
        attributes. An attribute of `None` indicates that the corresponding attribute is irrelevant.
        In case `fun_enabled` is `None` the checkboxes enabled attribute is toggled, otherwise set
        to the given value `fun_enabled`.
        """
        for fun in self._model.get_functions(lib_name, cat_name, fun_name, fun_type):
            if fun_enabled is None:
                fun.enabled = not fun.enabled
            else:
                fun.enabled = fun_enabled
            fun.checkbox.setChecked(fun.enabled)
        return
    
    def set_setting_value(
            self,
            name: str,
            value: int | str
        ) -> None:
        """
        This method sets the value of the setting with name `name`.
        """
        setting = self._model.get_setting(name)
        if setting:
            setting.value = value
        return

    def store_configuration(self) -> None:
        self._service.store_configuration(self._model.get())
        self._view.give_feedback("Save", "Saving...")
        return

    def reset_conf(self) -> None:
        """
        This method resets the configuration.
        """
        # Store input elements
        old_model = self._model.get()
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
        new_config = self._service.load_custom_configuration()
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
        self._model.set(new_config)
        # User feedback
        self._view.give_feedback("Reset", "Resetting...")
        return