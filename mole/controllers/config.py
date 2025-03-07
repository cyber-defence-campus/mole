from __future__        import annotations
from ..core.data       import Category, ComboboxSetting, Function, Library, SpinboxSetting, WidgetSetting
from ..models.config   import ConfigModel
from ..services.config import ConfigService
from ..views.config    import ConfigView
from typing            import Dict, Literal


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
        
    def get_libraries(self, type_name: Literal["Sources", "Sinks"]) -> Dict[str, Library]:
        """
        This method returns the libraries of the given type.
        """
        return self._model.get_libraries(type_name)
    
    def get_settings(self) -> Dict[str, WidgetSetting]:
        """
        This method returns the settings.
        """
        return self._model.get_settings()
    
    def checkbox_toggle(self, function: Function) -> None:
        """
        This method handles checkbox toggle events.
        """
        function.enabled = not function.enabled
        return
        
    def checkboxes_check(self, cat: Category, checked: bool) -> None:
        """
        This method handles selecting/deselecting all checkboxes.
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
        
    def combobox_change_value(self, setting: ComboboxSetting, value: str) -> None:
        """
        This method updates the model to reflect combobox value changes.
        """
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
        new_config = self._service.load_custom_configuration()
        self._model.set(new_config)
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
        # User feedback
        self._view.give_feedback("Reset", "Resetting...")
        return