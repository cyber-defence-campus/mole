from __future__  import annotations
from ..core.data import Configuration, Library, WidgetSetting
from typing      import Dict, Any, List, Literal


class ConfigModel:
    """
    This class implements a model to handle Mole's configuration.
    """
    
    def __init__(self, config: Configuration) -> None:
        """
        Initialize the configuration model with optional pre-loaded configuration.
        
        Args:
            config: A Configuration object to initialize the model with.
                    If None, an empty configuration will be created.
        """
        self._config = config
        return
    
    def get(self) -> Configuration:
        """
        This method returns the configuration.
        """
        return self._config

    def set(self, config: Configuration) -> None:
        """
        This method sets the configuration.
        """
        self._config = config
        return
        
    def get_libraries(self, type_name: Literal["Sources", "Sinks"]) -> Dict[str, Library]:
        """
        This method returns the libraries of the given type.
        """
        match type_name:
            case "Sources":
                return self._config.sources
            case "Sinks":
                return self._config.sinks
        return {}
    
    def get_settings(self) -> Dict[str, WidgetSetting]:
        """
        This method returns the settings.
        """
        return self._config.settings
    
    def set_settings(self, settings: Dict[str, WidgetSetting]) -> None:
        """
        This method sets the settings.
        """
        self._config.settings = settings
        return
        
    def set_libraries(
            self,
            type_name: Literal["Sources", "Sinks"],
            libraries: Dict[str, Library]
        ) -> None:
        """
        This method sets the libraries of the given type.
        """
        match type_name:
            case "Sources":
                self._config.sources = libraries
            case "Sinks":
                self._config.sinks = libraries
        return
            
    def get_configuration(self) -> Configuration:
        """
        This method returns the current configuration.
        """
        return self._config
    
    def get_functions(
            self,
            type_name: Literal["Sources", "Sinks"],
            enabled_only: bool = False
        ) -> List[Any]:
        """
        This method returns all (enabled) source or sink functions.
        """
        funs = []
        libs = self.get_libraries(type_name)
        for lib in libs.values():
            for cat in lib.categories.values():
                for fun in cat.functions.values():
                    if not enabled_only or fun.enabled:
                        funs.append(fun)
        return funs
    