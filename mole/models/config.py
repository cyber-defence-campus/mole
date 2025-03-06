from typing import Dict, Any, List
from ..core.data import Configuration

class ConfigModel:
    """
    This class implements the model for storing configuration data.
    """
    
    def __init__(self, configuration: Configuration) -> None:
        """
        Initialize the configuration model with optional pre-loaded configuration.
        
        Args:
            configuration: A Configuration object to initialize the model with.
                          If None, an empty configuration will be created.
        """
        self._configuration = configuration
    
    def get(self):
        """
        This method returns the configuration.
        """
        return self._configuration

    def set(self, configuration: Configuration):
        """
        This method sets the configuration.
        """
        self._configuration = configuration
        
    def get_libraries(self, type_name: str) -> Dict[str, Any]:
        """
        This method returns the libraries of the given type.
        """
        if type_name == "Sources":
            return self._configuration.sources
        elif type_name == "Sinks":
            return self._configuration.sinks
        return {}
    
    def get_settings(self) -> Dict[str, Any]:
        """
        This method returns the settings.
        """
        return self._configuration.settings
    
    def set_settings(self, settings: Dict[str, Any]) -> None:
        """
        This method sets the settings.
        """
        self._configuration.settings = settings
        
    def set_libraries(self, type_name: str, libraries: Dict[str, Any]) -> None:
        """
        This method sets the libraries of the given type.
        """
        if type_name == "Sources":
            self._configuration.sources = libraries
        elif type_name == "Sinks":
            self._configuration.sinks = libraries
            
    def get_configuration(self) -> Configuration:
        """
        This method returns the current configuration.
        """
        return self._configuration
    
        
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
    