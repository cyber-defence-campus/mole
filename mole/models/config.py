from typing import Dict, Any, List
import os
import yaml
from ..core.data import Configuration, Library, Category

class ConfigModel:
    """
    This class implements the model for storing configuration data.
    """
    
    def __init__(self) -> None:
        """
        This method initializes the configuration model.
        """
        self._configuration = Configuration()
        self._conf_path: str = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "../../conf/"
        )
    
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
    
    def update_configuration(self, new_conf: Configuration) -> None:
        """
        This method updates the configuration with new data.
        """
        if not new_conf: return
        old_conf = self._configuration
        # Update sources and sinks
        for type in ["sources", "sinks"]:
            match type:
                case "sources":
                    new_libs = new_conf.sources
                    old_libs = old_conf.sources
                case "sinks":
                    new_libs = new_conf.sinks
                    old_libs = old_conf.sinks
                case _:
                    new_libs = {}
                    old_libs = {}
            for new_lib_name, new_lib in new_libs.items():
                if not new_lib_name in old_libs:
                    old_libs[new_lib_name] = new_lib
                    continue
                old_lib = old_libs[new_lib_name]
                for new_cat_name, new_cat in new_lib.categories.items():
                    if not new_cat_name in old_lib.categories:
                        old_lib.categories[new_cat_name] = new_cat
                        continue
                    old_cat = old_lib.categories[new_cat_name]
                    for new_fun_name, new_fun in new_cat.functions.items():
                        old_cat.functions[new_fun_name] = new_fun
        # Update settings
        new_settings = new_conf.settings
        old_settings = old_conf.settings
        for new_setting_name, new_setting in new_settings.items():
            old_settings[new_setting_name] = new_setting
        return