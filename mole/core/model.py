from __future__   import annotations
from ..common.log import Logger
from .data        import Configuration


class SidebarModel:
    """
    This class implements the model for the plugin's sidebar.
    """

    def __init__(
            self,
            tag: str,
            log: Logger
        ) -> None:
        """
        This method initializes a model (MVC pattern).
        """
        self._tag: str = tag
        self._log: Logger = log
        self._cfg: Configuration = None
        return
    
    def init(self) -> SidebarModel:
        """
        This method initializes the data model.
        """
        self._cfg = Configuration()
        return self

    def get(self) -> Configuration:
        """
        This method returns the model.
        """
        return self._cfg

    def update(self, new_conf: Configuration) -> None:
        """
        This method updates the model.
        """
        if not new_conf: return
        old_conf = self.get()
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