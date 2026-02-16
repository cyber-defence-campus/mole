from __future__ import annotations
from mole.core.data import Configuration, Function, Library, WidgetSetting
from typing import Dict, List, Literal


class ConfigModel:
    """
    This class implements a model for Mole's configuration.
    """

    def __init__(self, config: Configuration) -> None:
        """
        This method initializes the configuration model.
        """
        super().__init__()
        self._config = config
        return

    @property
    def config(self) -> Configuration:
        """
        This method returns the current configuration.
        """
        return self._config

    @config.setter
    def config(self, config: Configuration) -> None:
        """
        This method sets the current configuration.
        """
        self._config = config
        return

    def get_libraries(
        self, fun_type: Literal["Sources", "Sinks"] | None
    ) -> Dict[str, Library]:
        """
        This method returns all libraries matching the given type.
        """
        match fun_type:
            case "Sources":
                return self._config.sources
            case "Sinks":
                return self._config.sinks
        return {}

    def get_functions(
        self,
        lib_name: str | None = None,
        cat_name: str | None = None,
        fun_name: str | None = None,
        fun_type: Literal["Sources", "Sinks"] | None = None,
        fun_enabled: bool | None = None,
    ) -> List[Function]:
        """
        This method returns all functions matching the given attributes. An attribute of `None`
        indicates that the corresponding attribute is irrelevant.
        """
        funs: List[Function] = []
        match fun_type:
            case "Sources":
                libs = self._config.sources.values()
            case "Sinks":
                libs = self._config.sinks.values()
            case _:
                libs = list(self._config.sources.values()) + list(
                    self._config.sinks.values()
                )
        for lib in libs:
            if lib_name is None or lib.name == lib_name:
                for cat in lib.categories.values():
                    if cat_name is None or cat.name == cat_name:
                        for fun in cat.functions.values():
                            if fun_name is None or fun.name == fun_name:
                                if fun_enabled is None or fun.enabled == fun_enabled:
                                    funs.append(fun)
        return funs

    def get_setting(self, name: str) -> WidgetSetting | None:
        """
        This method returns the setting with name `name`.
        """
        return self._config.settings.get(name, None)
