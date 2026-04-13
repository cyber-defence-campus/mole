from __future__ import annotations
from mole.data.config import Configuration, Function, Library, WidgetSetting
from mole.models import IndexedLabeledEnum
from typing import Dict, List


class TaintModelColumns(IndexedLabeledEnum):
    FUNCTION = (0, "Function")
    SOURCE = (1, "Src")
    SINK = (2, "Snk")
    FIX = (3, "Fix")


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

    def get_functions(
        self,
        lib_names: List[str] = [],
        cat_names: List[str] = [],
        fun_names: List[str] = [],
        fun_types: List[TaintModelColumns] = [],
    ) -> List[Function]:
        """
        This method returns all functions matching the given attributes. An empty attribute
        indicates that the corresponding attribute is irrelevant. E.g., if `lib_names` is empty,
        functions from all libraries are included.
        """
        funs = []
        for lib_name, lib in self._config.taint_model.items():
            if lib_names and lib_name not in lib_names:
                continue
            for cat_name, cat in lib.categories.items():
                if cat_names and cat_name not in cat_names:
                    continue
                for fun_name, fun in cat.functions.items():
                    if fun_names and fun_name not in fun_names:
                        continue
                    if fun_types:
                        for fun_type in fun_types:
                            match fun_type:
                                case TaintModelColumns.SOURCE:
                                    if fun.src_enabled:
                                        funs.append(fun)
                                case TaintModelColumns.SINK:
                                    if fun.snk_enabled:
                                        funs.append(fun)
                                case TaintModelColumns.FIX:
                                    if fun.fix_enabled:
                                        funs.append(fun)
                    else:
                        funs.append(fun)
        return funs

    def get_taint_model(self) -> Dict[str, Library]:
        """
        This method returns the complete taint model.
        """
        return self._config.taint_model

    def get_setting(self, name: str) -> WidgetSetting | None:
        """
        This method returns the setting with name `name`.
        """
        return self._config.settings.get(name, None)
