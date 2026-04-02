from __future__ import annotations
from dataclasses import dataclass, field
from mole.core.graph import MediumLevelILFunctionGraph, MediumLevelILInstructionGraph
from typing import Any, Callable, Dict, List, TYPE_CHECKING
import binaryninja as bn

if TYPE_CHECKING:
    import PySide6.QtWidgets as qtw


@dataclass
class Configuration:
    """
    This class is a representation of the data associated with the plugin's configuration.
    """

    taint_model: Dict[str, Library] = field(default_factory=dict)
    settings: Dict[str, WidgetSetting] = field(default_factory=dict)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Configuration):
            return False
        if len(self.taint_model) != len(other.taint_model):
            return False
        for lib_name, lib in self.taint_model.items():
            if lib_name not in other.taint_model:
                return False
            if lib != other.taint_model[lib_name]:
                return False
        if len(self.settings) != len(other.settings):
            return False
        for setting_name, setting in self.settings.items():
            if setting_name not in other.settings:
                return False
            if setting != other.settings[setting_name]:
                return False
        return True

    def to_dict(self) -> Dict:
        functions = {}
        for lib_name, lib in self.taint_model.items():
            functions[lib_name] = lib.to_dict()
        settings = {}
        for setting_name, setting in self.settings.items():
            settings[setting_name] = setting.to_dict()
        return {
            "taint_model": functions,
            "settings": settings,
        }


@dataclass
class Library:
    """
    This class is a representation of the data associated with libraries.
    """

    name: str
    categories: Dict[str, Category] = field(default_factory=dict)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Library):
            return False
        if self.name != other.name:
            return False
        if len(self.categories) != len(other.categories):
            return False
        for cat_name, cat in self.categories.items():
            if cat_name not in other.categories:
                return False
            if cat != other.categories[cat_name]:
                return False
        return True

    def to_dict(self) -> Dict:
        library = {}
        for cat_name, cat in self.categories.items():
            library[cat_name] = cat.to_dict()
        return library


@dataclass
class Category:
    """
    This class is a representation of the data associated with categories.
    """

    name: str
    functions: Dict[str, Function] = field(default_factory=dict)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Category):
            return False
        if self.name != other.name:
            return False
        if len(self.functions) != len(other.functions):
            return False
        for fun_name, fun in self.functions.items():
            if fun_name not in other.functions:
                return False
            if fun != other.functions[fun_name]:
                return False
        return True

    def to_dict(self) -> Dict:
        category = {}
        for fun_name, fun in self.functions.items():
            category[fun_name] = fun.to_dict()
        return category


@dataclass
class Function:
    """
    This class is a representation of the data associated with functions.
    """

    name: str
    symbols: List[str]
    synopsis: str = ""
    par_cnt: str = ""
    par_cnt_fun: Callable[[int], bool] = lambda _: False
    par_slice: str = ""
    par_slice_fun: Callable[[int], bool] = lambda _: False
    src_enabled: bool = False
    snk_enabled: bool = False
    fix_enabled: bool = False
    graph_map: Dict[CallSiteKey, Dict[ParamKey, Graphs]] = field(default_factory=dict)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Function):
            return False
        return self.name in other.symbols and other.name in self.symbols

    def to_dict(self) -> Dict:
        return {
            "aliases": [symbol for symbol in self.symbols if symbol != self.name],
            "synopsis": self.synopsis,
            "par_slice": self.par_slice,
            "attributes": {
                "source": self.src_enabled,
                "sink": self.snk_enabled,
                "fix": self.fix_enabled,
            },
        }


@dataclass(frozen=True)
class CallSiteKey:
    sym_addr: int
    sym_name: str
    call_inst: (
        bn.MediumLevelILCall
        | bn.MediumLevelILCallSsa
        | bn.MediumLevelILTailcall
        | bn.MediumLevelILTailcallSsa
    )


@dataclass(frozen=True)
class ParamKey:
    par_idx: int
    par_var: bn.MediumLevelILInstruction


@dataclass
class Graphs:
    inst_graph: MediumLevelILInstructionGraph
    call_graph: MediumLevelILFunctionGraph


@dataclass
class WidgetSetting:
    """
    This class is a representation of the data associated with a widget.
    """

    name: str
    value: Any
    help: str
    widget: qtw.QWidget | None = None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, WidgetSetting):
            return False
        return self.name == other.name

    def to_dict(self) -> dict:
        return {"value": self.value, "help": self.help}


@dataclass
class CheckboxSetting(WidgetSetting):
    """
    This class is a representation of the data associated with a checkbox widget.
    """

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CheckboxSetting):
            return False
        return super().__eq__(other)

    def to_dict(self) -> Dict:
        return super().to_dict()


@dataclass
class SpinboxSetting(WidgetSetting):
    """
    This class is a representation of the data associated with a spinbox widget.
    """

    min_value: int = field(default_factory=int)
    max_value: int = field(default_factory=int)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SpinboxSetting):
            return False
        return super().__eq__(other)

    def to_dict(self) -> Dict:
        d = super().to_dict()
        d.update({"min_value": self.min_value, "max_value": self.max_value})
        return d


@dataclass
class DoubleSpinboxSetting(WidgetSetting):
    """
    This class is a representation of the data associated with a spinbox widget.
    """

    min_value: float = field(default_factory=float)
    max_value: float = field(default_factory=float)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DoubleSpinboxSetting):
            return False
        return super().__eq__(other)

    def to_dict(self) -> Dict:
        d = super().to_dict()
        d.update({"min_value": self.min_value, "max_value": self.max_value})
        return d


@dataclass
class ComboboxSetting(WidgetSetting):
    """
    This class is a representation of the data associated with a combobox widget.
    """

    items: List[str] = field(default_factory=list)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ComboboxSetting):
            return False
        return super().__eq__(other)

    def to_dict(self) -> Dict:
        d = super().to_dict()
        d.update({"items": self.items})
        return d


@dataclass
class TextSetting(WidgetSetting):
    """
    This class is a representation of the data associated with a text input widget.
    """

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TextSetting):
            return False
        return super().__eq__(other)

    def to_dict(self) -> Dict:
        return super().to_dict()
