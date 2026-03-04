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

    sources: Dict[str, Library] = field(default_factory=dict)
    sinks: Dict[str, Library] = field(default_factory=dict)
    propagators: Dict[str, Library] = field(default_factory=dict)
    settings: Dict[str, WidgetSetting] = field(default_factory=dict)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Configuration):
            return False
        if len(self.sources) != len(other.sources):
            return False
        for lib_name, lib in self.sources.items():
            if lib_name not in other.sources:
                return False
            if lib != other.sources[lib_name]:
                return False
        if len(self.sinks) != len(other.sinks):
            return False
        for lib_name, lib in self.sinks.items():
            if lib_name not in other.sinks:
                return False
            if lib != other.sinks[lib_name]:
                return False
        if len(self.propagators) != len(other.propagators):
            return False
        for lib_name, lib in self.propagators.items():
            if lib_name not in other.propagators:
                return False
            if lib != other.propagators[lib_name]:
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
        sources = {}
        for lib_name, lib in self.sources.items():
            sources[lib_name] = lib.to_dict()
        sinks = {}
        for lib_name, lib in self.sinks.items():
            sinks[lib_name] = lib.to_dict()
        propagators = {}
        for lib_name, lib in self.propagators.items():
            propagators[lib_name] = lib.to_dict()
        settings = {}
        for setting_name, setting in self.settings.items():
            settings[setting_name] = setting.to_dict()
        return {
            "sources": sources,
            "sinks": sinks,
            "propagators": propagators,
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
        categories = {}
        for cat_name, cat in self.categories.items():
            categories[cat_name] = cat.to_dict()
        return {"categories": categories}


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
        functions = {}
        for fun_name, fun in self.functions.items():
            functions[fun_name] = fun.to_dict()
        return {"functions": functions}


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
class Function:
    """
    This class is a representation of the data associated with functions.
    """

    name: str
    symbols: List[str]
    synopsis: str = ""
    enabled: bool = False
    par_cnt: str = ""
    par_cnt_fun: Callable[[int], bool] = lambda _: False
    par_dataflow: str = ""
    par_dataflow_fun: Callable[[int], bool] = lambda _: False
    par_slice: str = ""
    par_slice_fun: Callable[[int], bool] = lambda _: False
    checkbox: qtw.QCheckBox | None = None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Function):
            return False
        return self.name == other.name

    def to_dict(self) -> Dict:
        return {
            "symbols": self.symbols,
            "synopsis": self.synopsis,
            "enabled": self.enabled,
            "par_cnt": self.par_cnt,
            "par_slice": self.par_slice,
        }


@dataclass
class SourceFunction(Function):
    """
    This class is a representation of the data associated with source functions.
    """

    graph_map: Dict[CallSiteKey, Dict[ParamKey, Graphs]] = field(default_factory=dict)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SourceFunction):
            return False
        return super().__eq__(other)


@dataclass
class SinkFunction(Function):
    """
    This class is a representation of the data associated with sink functions.
    """

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SinkFunction):
            return False
        return super().__eq__(other)


@dataclass
class PropagatorFunction(Function):
    """
    This class is a representation of the data associated with propagator functions.
    """

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PropagatorFunction):
            return False
        return super().__eq__(other)


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
