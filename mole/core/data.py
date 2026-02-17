from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List
import PySide6.QtWidgets as qtw


# TODO: Rework!
tag = "Data"


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
