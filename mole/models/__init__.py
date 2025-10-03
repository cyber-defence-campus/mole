from __future__ import annotations
from enum import Enum
from typing import List


class IndexedLabeledEnum(Enum):
    def __new__(cls, index: int, label: str = "") -> IndexedLabeledEnum:
        obj = object.__new__(cls)
        obj._value_ = index
        obj._label = label
        return obj

    @property
    def index(self) -> int:
        return self._value_

    @property
    def label(self) -> str:
        return self._label

    @classmethod
    def indexes(cls: IndexedLabeledEnum) -> List[int]:
        """
        This method returns a list with the enum members' indexes.
        """
        return [member._value_ for member in cls]

    @classmethod
    def labels(cls: IndexedLabeledEnum) -> List[str]:
        """
        This method returns a list with the enum members' labels.
        """
        return [member._label for member in cls]

    def __str__(self) -> str:
        return self._label

    def __lt__(self, other: object) -> bool:
        if isinstance(other, IndexedLabeledEnum):
            return self._value_ < other._value_
        return NotImplemented

    def __eq__(self, other: object) -> bool:
        if isinstance(other, IndexedLabeledEnum):
            return self._value_ == other._value_
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)
