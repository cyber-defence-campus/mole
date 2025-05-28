from enum import Enum
from typing import List


class IndexedLabeledEnum(Enum):
    def __init__(self, index: int, label: str = "") -> None:
        self._index = index
        self._label = label
        return

    @property
    def index(self) -> int:
        return self._index

    @property
    def label(self) -> str:
        return self._label

    @classmethod
    def indexes(cls) -> List[int]:
        """
        This method returns a list with the enum members' indexes.
        """
        return [member._index for member in cls]

    @classmethod
    def labels(cls) -> List[str]:
        """
        This method returns a list with the enum members' labels.
        """
        return [member._label for member in cls]

    def __str__(self) -> str:
        return self._label

    def __lt__(self, other: object) -> bool:
        if isinstance(other, IndexedLabeledEnum):
            return self._index < other._index
        return NotImplemented

    def __eq__(self, other: object) -> bool:
        if isinstance(other, IndexedLabeledEnum):
            return self._index == other._index
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._index)
