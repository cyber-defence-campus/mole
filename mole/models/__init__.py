from enum import Enum
from typing import List


class LabeledEnum(Enum):
    def __init__(self, index: int, label: str) -> None:
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
        return f"{self._index:d}: {self._label:s}"
