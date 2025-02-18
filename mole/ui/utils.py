from __future__   import annotations
import PySide6.QtWidgets as qtw


class NumericTableWidgetItem(qtw.QTableWidgetItem):
    """
    This class implements table items that can be sorted numerically.
    """

    def __init__(self, value: str) -> None:
        super().__init__(value)
        self.int_value = int(value, base=0)
        return

    def __lt__(self, other: NumericTableWidgetItem) -> bool:
        if isinstance(other, NumericTableWidgetItem):
            return other.int_value < self.int_value
        return super().__lt__(other)