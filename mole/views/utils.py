from __future__   import annotations
import PySide6.QtCore    as qtc
import PySide6.QtWidgets as qtw

    
class IntTableWidgetItem(qtw.QTableWidgetItem):
    """
    This class implements a custom `qtw.QTableWidgetItem` for sorting integers numerically.
    """

    def __init__(self, value: int, as_hex=False) -> None:
        if as_hex:
            super().__init__(f"0x{value:x}")
        else:
            super().__init__(f"{value:d}")
        self.setData(qtc.Qt.ItemDataRole.UserRole, value)
        return
    
    def __lt__(self, other: IntTableWidgetItem):
        if isinstance(other, IntTableWidgetItem):
            return other.data(qtc.Qt.ItemDataRole.UserRole.UserRole) < self.data(qtc.Qt.ItemDataRole.UserRole)
        return super().__lt__(other)