import PySide6.QtCore as qtc
from PySide6 import QtWidgets as qtw


def give_feedback(
    button: qtw.QPushButton,
    tmp_text: str = "",
    new_text: str = "",
    msec: int = 1000,
) -> None:
    """
    This method changes the `button`'s text temporarily to `tmp_text` for `msec` milliseconds and
    then to `new_text`. If `new_text` is empty, the button's current text is used instead. If `msec`
    is negative, the button will be disabled. If `msec` is non-negative, the button will be
    re-enabled.
    """

    # Restore button
    def restore(text: str) -> None:
        button.setText(text)
        button.setEnabled(True)
        return

    # Disable the button
    button.setEnabled(False)
    # Store button's text if it should not change
    if not new_text:
        new_text = button.text()
    # Set temporary button text if given
    if tmp_text:
        button.setText(tmp_text)
    # Re-enable the button
    if msec == 0:
        restore(new_text)
    elif msec > 0:
        qtc.QTimer.singleShot(msec, lambda: restore(new_text))
    return
