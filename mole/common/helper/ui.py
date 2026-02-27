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
    then to `new_text`. If `new_text` is empty, the button's current text is used instead. If
    `tmp_text` is empty or `msec` is non-positive, the button's text is immediately changed to
    `new_text`.
    """

    # Restore button
    def restore(text: str) -> None:
        button.setText(text)
        button.setEnabled(True)
        return

    # Store button's current text if no new text is given
    if not new_text:
        new_text = button.text()
    # Temporarily disable the button and change its text
    if tmp_text and msec > 0:
        button.setEnabled(False)
        button.setText(tmp_text)
        qtc.QTimer.singleShot(msec, lambda: restore(new_text))
    # Immediately change the button's text without disabling it
    else:
        button.setText(new_text)
    return
