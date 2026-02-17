from __future__ import annotations
from mole.models.config import ComboboxSetting, ConfigModel
import PySide6.QtWidgets as qtw
from typing import Literal
import binaryninja as bn


class GraphService:
    """
    This class implements a service for Mole's graph.
    """

    def __init__(self, config_model: ConfigModel) -> None:
        """
        This method initializes the graph service.
        """
        self.config_model = config_model
        return

    def get_color(
        self, name: Literal["src", "snk", "in_path"]
    ) -> bn.HighlightStandardColor:
        """
        This method retries the highlight color from the settings.
        """
        color = bn.HighlightStandardColor.WhiteHighlightColor
        if name == "src":
            try:
                setting = self.config_model.get_setting("src_highlight_color")
                if isinstance(setting, ComboboxSetting) and isinstance(
                    setting.widget, qtw.QComboBox
                ):
                    color_name = setting.widget.currentText().capitalize()
                    color = bn.HighlightStandardColor[f"{color_name:s}HighlightColor"]
            except Exception as _:
                color = bn.HighlightStandardColor.OrangeHighlightColor
        elif name == "snk":
            try:
                setting = self.config_model.get_setting("snk_highlight_color")
                if isinstance(setting, ComboboxSetting) and isinstance(
                    setting.widget, qtw.QComboBox
                ):
                    color_name = setting.widget.currentText().capitalize()
                    color = bn.HighlightStandardColor[f"{color_name:s}HighlightColor"]
            except Exception as _:
                color = bn.HighlightStandardColor.RedHighlightColor
        return color
