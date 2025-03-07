from __future__   import annotations
from ..common.log import Logger
from typing       import Literal, TYPE_CHECKING
import PySide6.QtCore    as qtc
import PySide6.QtWidgets as qtw

if TYPE_CHECKING:
    from ..controllers.config import ConfigController


class ConfigView(qtw.QWidget):
    """
    This class implements a view to handle Mole's configuration.
    """

    def __init__(self, tag: str, log: Logger) -> None:
        """
        This method initializes the configuration view.
        """
        super().__init__()
        self._tag = tag
        self._log = log
        self._ctr = None
        self._save_but = None
        self._reset_but = None

    def init(self) -> None:
        """
        Initialize the UI components
        """
        tab = qtw.QTabWidget()
        tab.addTab(self._init_cnf_fun_tab("Sources"), "Sources")
        tab.addTab(self._init_cnf_fun_tab("Sinks"), "Sinks")
        tab.addTab(self._init_cnf_set_tab(), "Settings")
        but = self._init_cnf_but()
        lay = qtw.QVBoxLayout()
        lay.addWidget(tab)
        lay.addWidget(but)
        self.setLayout(lay)
        return

    def set_controller(self, ctr: ConfigController) -> None:
        """
        This method sets the controller for the model.
        """
        self._ctr = ctr
        return
        
    def tab_title(self) -> str:
        """
        Returns the title for this tab
        """
        return "Configure"

    def _init_cnf_fun_tab(self, tab_name: Literal["Sources", "Sinks"]) -> qtw.QWidget:
        """
        This method initializes the tabs `Sources` and `Sinks`.
        """
        tab_wid = qtw.QTabWidget()
        for lib in self._ctr.get_libraries(tab_name).values():
            lib_lay = qtw.QVBoxLayout()
            lib_wid = qtw.QWidget()
            lib_wid.setLayout(lib_lay)
            for cat in lib.categories.values():
                # Function widget
                fun_lay = qtw.QFormLayout()
                for fun in cat.functions.values():
                    fun.checkbox = qtw.QCheckBox(fun.name)
                    fun.checkbox.setChecked(fun.enabled)
                    fun.checkbox.setToolTip(fun.synopsis)
                    fun.checkbox.clicked.connect(
                        lambda _, fun=fun: self._ctr.checkbox_toggle(fun)
                    )
                    fun_lay.addRow(fun.checkbox)
                fun_wid = qtw.QWidget()
                fun_wid.setLayout(fun_lay)
                # Button widget
                sel_but = qtw.QPushButton("Select All")
                sel_but.clicked.connect(
                    lambda _, cat=cat, checked=True: self._ctr.checkboxes_check(cat, checked)
                )
                dsl_but = qtw.QPushButton("Deselect All")
                dsl_but.clicked.connect(
                    lambda _, cat=cat, checked=False: self._ctr.checkboxes_check(cat, checked)
                )
                but_lay = qtw.QHBoxLayout()
                but_lay.addWidget(sel_but)
                but_lay.addWidget(dsl_but)
                but_wid = qtw.QWidget()
                but_wid.setLayout(but_lay)
                # Box widget
                box_lay = qtw.QVBoxLayout()
                box_lay.addWidget(fun_wid)
                box_lay.addWidget(but_wid)
                box_wid = qtw.QGroupBox(f"{cat.name:s}:")
                box_wid.setLayout(box_lay)
                lib_lay.addWidget(box_wid)
            scr_wid = qtw.QScrollArea()
            scr_wid.setWidget(lib_wid)
            scr_wid.setWidgetResizable(True)
            tab_wid.addTab(scr_wid, lib.name)
        lay = qtw.QVBoxLayout()
        lay.addWidget(tab_wid)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid
    
    def _init_cnf_set_tab(self) -> qtw.QWidget:
        """
        This method initializes the tab `Settings`.
        """
        com_wid = qtw.QWidget()
        com_lay = qtw.QFormLayout()
        settings = self._ctr.get_settings()
        for name in ["max_workers", "max_call_level", "max_slice_depth"]:
            setting = settings.get(name, None)
            if not setting:
                continue
            setting.widget = qtw.QSpinBox()
            setting.widget.setRange(setting.min_value, setting.max_value)
            setting.widget.setValue(setting.value)
            setting.widget.setToolTip(setting.help)
            setting.widget.valueChanged.connect(
                lambda value, setting=setting: self._ctr.spinbox_change_value(setting, value)
            )
            label = qtw.QLabel(f"{name:s}:")
            label.setToolTip(setting.help)
            com_lay.addRow(label, setting.widget)
        com_wid.setLayout(com_lay)
        com_box_lay = qtw.QVBoxLayout()
        com_box_lay.addWidget(com_wid)
        com_box_wid = qtw.QGroupBox("Finding Paths:")
        com_box_wid.setLayout(com_box_lay)
        pth_wid = qtw.QWidget()
        pth_lay = qtw.QFormLayout()
        col_name = "highlight_color"
        col = settings.get(col_name, None)
        if col:
            col.widget = qtw.QComboBox()
            col.widget.addItems(col.items)
            if col.value in col.items:
                col.widget.setCurrentText(col.value)
            col.widget.setToolTip(col.help)
            col.widget.currentTextChanged.connect(
                lambda value, setting=col: self._ctr.combobox_change_value(setting, value)
            )
            col_lbl = qtw.QLabel(f"{col_name:s}:")
            pth_lay.addRow(col_lbl, col.widget)
        pth_wid.setLayout(pth_lay)
        pth_box_lay = qtw.QVBoxLayout()
        pth_box_lay.addWidget(pth_wid)
        pth_box_wid = qtw.QGroupBox("Analyzing Path:")
        pth_box_wid.setLayout(pth_box_lay)
        lay = qtw.QVBoxLayout()
        lay.addWidget(com_box_wid)
        lay.addWidget(pth_box_wid)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid
    
    def _init_cnf_but(self) -> qtw.QWidget:
        """
        This method initializes the buttons.
        """
        self._save_but = qtw.QPushButton("Save")
        self._save_but.clicked.connect(self._ctr.store_configuration)
        self._reset_but = qtw.QPushButton("Reset")
        self._reset_but.clicked.connect(self._ctr.reset_conf)
        lay = qtw.QHBoxLayout()
        lay.addWidget(self._save_but)
        lay.addWidget(self._reset_but)
        wid = qtw.QWidget()
        wid.setLayout(lay)
        return wid
    
    def give_feedback(
            self,
            button_type: Literal["Save", "Reset"],
            text: str,
            msec: int = 1000
        ) -> None:
        """
        This method gives user feedback by temporarily changing a button's text.
        """
        match button_type:
            case "Save":
                button = self._save_but
            case "Reset":
                button = self._reset_but

        def restore(text: str) -> None:
            button.setText(text)
            button.setEnabled(True)
            return

        if button:
            button.setEnabled(False)
            old_text = button.text()
            button.setText(text)
            qtc.QTimer.singleShot(msec, lambda text=old_text: restore(text))
        return