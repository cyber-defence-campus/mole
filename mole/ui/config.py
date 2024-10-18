from __future__   import annotations
from typing       import Dict, List, Literal, Union
from ..common.log import Logger
from ..model      import lib
import os
import PySide6.QtWidgets as qtw
import PySide6.QtCore    as qtc
import yaml


class ConfigModel:
    """
    This class implements the model for plugin configuration.
    """

    def __init__(self) -> None:
        return super().__init__()
    
    def init(self, controller: ConfigController) -> None:
        """
        This method initializes the model.
        """
        self._controller = controller
        self.reset()
        return
    
    def reset(self) -> None:
        """
        This method resets the model (i.e. sets the model's default values).
        """
        self._conf = {}
        for flowtype in ["Sources", "Sinks"]:
            self._conf[flowtype] = {}
            for fun in self._controller.get_all_funs(flowtype):
                if not fun.category.value in self._conf[flowtype]:
                    self._conf[flowtype][fun.category.value] = {}
                if not fun.name in self._conf[flowtype][fun.category.value]:
                    self._conf[flowtype][fun.category.value][fun.name] = {}
                self._conf[flowtype][fun.category.value][fun.name]["enabled"] = fun.enabled
                self._conf[flowtype][fun.category.value][fun.name]["description"] = fun.description
                self._conf[flowtype][fun.category.value][fun.name]["synopsis"] = fun.synopsis
        self._conf["Settings"] = {
            "Common": {
                "max_func_depth": {
                    "value": 3,
                    "help": "backward slicing visits called functions up to the given depth"
                }
            }
        }
        return
    
    def read(self) -> Dict[str, Dict[str, Dict[str, Union[int, Dict[str, Union[bool, str]]]]]]:
        """
        This method returns the model.
        """
        return self._conf
    
    def update(self, new_conf: Dict[str, Dict[str, Dict[str, Union[int, Dict[str, Union[bool, str]]]]]]) -> None:
        """
        This method updates the model.
        """
        old_conf = self.read()
        if not isinstance(new_conf, dict): return
        for tab_name, tab_conf in new_conf.items():
            if not isinstance(tab_conf, dict): continue
            if tab_name in ["Sources", "Sinks"]:
                for grp_name, grp_conf in tab_conf.items():
                    if not isinstance(grp_conf, dict): continue
                    if not grp_name in old_conf[tab_name]: continue
                    for chb_name, chb_conf in grp_conf.items():
                        if not isinstance(chb_conf, dict): continue
                        if not chb_name in old_conf[tab_name][grp_name]: continue
                        try:
                            chb_enabled = bool(chb_conf.get("enabled", None))
                            self._conf[tab_name][grp_name][chb_name]["enabled"] = chb_enabled
                        except:
                            continue
            elif tab_name == "Settings":
                max_func_depth = tab_conf.get("Common", {}).get("max_func_depth", {})
                try:
                    v = max_func_depth.get("value", None)
                    v = max(0, min(int(v), 10))
                    self._conf["Settings"]["Common"]["max_func_depth"]["value"] = v
                except:
                    pass
                try:
                    v = max_func_depth.get("help", "")
                    self._conf["Settings"]["Common"]["max_func_depth"]["help"] = v
                except:
                    pass
        return


class ConfigView(qtw.QDialog):
    """
    This class implements the view for plugin configuration.
    """

    def __init__(self, runs_headless: bool = False) -> None:
        self._runs_headless = runs_headless
        if not self._runs_headless:
            super().__init__()
        return None
    
    def init(self, controller: ConfigController) -> None:
        """
        This method initializes the view.
        """
        self._controller = controller
        if not self._runs_headless:
            self._init_dialog()
        return
    
    def _init_dialog(self) -> None:
        """
        This method initializes the main dialog.
        """
        self._inputs = {}
        self.setWindowTitle("Mole Configuration")
        top_lay = qtw.QVBoxLayout()
        top_lay.addWidget(self._init_tabs())
        top_lay.addWidget(self._init_buttons())
        self.setLayout(top_lay)
        return
    
    def _init_tabs(self) -> qtw.QWidget:
        """
        This method initializes the tabs.
        """
        tab_wid = qtw.QTabWidget()
        tab_wid.addTab(self._init_tab(tab_name="Sources"), "Sources")
        tab_wid.addTab(self._init_tab(tab_name="Sinks"), "Sinks")
        tab_wid.addTab(self._init_tab_settings(), "Settings")
        return tab_wid
    
    def _init_tab(self, tab_name: Literal["Sources", "Sinks"]) -> qtw.QScrollArea:
        """
        This method initializes the tabs `Sources` and `Sinks`.
        """
        tab_wid = qtw.QWidget()
        tab_lay = qtw.QVBoxLayout()
        self._inputs[tab_name] = {}
        for grp_name, grp_conf in self._controller.get_model().get(tab_name, {}).items():
            # Function widget
            fun_lay = qtw.QFormLayout()
            self._inputs[tab_name][grp_name] = []
            for chb_name, chb_conf in grp_conf.items():
                cb = qtw.QCheckBox(chb_name)
                cb.setChecked(chb_conf.get("enabled", True))
                cb.setToolTip(chb_conf.get("synopsis", ""))
                self._inputs[tab_name][grp_name].append(cb)
                ql = qtw.QLabel(chb_conf.get("description", ""))
                ql.setToolTip(chb_conf.get("synopsis", ""))
                fun_lay.addRow(cb, ql)
            fun_wid = qtw.QWidget()
            fun_wid.setLayout(fun_lay)
            # Button widget
            but_lay = qtw.QHBoxLayout()
            sel_but = qtw.QPushButton("Select All")
            sel_cbs = self._inputs[tab_name][grp_name]
            sel_fun = lambda _, checkboxes=sel_cbs, checked=True: self._controller.check_all(checkboxes, checked)
            sel_but.clicked.connect(sel_fun)
            but_lay.addWidget(sel_but)
            dsl_but = qtw.QPushButton("Deselect All")
            dsl_cbs = self._inputs[tab_name][grp_name]
            dsl_fun = lambda _, checkboxes=dsl_cbs, checked=False: self._controller.check_all(checkboxes, checked) 
            dsl_but.clicked.connect(dsl_fun)
            but_lay.addWidget(dsl_but)
            but_wid = qtw.QWidget()
            but_wid.setLayout(but_lay)
            # Box widget
            box_lay = qtw.QVBoxLayout()
            box_lay.addWidget(fun_wid)
            box_lay.addWidget(but_wid)
            box_wid = qtw.QGroupBox(f"{grp_name:s}:")
            box_wid.setLayout(box_lay)
            tab_lay.addWidget(box_wid)
        tab_wid.setLayout(tab_lay)
        tab_scr = qtw.QScrollArea()
        tab_scr.setMinimumWidth(650)
        tab_scr.setMinimumHeight(550)
        tab_scr.setWidget(tab_wid)
        tab_scr.setWidgetResizable(True)
        return tab_scr
    
    def _init_tab_settings(self) -> qtw.QWidget:
        """
        This method initializes the tab `Settings`.
        """
        settings_common = self._controller.get_model().get("Settings", {}).get("Common", {})

        com_wid = qtw.QWidget()
        com_lay = qtw.QFormLayout()
        rec_spi_wid = qtw.QSpinBox()
        rec_spi_wid.setRange(0, 10)
        rec_spi_val = settings_common.get("max_func_depth", {}).get("value", 3)
        rec_spi_wid.setValue(rec_spi_val)
        rec_spi_tip = settings_common.get("max_func_depth", {}).get("help", "")
        rec_spi_wid.setToolTip(rec_spi_tip)
        self._inputs["Settings"] = {
            "Common": {
                "max_func_depth": rec_spi_wid
            }
        }
        rec_spi_lbl = qtw.QLabel("max_func_depth")
        rec_spi_lbl.setToolTip(rec_spi_tip)
        com_lay.addRow(rec_spi_wid, rec_spi_lbl)
        com_wid.setLayout(com_lay)

        box_wid = qtw.QGroupBox("Common:")
        box_lay = qtw.QVBoxLayout()
        box_lay.addWidget(com_wid)
        box_wid.setLayout(box_lay)

        tab_wid = qtw.QWidget()
        tab_lay = qtw.QVBoxLayout()
        tab_lay.addWidget(box_wid)
        tab_wid.setLayout(tab_lay)
        return tab_wid
    
    def _init_buttons(self) -> qtw.QWidget:
        """
        This method initializes the buttons.
        """
        but_wid = qtw.QWidget()
        but_lay = qtw.QHBoxLayout()
        sav_but = qtw.QPushButton("Save")
        sav_but.clicked.connect(lambda _, button=sav_but: self._controller.store_to_file(button))
        but_lay.addWidget(sav_but)
        rst_but = qtw.QPushButton("Reset")
        rst_but.clicked.connect(lambda _, button=rst_but: self._controller.reset(button))
        but_lay.addWidget(rst_but)
        cls_but = qtw.QPushButton("Close")
        cls_but.clicked.connect(self.close)
        but_lay.addWidget(cls_but)
        but_wid.setLayout(but_lay)
        return but_wid
    
    def read(self) -> Dict[str, Dict[str, Dict[str, Union[int, Dict[str, Union[bool, str]]]]]]:
        """
        This method returns the view.
        """
        conf = {}
        if self._runs_headless: return conf
        for tab_name, grp_conf in self._inputs.items():
            if not tab_name in ["Sources", "Sinks"]: continue
            conf[tab_name] = {}
            for grp_name, cbs in grp_conf.items():
                conf[tab_name][grp_name] = {}
                for cb in cbs:
                    conf[tab_name][grp_name][cb.text()] = {"enabled": cb.isChecked()}
        conf["Settings"] = {
            "Common": {
                "max_func_depth": {
                    "value": self._inputs["Settings"]["Common"]["max_func_depth"].value()
                }
            }
        }
        return conf
    
    def update(self, conf: Dict[str, Dict[str, Dict[str, Union[int, Dict[str, Union[bool, str]]]]]]) -> None:
        """
        This method updates the view.
        """
        if self._runs_headless: return
        for tab_name in ["Sources", "Sinks"]:
            tab_conf = conf.get(tab_name, {})
            for grp_name, cbs in self._inputs.get(tab_name, {}).items():
                grp_conf = tab_conf.get(grp_name, {})
                for cb in cbs:
                    cb_conf = grp_conf.get(cb.text(), {})
                    cb.setChecked(bool(cb_conf.get("enabled", False)))
        settings_common = conf.get("Settings", {}).get("Common", {})
        rec_spi_val = settings_common.get("max_func_depth", {}).get("value", None)
        if not rec_spi_val is None:
            rec_spi_wid = self._inputs["Settings"]["Common"]["max_func_depth"]
            rec_spi_wid.setValue(rec_spi_val)
        return


class ConfigController:
    """
    This class implements the controller for plugin configuration.
    """

    def __init__(
            self,
            model: ConfigModel,
            view: ConfigView,
            src_funs: List[lib.func] = [],
            snk_funs: List[lib.func] = [],
            tag: str = "Config",
            log: Logger = Logger()
        ) -> None:
        self._model = model
        self._view = view
        self._src_funs = src_funs
        self._snk_funs = snk_funs
        self._tag = tag
        self._log = log
        self._conf_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "../../conf/config.yml"
        )
        return
    
    def init(self) -> None:
        """
        This method initializes the model and view.
        """
        self._model.init(self)
        self._view.init(self)
        self.load_from_file()
        return
    
    def load_from_file(self) -> None:
        """
        This method loads the plugin configuration from a file.
        """
        # Load configuration from file
        try:
            with open(self._conf_file, "r") as f:
                conf = yaml.safe_load(f)
        except FileNotFoundError:
            return
        except:
            self._log.warn(
                self._tag,
                f"Failed to load configuration from file '{self._conf_file:s}'"
            )
            return
        # Update model
        self._model.update(conf)
        # Update view
        self._view.update(self._model.read())
        return
    
    def store_to_file(self, button: qtw.QPushButton = None) -> None:
        """
        This method stores the plugin configuration to a file.
        """
        # Update model
        self._model.update(self._view.read())
        # Save configuration to file
        with open(self._conf_file, "w") as f:
            yaml.safe_dump(self._model.read(), f,
                           sort_keys=False,
                           default_style=None, default_flow_style=None,
                           encoding="utf-8"
            )
        # Send user feedback
        if not button is None:
            button.setText("Saving...")
            qtc.QTimer.singleShot(1000, lambda: button.setText("Save"))
        return

    def get_all_funs(self, flowtype: Literal["Sources", "Sinks"]) -> List[lib.func]:
        """
        This method returns all source or sink functions.
        """
        if flowtype == "Sources":
            return self._src_funs
        elif flowtype == "Sinks":
            return self._snk_funs
        return []
    
    def get_enabled_funs(self, flowtype: Literal["Sources", "Sinks"]) -> List[lib.func]:
        """
        This method returns a list of all enabled source or sink functions.
        """
        ena_funs = []
        all_funs = self.get_all_funs(flowtype=flowtype)
        model = self._model.read()
        for fun in all_funs:
            fun_conf = model.get(flowtype, {}).get(fun.category.value, {}).get(fun.name, {})
            if fun_conf.get("enabled", False):
                ena_funs.append(fun)
        return ena_funs

    def get_max_func_depth(self) -> int:
        """
        This method returns the `max_func_depth` value.
        """
        model = self._model.read()
        return model["Settings"]["Common"]["max_func_depth"]["value"]

    def get_model(self) -> Dict[str, Dict[str, Dict[str, Union[int, Dict[str, Union[bool, str]]]]]]:
        """
        This method returns the model.
        """
        return self._model.read()
    
    def reset(self, button: qtw.QPushButton) -> None:
        """
        This method resets the plugin configuration (i.e. set the plugin's default values).
        """
        # Reset model
        self._model.reset()
        # Update view
        self._view.update(self._model.read())
        # Send user feedback
        button.setText("Resetting...")
        qtc.QTimer.singleShot(1000, lambda: button.setText("Reset"))
        return
    
    def check_all(self, checkboxes: List[qtw.QCheckBox], checked: bool) -> None:
        """
        This method selects or deselects all checkboxes.
        """
        for checkbox in checkboxes:
            checkbox.setChecked(checked)
        return
    
    def show_view(self) -> None:
        """
        This method shows the view dialog.
        """
        self._view.exec_()
        return