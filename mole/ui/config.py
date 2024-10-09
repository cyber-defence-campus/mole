from __future__   import annotations
from typing       import Dict, List, Union
from ..analysis   import lib
from ..common.log import Logger
import os, yaml
import PySide6.QtWidgets as qtw
import PySide6.QtCore    as qtc


class ConfigModel:
    """
    This class implements the model for plugin configuration.
    """

    def __init__(self) -> None:
        return super().__init__()
    
    def init(self, controller: ConfigController) -> None:
        self._controller = controller
        self._conf = self.get_default_values()
        return
    
    def get_default_values(self) -> Dict[str, Dict[str, Dict[str, Dict[str, Union[bool, str]]]]]:
        """
        This method returns the model's default values.
        """
        # Sources
        src_conf = {}
        for src_fun in self._controller.get_all_src_funs():
            if not src_fun.category.value in src_conf:
                src_conf[src_fun.category.value] = {}
            if not src_fun.name in src_conf[src_fun.category.value]:
                src_conf[src_fun.category.value][src_fun.name] = {}
            src_conf[src_fun.category.value][src_fun.name]["enabled"] = src_fun.enabled
            src_conf[src_fun.category.value][src_fun.name]["description"] = src_fun.description
        # TODO: Sinks
        snk_conf = {}
        for snk_fun in self._controller.get_all_snk_funs():
            pass
        return {"Sources": src_conf, "Sinks": snk_conf}
    
    def get_enabled_src_funs(self) -> List[lib.func]:
        """
        This method returns a list of all enabled source functions.
        """
        ena_src_funs = []
        all_src_funs = self._controller.get_all_src_funs()
        for src_fun in all_src_funs:
            src_fun_conf = self._conf["Sources"][src_fun.category.value][src_fun.name]
            if src_fun_conf["enabled"]:
                ena_src_funs.append(src_fun)
        return ena_src_funs
    
    def read(self) -> Dict[str, Dict[str, Dict[str, Dict[str, Union[bool, str]]]]]:
        """
        This method returns the model.
        """
        return self._conf
    
    def update(self, conf: Dict[str, Dict[str, Dict[str, Dict[str, Union[bool, str]]]]]) -> None:
        """
        This method updates the model.
        """
        def deep_update(ori: Dict, upd: Dict) -> Dict:
            for key, val in upd.items():
                if (key in ori and
                    isinstance(ori[key], dict) and
                    isinstance(val, dict)):
                    deep_update(ori[key], val)
                else:
                    ori[key] = val
            return ori
        self._conf = deep_update(self._conf, conf)
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
        self._controller = controller
        self._srcs_cbs = {}
        if not self._runs_headless:
            self._init_dialog()
        return
    
    def _init_dialog(self) -> None:
        """
        This method initializes the main dialog.
        """
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
        tab_wid.addTab(self._init_tab_sources(), "Sources")
        tab_wid.addTab(self._init_tab_sinks(), "Sinks")
        return tab_wid
    
    def _init_tab_sources(self) -> qtw.QWidget:
        """
        This method initializes the tab `Sources`.
        """
        src_wid = qtw.QWidget()
        src_lay = qtw.QVBoxLayout()
        for grp_name, grp_conf in self._controller.get_model().get("Sources", {}).items():
            # Source functions widget
            fun_lay = qtw.QFormLayout()
            self._srcs_cbs[grp_name] = []
            for chb_name, chb_conf in grp_conf.items():
                cb = qtw.QCheckBox(chb_name)
                cb.setChecked(chb_conf.get("enabled", True))
                self._srcs_cbs[grp_name].append(cb)
                fun_lay.addRow(cb, qtw.QLabel(chb_conf.get("description", "")))
            fun_wid = qtw.QWidget()
            fun_wid.setLayout(fun_lay)
            # Button widget
            but_lay = qtw.QHBoxLayout()
            sel_but = qtw.QPushButton("Select All")
            sel_fun = lambda _, checkboxes=self._srcs_cbs[grp_name], checked=True: self._controller.check_all(checkboxes, checked)
            sel_but.clicked.connect(sel_fun)
            but_lay.addWidget(sel_but)
            dsl_but = qtw.QPushButton("Deselect All")
            dsl_fun = lambda _, checkboxes=self._srcs_cbs[grp_name], checked=False: self._controller.check_all(checkboxes, checked) 
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
            src_lay.addWidget(box_wid)
        src_wid.setLayout(src_lay)
        return src_wid
    
    def _init_tab_sinks(self) -> qtw.QWidget:
        """
        TODO: This method initializes the tab `Sinks`.
        """
        snk_wid = qtw.QWidget()
        return snk_wid
    
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
    
    

    def read(self) -> Dict[str, Dict[str, Dict[str, Dict[str, Union[bool, str]]]]]:
        """
        This method returns the view.
        """
        conf = {}
        # Read source tab
        conf["Sources"] = {}
        for grp_name, cbs in self._srcs_cbs.items():
            conf["Sources"][grp_name] = {}
            for cb in cbs:
                conf["Sources"][grp_name][cb.text()] = {"enabled": cb.isChecked()}
        # TODO: Read sink tab
        return conf
    
    def update(self, conf: Dict[str, Dict[str, Dict[str, Dict[str, Union[bool, str]]]]]) -> None:
        """
        This method updates the view.
        """
        # Update source tab
        src_conf = conf.get("Sources", {})
        for grp_name, cbs in self._srcs_cbs.items():
            grp_conf = src_conf.get(grp_name, {})
            for cb in cbs:
                cb_conf = grp_conf.get(cb.text(), {})
                cb.setChecked(bool(cb_conf.get("enabled", False)))
        # TODO: Update sink tab
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
                new_conf = yaml.safe_load(f)
        except FileNotFoundError:
            return
        except:
            self._log.warn(
                self._tag,
                f"Failed to load configuration from file '{self._conf_file:s}'"
            )
            return
        # Update model
        old_conf = self._model.read()
        for tab_name, tab_conf in new_conf.items():
            if not tab_name in old_conf:
                self._log(
                    self._tag,
                    f"Skipped invalid configuration entry '{tab_name:s}'"
                )
                continue
            for grp_name, grp_conf in tab_conf.items():
                if not grp_name in old_conf[tab_name]:
                    self._log.warn(
                        self._tag,
                        f"Skipped invalid configuration entry '{tab_name:s}/{grp_name:s}'"
                    )
                    continue
                for chb_name, chb_conf in grp_conf.items():
                    if not chb_name in old_conf[tab_name][grp_name]:
                        self._log(
                            self._tag,
                            f"Skipped invalid configuration entry '{tab_name:s}/{grp_name:s}/{chb_name:s}'"
                        )
                        continue
                    self._model.update({
                        tab_name: {
                            grp_name: {
                                chb_name: {
                                    "enabled": bool(chb_conf["enabled"])
                                }
                            }
                        }
                    })
        # Update view
        self._view.update(self._model.read())
        return
    
    def store_to_file(self, button: qtw.QPushButton) -> None:
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
        button.setText("Saving...")
        qtc.QTimer.singleShot(1000, lambda: button.setText("Save"))
        return
    
    def get_all_src_funs(self) -> List[lib.func]:
        """
        This method returns all source functions.
        """
        return self._src_funs
    
    def get_all_snk_funs(self) -> List[lib.func]:
        """
        This method returns all sink functions.
        """
        return self._snk_funs
    
    def get_enabled_src_funs(self) -> List[lib.func]:
        """
        This method returns a list of all enabled source functions.
        """
        return self._model.get_enabled_src_funs()
    
    def get_model(self) -> Dict[str, Dict[str, Dict[str, Dict[str, Union[bool, str]]]]]:
        """
        This method returns the model.
        """
        return self._model.read()
    
    def reset(self, button: qtw.QPushButton) -> None:
        """
        This method resets the plugin configuration (default values).
        """
        # Reset model
        self._model.update(self._model.get_default_values())
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