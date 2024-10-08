from __future__   import annotations
from typing       import Dict, List, Union
from ..common.log import Logger
import os, yaml
import PySide6.QtWidgets as qtw
import PySide6.QtCore    as qtc


class ConfigModel:
    """
    Model for the plugin configuration.
    """

    def __init__(self) -> None:
        return super().__init__()
    
    def init(self, controller: ConfigController) -> ConfigModel:
        self._controller = controller
        self._conf = self.get_default_values()
        return self
    
    def get_default_values(self) -> Dict[str, Dict[str, Dict[str, Dict[str, Union[bool, str]]]]]:
        """
        Get the model's default values.
        """
        conf = {
            "Sources": {
                "Environment": {
                    "libc.getenv": {
                        "checked": True,
                        "comment": "Read environment variable"
                    }
                },
                "Stream, File and Directory": {
                    "libc.fgets": {
                        "checked": True,
                        "comment": "Read string from given stream"
                    },
                    "libc.gets": {
                        "checked": True,
                        "comment": "Read string from standard input stream"
                    }
                },
                "Network": {
                    "libgio.g_socket_receive": {
                        "checked": False,
                        "comment": "Read bytes from socket"
                    },
                    "libapr.apr_socket_recv": {
                        "checked": False,
                        "comment": "Read bytes from socket"
                    }
                }
            },
            "Sinks": {

            }
        }
        return conf
    
    def read(self) -> Dict[str, Dict[str, Dict[str, Dict[str, Union[bool, str]]]]]:
        """
        Read the model.
        """
        return self._conf
    
    def update(self, conf: Dict[str, Dict[str, Dict[str, Dict[str, Union[bool, str]]]]]) -> None:
        """
        Update the model.
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
    View for the plugin configuration.
    """

    def __init__(self) -> None:
        return super().__init__()
    
    def init(self, controller: ConfigController) -> ConfigView:
        self._controller = controller
        self._srcs_cbs = {}
        self._init_dialog()
        return self
    
    def _init_dialog(self) -> None:
        """
        Initialize main dialog.
        """
        self.setWindowTitle("Mole Configuration")
        top_lay = qtw.QVBoxLayout()
        top_lay.addWidget(self._init_tabs())
        top_lay.addWidget(self._init_buttons())
        self.setLayout(top_lay)
        return
    
    def _init_tabs(self) -> qtw.QWidget:
        """
        Initialize tabs.
        """
        tab_wid = qtw.QTabWidget()
        tab_wid.addTab(self._init_tab_sources(), "Sources")
        tab_wid.addTab(self._init_tab_sinks(), "Sinks")
        return tab_wid
    
    def _init_tab_sources(self) -> qtw.QWidget:
        """
        Initialize tab sources.
        """
        src_wid = qtw.QWidget()
        src_lay = qtw.QVBoxLayout()
        for grp_name, grp_conf in self._controller.read().get("Sources", {}).items():
            # Source functions widget
            fun_lay = qtw.QFormLayout()
            self._srcs_cbs[grp_name] = []
            for chb_name, chb_conf in grp_conf.items():
                cb = qtw.QCheckBox(chb_name)
                cb.setChecked(chb_conf.get("checked", True))
                self._srcs_cbs[grp_name].append(cb)
                fun_lay.addRow(cb, qtw.QLabel(chb_conf.get("comment", "")))
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
        TODO: Initialize tab sinks.
        """
        snk_wid = qtw.QWidget()
        return snk_wid
    
    def _init_buttons(self) -> qtw.QWidget:
        """
        Initialize buttons.
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
        Read the view.
        """
        conf = {}
        # Read source tab
        conf["Sources"] = {}
        for grp_name, cbs in self._srcs_cbs.items():
            conf["Sources"][grp_name] = {}
            for cb in cbs:
                conf["Sources"][grp_name][cb.text()] = {"checked": cb.isChecked()}
        # TODO: Read sink tab
        return conf
    
    def update(self, conf: Dict[str, Dict[str, Dict[str, Dict[str, Union[bool, str]]]]]) -> None:
        """
        Update the view.
        """
        # Update source tab
        src_conf = conf.get("Sources", {})
        for grp_name, cbs in self._srcs_cbs.items():
            grp_conf = src_conf.get(grp_name, {})
            for cb in cbs:
                cb_conf = grp_conf.get(cb.text(), {})
                cb.setChecked(bool(cb_conf.get("checked", False)))
        # TODO: Update sink tab
        return

    
class ConfigController:
    """
    Controller for the plugin configuration.
    """

    def __init__(
            self,
            model: ConfigModel, view: ConfigView,
            tag: str = "Config", log: Logger = Logger()
        ) -> None:
        self._model = model.init(self)
        self._view = view.init(self)
        self._tag = tag
        self._log = log
        self._conf_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "../../conf/config.yml"
        )
        self.load_from_file()
        return
    
    def load_from_file(self) -> None:
        """
        Load plugin configuration from file.
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
                    self._model.update(
                        {
                            tab_name: {
                                grp_name: {
                                    chb_name: {
                                        "checked": bool(chb_conf["checked"])
                                    }
                                }
                            }
                        }
                    )
        # Update view
        self._view.update(self._model.read())
        return
    
    def store_to_file(self, button: qtw.QPushButton) -> None:
        """
        Store plugin configuration to file.
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
    
    def read(self) -> Dict[str, Dict[str, Dict[str, Dict[str, Union[bool, str]]]]]:
        """
        Read plugin configuration.
        """
        return self._model.read().copy()
    
    def reset(self, button: qtw.QPushButton) -> None:
        """
        Reset plugin configuration (default values).
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
        Select or deselect all checkboxes.
        """
        for checkbox in checkboxes:
            checkbox.setChecked(checked)
        return
    
    def show_view(self) -> None:
        """
        Show the view dialog.
        """
        self._view.exec_()
        return