import os
import PySide6.QtWidgets as qtw
import PySide6.QtCore    as qtc
import yaml
from typing       import List
from ..common.log import Logger

    
class ConfigurationDialog(qtw.QDialog):
    """
    Dialog to configure the plugin.
    """

    def __init__(
            self,
            parent: qtw.QWidget | None = None,
            tag: str = "ConfDialog",
            log: Logger = Logger()
        ) -> None:
        super().__init__(parent)
        self._tag = tag
        self._log = log
        self._conf_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "../../conf/dialog.yml"
        )
        self._init_conf()
        self._load_conf()
        self._init_dialog()
        return
    
    def _init_conf(self) -> None:
        """
        Initialize with default configuration.
        """
        self._conf = {
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
        return
    
    def _init_dialog(self) -> None:
        """
        Initialize dialog widgets.
        """
        # Sources widget
        self.src_cbs = {}
        src_wid = qtw.QWidget()
        src_lay = qtw.QVBoxLayout()
        for grp_name, grp_conf in self._conf["Sources"].items():
            # Source functions widget
            fun_wid = qtw.QWidget()
            fun_lay = qtw.QFormLayout()
            self.src_cbs[grp_name] = []
            for chb_text, chb_conf in grp_conf.items():
                cb = qtw.QCheckBox(chb_text)
                cb.setChecked(chb_conf.get("checked", True))
                self.src_cbs[grp_name].append(cb)
                fun_lay.addRow(cb, qtw.QLabel(chb_conf.get("comment", "")))
            fun_wid.setLayout(fun_lay)
            # Button widget
            but_wid = qtw.QWidget()
            but_lay = qtw.QHBoxLayout()
            sel_but = qtw.QPushButton("Select All")
            sel_fun = lambda _, checkboxes=self.src_cbs[grp_name], checked=True: self._check_all(checkboxes, checked)
            sel_but.clicked.connect(sel_fun)
            but_lay.addWidget(sel_but)
            dsl_but = qtw.QPushButton("Deselect All")
            dsl_fun = lambda _, checkboxes=self.src_cbs[grp_name], checked=False: self._check_all(checkboxes, checked)
            dsl_but.clicked.connect(dsl_fun)
            but_lay.addWidget(dsl_but)
            but_wid.setLayout(but_lay)
            # Box widget
            box_wid = qtw.QGroupBox(f"{grp_name:s}:")
            box_lay = qtw.QVBoxLayout()
            box_lay.addWidget(fun_wid)
            box_lay.addWidget(but_wid)
            box_wid.setLayout(box_lay)
            src_lay.addWidget(box_wid)
        src_wid.setLayout(src_lay)

        # Sinks
        snk_wid = qtw.QWidget()

        # Tabs
        tab_wid = qtw.QTabWidget()
        tab_wid.addTab(src_wid, "Sources")
        tab_wid.addTab(snk_wid, "Sinks")

        # Buttons
        but_wid = qtw.QWidget()
        but_lay = qtw.QHBoxLayout()
        sav_but = qtw.QPushButton("Save")
        sav_fun = lambda _, button=sav_but: self._save_conf(button)
        sav_but.clicked.connect(sav_fun)
        but_lay.addWidget(sav_but)
        rst_but = qtw.QPushButton("Reset")
        rst_fun = lambda _, button=rst_but, : self._reset_conf(button)
        rst_but.clicked.connect(rst_fun)
        but_lay.addWidget(rst_but)
        cls_but = qtw.QPushButton("Close")
        cls_but.clicked.connect(self.close)
        but_lay.addWidget(cls_but)
        but_wid.setLayout(but_lay)

        top_lay = qtw.QVBoxLayout()
        top_lay.addWidget(tab_wid)
        top_lay.addWidget(but_wid)

        self.setLayout(top_lay)
        self.setWindowTitle("Mole Configuration")
        return

    def _load_conf(self) -> None:
        """
        Load plugin configuration from file.
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
        # Apply configuration from file
        for tab_name, tab_conf in conf.items():
            if not tab_name in self._conf:
                self._log(
                    self._tag,
                    f"Skipped invalid configuration entry '{tab_name:s}'"
                )
                continue
            for grp_name, grp_conf in tab_conf.items():
                if not grp_name in self._conf[tab_name]:
                    self._log.warn(
                        self._tag,
                        f"Skipped invalid configuration entry '{tab_name:s}/{grp_name:s}'"
                    )
                    continue
                for chb_text, chb_conf in grp_conf.items():
                    if not chb_text in self._conf[tab_name][grp_name]:
                        self._log(
                            self._tag,
                            f"Skipped invalid configuration entry '{tab_name:s}/{grp_name:s}/{chb_text:s}'"
                        )
                        continue
                    try:
                        self._conf[tab_name][grp_name][chb_text]["checked"] = bool(chb_conf["checked"])
                    except:
                        self._log.warn(
                            self._tag,
                            f"Skipped invalid configuration entry '{tab_name:s}/{grp_name:s}/{chb_text:s}'"
                        )
                        continue
        return
    
    def _save_conf(self, button: qtw.QPushButton) -> None:
        """
        Save plugin configuration to file.
        """
        # Update configuration
        for grp_name, cbs in self.src_cbs.items():
            for cb in cbs:
                self._conf["Sources"][grp_name][cb.text()]["checked"] = cb.isChecked()
        # Save configuration to file
        with open(self._conf_file, "w") as f:
            yaml.safe_dump(self._conf, f,
                           sort_keys=False,
                           default_style=None, default_flow_style=None,
                           encoding="utf-8"
            )
        # User feedback
        button.setText("Config Saved...")
        qtc.QTimer.singleShot(1000, lambda: button.setText("Save"))
        return
    
    def _reset_conf(self, button: qtw.QPushButton) -> None:
        """
        Reset plugin configuration.
        """
        # Reset configuration
        self._init_conf()
        # Update configuration
        for grp_name, cbs in self.src_cbs.items():
            for cb in cbs:
                cb.setChecked(self._conf["Sources"][grp_name][cb.text()]["checked"])
        # User feedback
        button.setText("Config Reset...")
        qtc.QTimer.singleShot(1000, lambda: button.setText("Reset"))
        return

    def _check_all(self, checkboxes: List[qtw.QCheckBox], checked: bool) -> None:
        """
        Select or deselect all checkboxes.
        """
        for checkbox in checkboxes:
            checkbox.setChecked(checked)
        return
