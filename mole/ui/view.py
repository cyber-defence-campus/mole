import os
import PySide6.QtWidgets as qtw
import yaml
from typing import List


# class ConfigWidget(QWidget):
#     """
#     """

#     def __init__(self, parent: QWidget | None = None) -> None:
#         super().__init__(parent)
#         self.setWindowTitle("Mole Configuration")

#         layout = QVBoxLayout()
#         layout.addWidget(QCheckBox("Checkbox1", self))
#         layout.addWidget(QCheckBox("Checkbox2", self))
#         layout.addWidget(QPushButton("Save", self))
#         self.setLayout(layout)
#         return
    
class ConfigurationDialog(qtw.QDialog):
    """
    """

    def __init__(self, parent: qtw.QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Mole Configuration")
        self.src_cbs = {}
        self.config_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "../../config/srcs.yml"
        )

        # Sources
        srcs = {
            "Environment": [
                ("libc.getenv", True, "Read environment variable")
            ],
            "Stream, File and Directory": [
                ("libc.fgets", True, "Read string from given stream"),
                ("libc.gets", True, "Read string from standard input stream")
            ],
            "Network": [
                ("libgio.g_socket_receive", False, "Read bytes from socket"),
                ("libapr.apr_socket_recv", False, "Read bytes from socket")
            ]
        }
        # Sources widget
        src_wid = qtw.QWidget()
        src_lay = qtw.QVBoxLayout()
        for grp, funs in srcs.items():
            # Source functions widget
            fun_wid = qtw.QWidget()
            fun_lay = qtw.QFormLayout()
            self.src_cbs[grp] = []
            for fun, chk, cmt in funs:
                cb = qtw.QCheckBox(fun)
                cb.setChecked(chk)
                self.src_cbs[grp].append(cb)
                fun_lay.addRow(cb, qtw.QLabel(cmt))
            fun_wid.setLayout(fun_lay)
            # Button widget
            but_wid = qtw.QWidget()
            but_lay = qtw.QHBoxLayout()
            sel_but = qtw.QPushButton("Select All")
            sel_fun = lambda _, checkboxes=self.src_cbs[grp], checked=True: self.check_all(checkboxes, checked)
            sel_but.clicked.connect(sel_fun)
            but_lay.addWidget(sel_but)
            dsl_but = qtw.QPushButton("Deselect All")
            dsl_fun = lambda _, checkboxes=self.src_cbs[grp], checked=False: self.check_all(checkboxes, checked)
            dsl_but.clicked.connect(dsl_fun)
            but_lay.addWidget(dsl_but)
            but_wid.setLayout(but_lay)
            # Box widget
            box_wid = qtw.QGroupBox(f"{grp:s}:")
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
        sav_but.clicked.connect(self.save)
        but_lay.addWidget(sav_but)
        cls_but = qtw.QPushButton("Close")
        cls_but.clicked.connect(self.close)
        but_lay.addWidget(cls_but)
        but_wid.setLayout(but_lay)

        top_lay = qtw.QVBoxLayout()
        top_lay.addWidget(tab_wid)
        top_lay.addWidget(but_wid)

        self.setLayout(top_lay)
        return

    def check_all(self, checkboxes: List[qtw.QCheckBox], checked: bool) -> None:
        """
        Select or deselect all checkboxes.
        """
        for checkbox in checkboxes:
            checkbox.setChecked(checked)
        return
    
    def save(self) -> None:
        """
        """
        src = {}
        for grp, cbs in self.src_cbs.items():
            src[grp] = []
            for cb in cbs:
                src[grp].append((cb.text(), cb.isChecked()))
        with open(self.config_file, "w") as f:
            yaml.safe_dump(src, f,
                           sort_keys=False,
                           default_style=None, default_flow_style=None,
                           encoding="utf-8"
            )
        return
