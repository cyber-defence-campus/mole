from __future__ import annotations
from mole.views.graph import CallGraphWidget
from mole.views.path_tree import PathTreeView
from typing import Dict, Optional, Tuple, TYPE_CHECKING
import binaryninja as bn
import binaryninjaui as bnui
import os as os
import PySide6.QtCore as qtc
import PySide6.QtWidgets as qtw

if TYPE_CHECKING:
    from mole.controllers.path import PathController


class PathView(bnui.SidebarWidget):
    """
    This class implements the widget for the plugin's sidebar.
    """

    signal_find_paths = qtc.Signal()
    signal_find_paths_feedback = qtc.Signal(object, object, int)
    signal_load_paths = qtc.Signal()
    signal_load_paths_feedback = qtc.Signal(object, object, int)
    signal_save_paths = qtc.Signal()
    signal_save_paths_feedback = qtc.Signal(object, object, int)
    signal_setup_path_tree = qtc.Signal(object, object, object)
    signal_auto_update_paths = qtc.Signal(bool)

    def __init__(self) -> None:
        """
        This method initializes a sidebar widget.
        """
        super().__init__("Mole")
        self._bv: Optional[bn.BinaryView] = None
        self._wid: Optional[qtw.QTabWidget] = None
        self.path_ctr: Optional[PathController] = None
        self.path_tabs: Dict[bn.BinaryView, Tuple[qtw.QWidget, str]] = {}
        return

    def init(self, path_ctr: PathController) -> PathView:
        """
        This method sets the controller and initializes relevant UI components.
        """
        # Set controller
        self.path_ctr = path_ctr
        # Tab widget
        self._wid = qtw.QTabWidget()
        self._wid.addTab(*self._init_path_tab())
        self._wid.addTab(*self._init_graph_tab())
        self._wid.addTab(self.path_ctr.ai_ctr.ai_view, "AI Report")
        self._wid.addTab(self.path_ctr.config_ctr.config_view, "Configure")
        # Scroll widget
        scr_wid = qtw.QScrollArea()
        scr_wid.setWidgetResizable(True)
        scr_wid.setWidget(self._wid)
        # Main layout
        main_lay = qtw.QVBoxLayout()
        main_lay.addWidget(scr_wid)
        self.setLayout(main_lay)
        return self

    def _init_path_tab(self) -> Tuple[qtw.QWidget, str]:
        """
        This method initializes the tab `Path`.
        """
        # Initialize control buttons
        run_but = qtw.QPushButton("Find")
        run_but.clicked.connect(self.signal_find_paths.emit)
        self.signal_find_paths_feedback.connect(
            lambda tmp_text, new_text, msec: self.give_feedback(
                run_but, tmp_text, new_text, msec
            )
        )
        load_but = qtw.QPushButton("Load")
        load_but.clicked.connect(self.signal_load_paths.emit)
        self.signal_load_paths_feedback.connect(
            lambda tmp_text, new_text, msec: self.give_feedback(
                load_but, tmp_text, new_text, msec
            )
        )
        save_but = qtw.QPushButton("Save")
        save_but.clicked.connect(self.signal_save_paths.emit)
        self.signal_save_paths_feedback.connect(
            lambda tmp_text, new_text, msec: self.give_feedback(
                save_but, tmp_text, new_text, msec
            )
        )
        update_but = qtw.QPushButton("Auto-Update")
        update_but.setCheckable(True)
        update_but.setChecked(True)
        update_but.toggled.connect(
            lambda checked: self.signal_auto_update_paths.emit(checked)
        )

        # Initialize button widget
        but_lay = qtw.QHBoxLayout()
        but_lay.addWidget(run_but)
        but_lay.addWidget(load_but)
        but_lay.addWidget(save_but)
        but_lay.addWidget(update_but)
        but_wid = qtw.QWidget()
        but_wid.setLayout(but_lay)

        # Initialize PathTreeView widget
        path_tree_wid = PathTreeView(
            "Empty" if self._bv is None else self._bv.file.filename
        )
        path_tree_wid.signal_show_ai_report.connect(self.path_ctr.show_ai_report)
        path_tree_wid.path_tree_model.signal_path_modified.connect(
            lambda: self.give_feedback(save_but, "Save*", "Save*", 0)
        )

        # Initialize path tab widget
        lay = qtw.QVBoxLayout()
        lay.addWidget(path_tree_wid)
        lay.addWidget(but_wid)
        wid = qtw.QWidget()
        wid.setLayout(lay)

        return wid, "Paths"

    def _init_graph_tab(self) -> Tuple[qtw.QWidget, str]:
        return CallGraphWidget(self.path_ctr), "Graph"

    def give_feedback(
        self,
        button: qtw.QPushButton,
        tmp_text: str = None,
        new_text: str = None,
        msec: int = 1000,
    ) -> None:
        """
        This method changes `button`'s text to `tmp_text` for `msec` milliseconds and then back to
        `new_text`. If `tmp_text` is `None` or `msec` is less than or equal to 0, it directly sets
        the button's text to `new_text`. If `new_text` is `None`, it restores the current text of
        the button.
        """

        def restore(text: str) -> None:
            button.setText(text)
            button.setEnabled(True)
            return

        if button:
            if new_text is None:
                new_text = button.text()
            if tmp_text is not None and msec > 0:
                button.setEnabled(False)
                button.setText(tmp_text)
                qtc.QTimer.singleShot(msec, lambda text=new_text: restore(text))
            else:
                button.setText(new_text)
        return

    def notifyViewChanged(self, vf: bnui.ViewFrame) -> None:
        """
        This method is a callback invoked when the active view in the Binary UI changes.
        """
        # Ensure the BinaryView changed
        new_bv: bn.BinaryView = vf.getCurrentBinaryView() if vf else None
        if new_bv is not None and new_bv != self._bv:
            # Create a new path tab if none exists for the BinaryView
            if new_bv not in self.path_tabs:
                new_path_tab, new_path_tab_name = self._init_path_tab()
                self.path_tabs[new_bv] = (new_path_tab, new_path_tab_name)
            # Take the existing path tab of the BinaryView
            else:
                new_path_tab, new_path_tab_name = self.path_tabs[new_bv]
            # Emit signal to set up the path tab's PathTreeView
            new_path_tree_view = new_path_tab.layout().itemAt(0).widget()
            self.signal_setup_path_tree.emit(new_bv, new_path_tree_view, self._wid)
            # Replace old path tab with the new one
            self._wid.removeTab(0)
            self._wid.insertTab(0, new_path_tab, new_path_tab_name)
            self._wid.setCurrentIndex(0)
            # Store the newly active BinaryView and its path tab
            self._bv = new_bv

            # # Create a new PathTreeView if none exists for the BinaryView
            # if new_bv not in self.path_tree_views:
            #     new_path_tree_view = PathTreeView(new_bv.file.filename)
            #     self.path_tree_views[new_bv] = new_path_tree_view
            # # Take the existing PathTreeView of the BinaryView
            # else:
            #     new_path_tree_view = self.path_tree_views[new_bv]
            # # Emit signal to set up the PathTreeView
            # self.signal_setup_path_tree.emit(new_bv, new_path_tree_view, self._wid)
            # # Update the PathTreeView for the newly active BinaryView
            # path_tab_lay = self._path_tree_view.parentWidget().layout()
            # path_tab_lay.replaceWidget(self._path_tree_view, new_path_tree_view)
            # self._path_tree_view.hide()
            # new_path_tree_view.show()
            # # Store the newly active BinaryView and its PathTreeView
            # self._bv = new_bv
            # self._path_tree_view = new_path_tree_view
        return

    def show_ai_report_tab(self) -> None:
        """
        This method switches to the AI Report tab.
        """
        for i in range(self._wid.count()):
            if self._wid.tabText(i) == "AI Report":
                self._wid.setCurrentIndex(i)
                break
        return


class FunctionUpdateNotification(bn.BinaryDataNotification):
    """
    This class catches update notifications with respect to functions and updates paths in the
    sidebar's path view.
    """

    def __init__(self, path_ctr: Optional[PathController]) -> None:
        """
        This method initializes a notification handler.
        """
        super(FunctionUpdateNotification, self).__init__(
            bn.NotificationType.NotificationBarrier
            | bn.NotificationType.FunctionLifetime
            | bn.NotificationType.FunctionUpdated
        )
        self.path_ctr = path_ctr
        self.received_event = False
        return

    def notification_barrier(self, bv: bn.BinaryView) -> int:
        """
        This method updates the paths after notifications have been received.
        """
        if self.received_event:
            self.received_event = False
            if (
                self.path_ctr is not None
                and self.path_ctr.auto_update_paths
                and self.path_ctr.thread_finished
            ):
                self.path_ctr.update_paths()
        return 250

    def function_updated(self, bv: bn.BinaryView, func: bn.Function) -> None:
        """
        This method marks that a function has been updated.
        """
        self.received_event = True
        return
