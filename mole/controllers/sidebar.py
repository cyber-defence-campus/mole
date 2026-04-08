from __future__ import annotations
from mole.controllers.ai import AiController
from mole.controllers.config import ConfigController
from mole.controllers.graph import GraphController
from mole.controllers.path import PathController
from typing import TYPE_CHECKING
import binaryninja as bn

if TYPE_CHECKING:
    from mole.views.sidebar import SidebarView


class SidebarController:
    """
    This class implements a controller for Mole's sidebar.
    """

    def __init__(
        self,
        bv: bn.BinaryView,
        sidebar_view: SidebarView,
        config_ctr: ConfigController,
        path_ctr: PathController,
        graph_ctr: GraphController,
        ai_ctr: AiController,
    ) -> None:
        """
        This method starts initializing the sidebar controller.
        """
        self.bv = bv
        self.sidebar_view = sidebar_view
        self.config_ctr = config_ctr
        self.path_ctr = path_ctr
        self.graph_ctr = graph_ctr
        self.ai_ctr = ai_ctr
        self._register_notifications()
        self._connect_signals()
        return

    def _register_notifications(self) -> None:
        """
        This method registers all notifications in the sidebar.
        """
        self.bv.register_notification(SidebarUpdateNotification(self.path_ctr))
        return

    def _connect_signals(self) -> None:
        """
        This method connects all signals in the sidebar.
        """
        # Connect config view signals
        self.config_ctr.config_view.signal_save_config.connect(
            self.config_ctr.save_config
        )
        self.config_ctr.config_view.signal_reset_config.connect(
            self.config_ctr.reset_config
        )
        self.config_ctr.config_view.signal_import_config.connect(
            self.config_ctr.import_config
        )
        self.config_ctr.config_view.signal_export_config.connect(
            self.config_ctr.export_config
        )
        self.config_ctr.config_view.signal_change_setting.connect(
            self.config_ctr.change_setting
        )
        self.config_ctr.config_view.signal_change_highlight_color.connect(
            lambda: self.graph_ctr.show_call_graph(show_tab=False)
        )
        self.config_ctr.config_view.signal_change_path_grouping.connect(
            self.path_ctr.regroup_paths
        )
        self.config_ctr.config_view.fun_add_dialog.signal_find.connect(
            lambda inst,
            all_callsites,
            name,
            synopsis,
            aliases,
            src_enabled,
            src_par_slice,
            snk_enabled,
            snk_par_slice,
            fix_enabled: self.config_ctr.give_feedback(
                "Find",
                self.path_ctr.find_paths_from_call_inst(
                    inst,
                    all_callsites,
                    *self.config_ctr.create_fun(
                        name,
                        synopsis,
                        aliases,
                        src_enabled,
                        src_par_slice,
                        snk_enabled,
                        snk_par_slice,
                        fix_enabled,
                    ),
                ),
            )
        )
        self.config_ctr.config_view.fun_add_dialog.signal_add.connect(
            lambda cat_name,
            name,
            synopsis,
            aliases,
            src_enabled,
            src_par_slice,
            snk_enabled,
            snk_par_slice,
            fix_enabled: self.config_ctr.give_feedback(
                "Add",
                self.config_ctr.save_fun(
                    "manual",
                    cat_name,
                    *self.config_ctr.create_fun(
                        name,
                        synopsis,
                        aliases,
                        src_enabled,
                        src_par_slice,
                        snk_enabled,
                        snk_par_slice,
                        fix_enabled,
                    ),
                ),
            )
        )
        self.config_ctr.config_view.fun_edit_dialog.signal_edit.connect(
            lambda lib_name,
            cat_name,
            name,
            synopsis,
            aliases,
            src_enabled,
            src_par_slice,
            snk_enabled,
            snk_par_slice,
            fix_enabled: self.config_ctr.give_feedback(
                "Edit",
                self.config_ctr.save_fun(
                    lib_name,
                    cat_name,
                    *self.config_ctr.create_fun(
                        name,
                        synopsis,
                        aliases,
                        src_enabled,
                        src_par_slice,
                        snk_enabled,
                        snk_par_slice,
                        fix_enabled,
                    ),
                ),
            )
        )
        # Connect path model signals
        self.path_ctr.path_proxy_model.modelReset.connect(
            self.path_ctr.path_view.path_tree_view.refresh_view
        )
        self.path_ctr.path_proxy_model.dataChanged.connect(
            self.path_ctr.path_view.path_tree_view.handle_comment_edit
        )
        self.path_ctr.path_proxy_model.path_tree_model.signal_paths_updated.connect(
            self.path_ctr.path_view.path_tree_view.refresh_view
        )
        self.path_ctr.path_proxy_model.path_tree_model.dataChanged.connect(
            lambda: self.path_ctr.give_feedback("Save", "Save*", "Save*", 0)
        )
        # Connect path view signals
        self.path_ctr.path_view.signal_find_paths.connect(self.path_ctr.find_paths)
        self.path_ctr.path_view.signal_load_paths.connect(self.path_ctr.load_paths)
        self.path_ctr.path_view.signal_load_paths.emit()
        self.path_ctr.path_view.signal_save_paths.connect(self.path_ctr.save_paths)
        self.path_ctr.path_view.signal_auto_update_paths.connect(
            lambda enable: setattr(self.path_ctr, "auto_update_paths", enable)
        )
        self.path_ctr.path_view.path_tree_view.customContextMenuRequested.connect(
            lambda pos: self.path_ctr.path_view.path_tree_view.setup_context_menu(
                pos=pos,
                on_log_path=self.path_ctr.log_path,
                on_log_path_diff=self.path_ctr.log_path_diff,
                on_log_call=self.path_ctr.log_call,
                on_highlight_path=self.path_ctr.highlight_path,
                on_show_call_graph=self.graph_ctr.show_call_graph,
                on_import_paths=lambda: self.path_ctr.import_paths(),
                on_export_paths=self.path_ctr.export_paths,
                on_update_paths=self.path_ctr.update_paths,
                on_remove_paths=self.path_ctr.remove_paths,
                on_clear_paths=self.path_ctr.clear_paths,
                is_ai_analysis_alive=lambda: self.ai_ctr.ai_service.is_alive("analyze"),
                on_start_ai_analysis=lambda paths: self.ai_ctr.analyze_paths(
                    paths, self.path_ctr.add_path_report
                ),
                on_cancel_ai_analysis=lambda: self.ai_ctr.ai_service.cancel("analyze"),
                on_show_ai_report=self.ai_ctr.show_report,
            )
        )
        self.path_ctr.path_view.path_tree_view.doubleClicked.connect(
            self.path_ctr.path_view.path_tree_view.navigate
        )
        self.path_ctr.path_view.path_tree_view.signal_show_ai_report.connect(
            self.ai_ctr.show_report
        )
        # Connect graph view signals
        self.graph_ctr.graph_view.signal_show_graph_tab.connect(
            lambda: self.sidebar_view.show_tab("Graph")
        )
        self.graph_ctr.graph_view.signal_update_graph.connect(
            self.graph_ctr.show_call_graph
        )
        # Connect AI view signals
        self.ai_ctr.ai_view.signal_show_ai_report_tab.connect(
            lambda: self.sidebar_view.show_tab("AI Report")
        )
        return


class SidebarUpdateNotification(bn.BinaryDataNotification):
    """
    This class implements a notification handler for Mole's sidebar.
    """

    def __init__(self, path_ctr: PathController) -> None:
        """
        This method initializes a notification handler.
        """
        super(SidebarUpdateNotification, self).__init__(
            bn.NotificationType.NotificationBarrier
            | bn.NotificationType.FunctionLifetime
            | bn.NotificationType.FunctionUpdated
        )
        self.path_ctr = path_ctr
        self.received_event = False
        return

    def notification_barrier(self, view: bn.BinaryView) -> int:
        """
        This method updates the paths after notifications have been received.
        """
        if self.received_event:
            if (
                self.path_ctr.auto_update_paths
                and not self.path_ctr.path_service.is_alive()
            ):
                self.received_event = False
                self.path_ctr.update_paths()
        return 250

    def function_updated(self, view: bn.BinaryView, func: bn.Function) -> None:
        """
        This method catches function update notifications and marks that an update has occurred.
        """
        self.received_event = True
        return
