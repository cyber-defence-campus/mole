from __future__ import annotations
from mole.common.helper.function import FunctionHelper
from mole.common.helper.instruction import InstructionHelper
from mole.common.log import Logger
from mole.common.parse import LogicalExpressionParser
from mole.data.config import Category, Configuration, Function, Library
from typing import Any, Literal, Tuple, TYPE_CHECKING
import binaryninja as bn
import os
import PySide6.QtWidgets as qtw

if TYPE_CHECKING:
    from mole.models.config import ConfigModel
    from mole.services.config import ConfigService
    from mole.views.config import ConfigDialog, ConfigView


tag = "Config"


class ConfigController:
    """
    This class implements a controller for Mole's configuration.
    """

    def __init__(
        self,
        bv: bn.BinaryView,
        log: Logger,
        config_service: ConfigService,
        config_model: ConfigModel,
        config_view: ConfigView,
        config_dialog: ConfigDialog,
    ) -> None:
        """
        This method initializes the configuration controller.
        """
        self.bv = bv
        self.log = log
        self.config_service = config_service
        self.config_model = config_model
        self.config_view = config_view
        self.config_dialog = config_dialog
        return

    def save_config(self) -> None:
        """
        This method saves the configuration.
        """
        # Save configuration
        self.config_service.save_config(self.config_model.config)
        # Update view
        self.config_view.signal_save_config_feedback.emit("Saving...", "Save", 1000)
        return

    def reset_config(self) -> None:
        """
        This method resets the configuration.
        """
        # Clear current configuration file
        self.config_service.clear_main_config_file()
        # Load default configuration
        config = self.config_service.load_config()
        # Save configuration file
        self.config_service.save_config(config)
        # Update model
        self.config_model.config = config
        # Update view
        self.config_view.refresh_tabs()
        self.config_view.signal_reset_config_feedback.emit(
            "Resetting...", "Reset", 1000
        )
        self.config_view.signal_save_config_feedback.emit("Save", "Save", 0)
        return

    def import_config(self) -> None:
        """
        This method imports a configuration.
        """
        # Open dialog to select file path
        filepath, _ = qtw.QFileDialog.getOpenFileName(
            caption="Open File", filter="JSON Files (*.json);;All Files (*)"
        )
        if not filepath:
            return
        # Expand file path
        filepath = os.path.abspath(os.path.expanduser(os.path.expandvars(filepath)))
        # Update default configuration with the imported one
        config = self.config_service.load_custom_config(ignore_enabled=True)
        import_config = self.config_service.import_config(filepath)
        self.config_service.update_config(config, import_config)
        self.config_model.config = config
        # Update view
        self.config_view.refresh_tabs()
        self.config_view.signal_import_config_feedback.emit(
            "Importing...", "Import", 1000
        )
        self.config_view.signal_save_config_feedback.emit("Save*", "Save*", 0)
        return

    def export_config(self) -> None:
        """
        This method exports the configuration.
        """
        # Open dialog to select file path
        filepath, _ = qtw.QFileDialog.getSaveFileName(
            caption="Save As", filter="JSON Files (*.json);;All Files (*)"
        )
        if not filepath:
            return
        # Expand file path
        filepath = os.path.abspath(os.path.expanduser(os.path.expandvars(filepath)))
        # Export configuration
        self.config_service.export_config(self.config_model.config, filepath)
        # Update view
        self.config_view.signal_export_config_feedback.emit(
            "Exporting...", "Export", 1000
        )
        return

    def create_manual_fun(
        self,
        name: str,
        synopsis: str,
        par_slice: str,
        src_enabled: bool,
        snk_enabled: bool,
        fix_enabled: bool,
    ) -> Tuple[Function | None, str]:
        """
        This method creates and returns a function with the given parameters. If the parameters are
        invalid, it returns `None` and an error message.
        """
        # Validate synopsis
        try:
            fun_type, _ = self.bv.parse_type_string(synopsis)
            if not isinstance(fun_type, bn.types.FunctionType):
                raise TypeError()
        except Exception:
            return None, "Invalid Synopsis..."
        # Validate par_slice
        parser = LogicalExpressionParser(self.log)
        par_slice_fun = parser.parse(par_slice)
        if par_slice_fun is None:
            self.log.warn(
                tag, f"Failed to parse 'par_slice' expression '{par_slice:s}'"
            )
            return None, "Invalid Par Slice..."
        # Create manual function
        fun = Function(
            name=name,
            symbols=[name],
            synopsis=synopsis,
            par_slice=par_slice,
            src_enabled=src_enabled,
            snk_enabled=snk_enabled,
            fix_enabled=fix_enabled,
        )
        return fun, ""

    def save_manual_fun(
        self,
        category_name: str = "Default",
        fun: Function | None = None,
        err_msg: str = "",
    ) -> str:
        """
        This method saves the given function `fun` as a manual source or sink.
        """
        if fun is not None:
            # Update configuration
            manual_config = Configuration(
                taint_model={
                    "manual": Library(
                        name="manual",
                        categories={
                            category_name: Category(
                                name=category_name, functions={fun.name: fun}
                            )
                        },
                    )
                }
            )
            self.config_service.update_config(self.config_model.config, manual_config)
            # Update view
            self.config_view.refresh_tabs(0)
            self.config_view.signal_save_config_feedback.emit("Save*", "Save*", 0)
        return err_msg

    # # TODO: Remove
    # def clear_manual_functions(
    #     self, cat_name: str, fun_type: Literal["Sources", "Sinks"]
    # ) -> None:
    #     """
    #     This method clears all manual source or sink functions in the given category name
    #     `cat_name`.
    #     """
    #     config = self.config_model.config
    #     match fun_type:
    #         case "Sources":
    #             manual_lib = config.sources.get("manual", None)
    #             index = 0
    #         case "Sinks":
    #             manual_lib = config.sinks.get("manual", None)
    #             index = 1
    #         case _:
    #             manual_lib = None
    #             index = -1
    #     if manual_lib and cat_name in manual_lib.categories:
    #         del manual_lib.categories[cat_name]
    #     self.config_view.refresh_tabs(index)
    #     self.config_view.signal_save_config_feedback.emit("Save*", "Save*", 0)
    #     return

    def change_setting(self, name: str, value: Any) -> None:
        """
        This method changes setting values.
        """
        setting = self.config_model.get_setting(name)
        if setting:
            setting.value = value
        self.config_view.signal_save_config_feedback.emit("Save*", "Save*", 0)
        return

    def give_feedback(
        self,
        button_type: Literal["Find", "Add"] = "Find",
        tmp_text: str = "",
        new_text: str = "",
        msec: int = 1000,
    ) -> None:
        """
        This method gives feedback on the given button.
        """
        match button_type:
            case "Find":
                self.config_dialog.signal_find_feedback.emit(tmp_text, new_text, msec)
            case "Add":
                self.config_dialog.signal_add_feedback.emit(tmp_text, new_text, msec)
        if not tmp_text:
            self.config_dialog.accept()
        return

    def execute_dialog_manual_inst(
        self,
        inst: bn.HighLevelILInstruction
        | bn.MediumLevelILInstruction
        | bn.LowLevelILInstruction,
        all_callsites: bool,
    ) -> None:
        """
        This method executes a dialog to manually configure a function based on the given
        instruction `inst`.
        """
        # Map to MLIL call instruction
        mlil_call_insts = InstructionHelper.get_mlil_call_insts(inst)
        if len(mlil_call_insts) <= 0:
            self.log.warn(
                tag,
                "Selected instruction could not be mapped to a MLIL call instruction",
            )
            return
        # Get MLIL call instruction in SSA form
        inst = mlil_call_insts[0].ssa_form
        if not isinstance(
            inst,
            (
                bn.MediumLevelILCall,
                bn.MediumLevelILCallSsa,
                bn.MediumLevelILCallUntyped,
                bn.MediumLevelILCallUntypedSsa,
                bn.MediumLevelILTailcall,
                bn.MediumLevelILTailcallSsa,
                bn.MediumLevelILTailcallUntyped,
                bn.MediumLevelILTailcallUntypedSsa,
            ),
        ):
            self.log.warn(
                tag,
                "Selected instruction could not be mapped to a MLIL call instruction in SSA form",
            )
            return
        inst_info = InstructionHelper.get_inst_info(inst)
        self.log.info(tag, f"Selected MLIL call instruction '{inst_info:s}'")
        # Function information
        name, synopsis = InstructionHelper.get_func_signature(inst)
        # Set dialog fields
        self.config_dialog.set_fields(inst, all_callsites, name, synopsis)
        # Execute dialog
        self.config_dialog.exec()
        return

    def execute_dialog_manual_func(
        self,
        func: bn.HighLevelILFunction | bn.MediumLevelILFunction | bn.LowLevelILFunction,
    ) -> None:
        """
        This method executes a dialog to manually configure a function based on the given function
        `func`.
        """
        # Get MLIL function in SSA form
        if not isinstance(func, bn.MediumLevelILFunction):
            mlil_func = func.mlil
        else:
            mlil_func = func
        if mlil_func is None or mlil_func.ssa_form is None:
            self.log.warn(tag, "Selected function has no SSA form")
            return
        mlil_func = mlil_func.ssa_form
        # Build a synthetic MLIL call instruction in SSA form
        call_inst = FunctionHelper.get_mlil_synthetic_call_inst(mlil_func)
        if call_inst is None:
            self.log.warn(
                tag, "Could not create synthetic call instruction for selected function"
            )
            return
        # Execute dialog using the synthetic call instruction
        return self.execute_dialog_manual_inst(call_inst, False)
