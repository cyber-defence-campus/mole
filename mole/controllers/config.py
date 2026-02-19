from __future__ import annotations
from mole.common.helper.function import FunctionHelper
from mole.common.helper.instruction import InstructionHelper
from mole.common.log import Logger
from mole.common.parse import LogicalExpressionParser
from mole.data.config import (
    Category,
    CheckboxSetting,
    ComboboxSetting,
    Configuration,
    DoubleSpinboxSetting,
    Library,
    SinkFunction,
    SourceFunction,
    SpinboxSetting,
    TextSetting,
)
from typing import Any, Dict, Literal, Tuple, TYPE_CHECKING
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
        # Store input elements
        old_model = self.config_model.config
        sources_ie: Dict[str, Dict] = {}
        for lib_name, lib in old_model.sources.items():
            sources_ie_lib: Dict[str, Dict] = sources_ie.setdefault(lib_name, {})
            for cat_name, cat in lib.categories.items():
                sources_ie_cat: Dict = sources_ie_lib.setdefault(cat_name, {})
                for fun_name, fun in cat.functions.items():
                    sources_ie_cat[fun_name] = fun.checkbox
        sinks_ie: Dict[str, Dict] = {}
        for lib_name, lib in old_model.sinks.items():
            sinks_ie_lib: Dict[str, Dict] = sinks_ie.setdefault(lib_name, {})
            for cat_name, cat in lib.categories.items():
                sinks_ie_cat: Dict = sinks_ie_lib.setdefault(cat_name, {})
                for fun_name, fun in cat.functions.items():
                    sinks_ie_cat[fun_name] = fun.checkbox
        settings_ie = {}
        for setting_name, setting in old_model.settings.items():
            settings_ie[setting_name] = setting.widget
        # Load configuration
        new_config = self.config_service.load_custom_config()
        # Restore input elements
        for lib_name, lib in new_config.sources.items():
            sources_ie_lib = sources_ie.get(lib_name, {})
            for cat_name, cat in lib.categories.items():
                sources_ie_cat = sources_ie_lib.get(cat_name, {})
                for fun_name, fun in cat.functions.items():
                    cb_fun = sources_ie_cat.get(fun_name)
                    if not isinstance(cb_fun, qtw.QCheckBox):
                        continue
                    fun.checkbox = cb_fun
                    fun.checkbox.setChecked(fun.enabled)
        for lib_name, lib in new_config.sinks.items():
            sinks_ie_lib = sinks_ie.get(lib_name, {})
            for cat_name, cat in lib.categories.items():
                sinks_ie_cat = sinks_ie_lib.get(cat_name, {})
                for fun_name, fun in cat.functions.items():
                    cb_fun = sinks_ie_cat.get(fun_name)
                    if not isinstance(cb_fun, qtw.QCheckBox):
                        continue
                    fun.checkbox = cb_fun
                    fun.checkbox.setChecked(fun.enabled)
        for setting_name, setting in new_config.settings.items():
            setting_ie = settings_ie.get(setting_name, None)
            if isinstance(setting, CheckboxSetting) and isinstance(
                setting_ie, qtw.QCheckBox
            ):
                setting.widget = setting_ie
                setting.widget.setChecked(bool(setting.value))
            elif isinstance(setting, SpinboxSetting) and isinstance(
                setting_ie, qtw.QSpinBox
            ):
                setting.widget = setting_ie
                setting.widget.setValue(int(setting.value))
            elif isinstance(setting, DoubleSpinboxSetting) and isinstance(
                setting_ie, qtw.QDoubleSpinBox
            ):
                setting.widget = setting_ie
                setting.widget.setValue(float(setting.value))
            elif isinstance(setting, ComboboxSetting) and isinstance(
                setting_ie, qtw.QComboBox
            ):
                if str(setting.value) in setting.items:
                    setting.widget = setting_ie
                    setting.widget.setCurrentText(str(setting.value))
            elif isinstance(setting, TextSetting) and isinstance(
                setting_ie, qtw.QLineEdit
            ):
                setting.widget = setting_ie
                setting.widget.setText(str(setting.value))
        self.config_model.config = new_config
        # Update view
        self.config_view.signal_reset_config_feedback.emit(
            "Resetting...", "Reset", 1000
        )
        self.config_view.signal_save_config_feedback.emit("Save*", "Save*", 0)
        return

    def import_config(self) -> None:
        """
        This method imports a configuration.
        """
        # Open dialog to select file path
        filepath, _ = qtw.QFileDialog.getOpenFileName(
            caption="Open File", filter="YAML Files (*.yml *.yaml);;All Files (*)"
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
            caption="Save As", filter="YAML Files (*.yml *.yaml);;All Files (*)"
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
        self, is_src: bool, symbol: str, synopsis: str, par_cnt: str, par_slice: str
    ) -> Tuple[SourceFunction | SinkFunction | None, str]:
        """
        This method creates a manual source (`is_src=True`) or sink (`is_src=False`) function with
        the given parameters.
        """
        # Create expression parser
        parser = LogicalExpressionParser(self.log)
        # Parse `par_cnt` expression
        par_cnt_fun = parser.parse(par_cnt)
        if par_cnt_fun is None:
            self.log.warn(tag, f"Failed to parse 'par_cnt' expression '{par_cnt:s}'")
            return None, "Invalid par_cnt..."
        par_slice_fun = parser.parse(par_slice)
        if par_slice_fun is None:
            self.log.warn(
                tag, f"Failed to parse 'par_slice' expression '{par_slice:s}'"
            )
            return None, "Invalid par_slice..."
        # Create manual source function
        if is_src:
            fun = SourceFunction(
                name=symbol,
                symbols=[symbol],
                synopsis=synopsis,
                enabled=True,
                par_cnt=par_cnt,
                par_cnt_fun=par_cnt_fun,
                par_slice=par_slice,
                par_slice_fun=par_slice_fun,
            )
        # Create manual sink function
        else:
            fun = SinkFunction(
                name=symbol,
                symbols=[symbol],
                synopsis=synopsis,
                enabled=True,
                par_cnt=par_cnt,
                par_cnt_fun=par_cnt_fun,
                par_slice=par_slice,
                par_slice_fun=par_slice_fun,
            )
        return fun, ""

    def save_manual_fun(
        self,
        fun: SourceFunction | SinkFunction | None = None,
        err_msg: str = "",
        category_name: str = "Default",
    ) -> str:
        """
        This method saves the given function `fun` as a manual source or sink.
        """
        if fun is not None:
            # Update configuration
            manual_config = Configuration(
                sources={
                    "manual": Library(
                        name="manual",
                        categories={
                            category_name: Category(
                                name=category_name, functions={fun.name: fun}
                            )
                        },
                    )
                }
                if isinstance(fun, SourceFunction)
                else {},
                sinks={
                    "manual": Library(
                        name="manual",
                        categories={
                            category_name: Category(
                                name=category_name, functions={fun.name: fun}
                            )
                        },
                    )
                }
                if isinstance(fun, SinkFunction)
                else {},
            )
            self.config_service.update_config(self.config_model.config, manual_config)
            # Update view
            self.config_view.refresh_tabs(1 if isinstance(fun, SinkFunction) else 0)
            self.config_view.signal_save_config_feedback.emit("Save*", "Save*", 0)
        return err_msg

    def clear_manual_functions(
        self, cat_name: str, fun_type: Literal["Sources", "Sinks"]
    ) -> None:
        """
        This method clears all manual source or sink functions in the given category name
        `cat_name`.
        """
        config = self.config_model.config
        match fun_type:
            case "Sources":
                manual_lib = config.sources.get("manual", None)
                index = 0
            case "Sinks":
                manual_lib = config.sinks.get("manual", None)
                index = 1
            case _:
                manual_lib = None
                index = -1
        if manual_lib and cat_name in manual_lib.categories:
            del manual_lib.categories[cat_name]
        self.config_view.refresh_tabs(index)
        self.config_view.signal_save_config_feedback.emit("Save*", "Save*", 0)
        return

    def check_functions(
        self,
        lib_name: str | None = None,
        cat_name: str | None = None,
        fun_name: str | None = None,
        fun_type: Literal["Sources", "Sinks"] | None = None,
        fun_enabled: bool | None = None,
    ) -> None:
        """
        This method sets the enabled attribute of all functions' checkboxes matching the given
        attributes. An attribute of `None` indicates that the corresponding attribute is irrelevant.
        In case `fun_enabled` is `None` the checkboxes enabled attribute is toggled, otherwise set
        to the given value `fun_enabled`.
        """
        for fun in self.config_model.get_functions(
            lib_name, cat_name, fun_name, fun_type
        ):
            if fun_enabled is None:
                fun.enabled = not fun.enabled
            else:
                fun.enabled = fun_enabled
            if fun.checkbox is not None:
                fun.checkbox.setChecked(fun.enabled)
        self.config_view.signal_save_config_feedback.emit("Save*", "Save*", 0)
        return

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
        is_src: bool = True,
    ) -> None:
        """
        This method executes a dialog for configuring a manual source or sink function based on the
        given instruction.
        """
        # Map to MLIL call instruction
        mlil_call_insts = InstructionHelper.get_mlil_call_insts(inst)
        if len(mlil_call_insts) <= 0:
            self.log.warn(
                tag,
                "Selected instruction could not be mapped to a MLIL call instruction",
            )
            return None
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
            return None
        inst_info = InstructionHelper.get_inst_info(inst)
        self.log.info(tag, f"Selected MLIL call instruction '{inst_info:s}'")
        # Function information
        symbol, synopsis = InstructionHelper.get_func_signature(inst)
        par_cnt = f"i == {len(inst.params):d}"
        # Set dialog fields
        self.config_dialog.set_fields(
            inst, is_src, symbol, synopsis, par_cnt, "False", False
        )
        # Execute dialog
        self.config_dialog.exec()
        return

    def execute_dialog_manual_func(
        self,
        func: bn.HighLevelILFunction | bn.MediumLevelILFunction | bn.LowLevelILFunction,
        is_src: bool = True,
    ) -> None:
        """
        This method executes a dialog for configuring a manual source or sink function based on the
        given function.
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
        return self.execute_dialog_manual_inst(call_inst, is_src)
