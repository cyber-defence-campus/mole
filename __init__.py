# Import Binary Ninja UI module
try:
    import binaryninjaui as bnui
except Exception:
    bnui = None

# Register Mole's sidebar if the Binary Ninja UI
if bnui is not None:
    from mole.common.helper.instruction import InstructionHelper
    from mole.views.sidebar import SidebarViewType, sidebar_ctrs
    from typing import cast
    import binaryninja as bn

    # Create the sidebar view type
    sidebar_view_type = SidebarViewType()

    # Register the sidebar view type with the Binary Ninja UI
    bnui.Sidebar.addSidebarWidgetType(sidebar_view_type)  # type: ignore

    # Helper functions looking up the correct sidebar controller at runtime

    def configure_selected_inst(
        bv: bn.BinaryView,
        inst: bn.HighLevelILInstruction
        | bn.MediumLevelILInstruction
        | bn.LowLevelILInstruction,
        all_callsites: bool,
    ) -> None:
        # Get the sidebar controller associated with the current BinaryView
        sidebar_ctr = sidebar_ctrs.get(bv, None)
        if sidebar_ctr is not None:
            # Execute the configuration dialog
            sidebar_ctr.config_ctr.execute_dialog_manual_inst(inst, all_callsites)
        return

    def configure_selected_func(
        bv: bn.BinaryView,
        func: bn.HighLevelILFunction | bn.MediumLevelILFunction | bn.LowLevelILFunction,
    ) -> None:
        # Get the sidebar controller associated with the current BinaryView
        sidebar_ctr = sidebar_ctrs.get(bv, None)
        if sidebar_ctr is not None:
            # Execute the configuration dialog
            sidebar_ctr.config_ctr.execute_dialog_manual_func(func)
        return

    # Helper function to check if the selected function is valid
    def is_valid_func(
        bv: bn.BinaryView,
        func: bn.HighLevelILFunction | bn.MediumLevelILFunction | bn.LowLevelILFunction,
    ) -> bool:
        try:
            ctx = bnui.UIContext.activeContext()  # type: ignore
            vf = ctx.getCurrentViewFrame()
            addr = cast(int, vf.getCurrentOffset())
            f = bv.get_function_at(addr)
        except Exception:
            return False
        if f is None:
            return False
        return func.source_function == f

    # Register commands with the Binary Ninja UI
    bn.PluginCommand.register_for_high_level_il_instruction(
        name="Mole\\Select Current HLIL Inst",
        description="Add selected HLIL call instruction to the taint model",
        action=lambda bv, inst: configure_selected_inst(bv, inst, False),
        is_valid=lambda _, inst: InstructionHelper.is_call_inst(inst),
    )
    bn.PluginCommand.register_for_high_level_il_instruction(
        name="Mole\\Select Current HLIL Inst (All Callsites)",
        description="Add all callsites of the selected HLIL call instruction to the taint model",
        action=lambda bv, inst: configure_selected_inst(bv, inst, True),
        is_valid=lambda _, inst: InstructionHelper.is_call_inst(inst),
    )
    bn.PluginCommand.register_for_high_level_il_function(
        name="Mole\\Select Current HLIL Func",
        description="Add selected HLIL function to the taint model",
        action=lambda bv, func: configure_selected_func(bv, func),
        is_valid=lambda bv, func: is_valid_func(bv, func),
    )
    bn.PluginCommand.register_for_medium_level_il_instruction(
        name="Mole\\Select Current MLIL Inst",
        description="Add selected MLIL call instruction to the taint model",
        action=lambda bv, inst: configure_selected_inst(bv, inst, False),
        is_valid=lambda _, inst: InstructionHelper.is_call_inst(inst),
    )
    bn.PluginCommand.register_for_medium_level_il_instruction(
        name="Mole\\Select Current MLIL Inst (All Callsites)",
        description="Add all callsites of the selected MLIL call instruction to the taint model",
        action=lambda bv, inst: configure_selected_inst(bv, inst, True),
        is_valid=lambda _, inst: InstructionHelper.is_call_inst(inst),
    )
    bn.PluginCommand.register_for_medium_level_il_function(
        name="Mole\\Select Current MLIL Func",
        description="Add selected MLIL function to the taint model",
        action=lambda bv, func: configure_selected_func(bv, func),
        is_valid=lambda bv, func: is_valid_func(bv, func),
    )
    bn.PluginCommand.register_for_low_level_il_instruction(
        name="Mole\\Select Current LLIL Inst",
        description="Add selected LLIL call instruction to the taint model",
        action=lambda bv, inst: configure_selected_inst(bv, inst, False),
        is_valid=lambda _, inst: InstructionHelper.is_call_inst(inst),
    )
    bn.PluginCommand.register_for_low_level_il_instruction(
        name="Mole\\Select Current LLIL Inst (All Callsites)",
        description="Add all callsites of the selected LLIL call instruction to the taint model",
        action=lambda bv, inst: configure_selected_inst(bv, inst, True),
        is_valid=lambda _, inst: InstructionHelper.is_call_inst(inst),
    )
    bn.PluginCommand.register_for_low_level_il_function(
        name="Mole\\Select Current LLIL Func",
        description="Add selected LLIL function to the taint model",
        action=lambda bv, func: configure_selected_func(bv, func),
        is_valid=lambda bv, func: is_valid_func(bv, func),
    )
