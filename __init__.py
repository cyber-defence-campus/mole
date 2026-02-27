# Import Binary Ninja UI module
try:
    import binaryninjaui as bnui
except Exception:
    bnui = None

# Register Mole's sidebar if the Binary Ninja UI
if bnui is not None:
    from mole.views.sidebar import SidebarViewType, sidebar_ctrs
    import binaryninja as bn

    # Create the sidebar view type
    sidebar_view_type = SidebarViewType()

    # Register the sidebar view type with the Binary Ninja UI
    bnui.Sidebar.addSidebarWidgetType(sidebar_view_type)  # type: ignore

    # Helper functions looking up the correct sidebar controller at runtime

    def find_paths_from_manual_inst(
        bv: bn.BinaryView,
        inst: bn.HighLevelILInstruction
        | bn.MediumLevelILInstruction
        | bn.LowLevelILInstruction,
        is_src: bool = True,
    ) -> None:
        # Get the sidebar controller associated with the current BinaryView
        sidebar_ctr = sidebar_ctrs.get(bv, None)
        if sidebar_ctr is not None:
            # Execute the configuration dialog
            sidebar_ctr.config_ctr.execute_dialog_manual_inst(inst, is_src)
        return

    def find_paths_from_manual_func(
        bv: bn.BinaryView,
        func: bn.HighLevelILFunction | bn.MediumLevelILFunction | bn.LowLevelILFunction,
        is_src: bool = True,
    ) -> None:
        # Get the sidebar controller associated with the current BinaryView
        sidebar_ctr = sidebar_ctrs.get(bv, None)
        if sidebar_ctr is not None:
            # Execute the configuration dialog
            sidebar_ctr.config_ctr.execute_dialog_manual_func(func, is_src)
        return

    # Register commands with the Binary Ninja UI
    bn.PluginCommand.register_for_high_level_il_instruction(
        name="Mole\\1. Select HLIL Instruction as Source",
        description="Find paths using the selected HLIL call instruction as source",
        action=lambda bv, inst: find_paths_from_manual_inst(bv, inst, is_src=True),
    )
    bn.PluginCommand.register_for_high_level_il_instruction(
        name="Mole\\2. Select HLIL Instruction as Sink",
        description="Find paths using the selected HLIL call instruction as sink",
        action=lambda bv, inst: find_paths_from_manual_inst(bv, inst, is_src=False),
    )
    bn.PluginCommand.register_for_high_level_il_function(
        name="Mole\\1. Select HLIL Function as Source",
        description="Find paths using the selected HLIL function as source",
        action=lambda bv, func: find_paths_from_manual_func(bv, func, is_src=True),
    )
    bn.PluginCommand.register_for_medium_level_il_instruction(
        name="Mole\\1. Select MLIL Instruction as Source",
        description="Find paths using the selected MLIL call instruction as source",
        action=lambda bv, inst: find_paths_from_manual_inst(bv, inst, is_src=True),
    )
    bn.PluginCommand.register_for_medium_level_il_instruction(
        name="Mole\\2. Select MLIL Instruction as Sink",
        description="Find paths using the selected MLIL call instruction as sink",
        action=lambda bv, inst: find_paths_from_manual_inst(bv, inst, is_src=False),
    )
    bn.PluginCommand.register_for_medium_level_il_function(
        name="Mole\\1. Select MLIL Function as Source",
        description="Find paths using the selected MLIL function as source",
        action=lambda bv, func: find_paths_from_manual_func(bv, func, is_src=True),
    )
    bn.PluginCommand.register_for_low_level_il_instruction(
        name="Mole\\1. Select LLIL Instruction as Source",
        description="Find paths using the selected LLIL call instruction as source",
        action=lambda bv, inst: find_paths_from_manual_inst(bv, inst, is_src=True),
    )
    bn.PluginCommand.register_for_low_level_il_instruction(
        name="Mole\\2. Select LLIL Instruction as Sink",
        description="Find paths using the selected LLIL call instruction as sink",
        action=lambda bv, inst: find_paths_from_manual_inst(bv, inst, is_src=False),
    )
    bn.PluginCommand.register_for_low_level_il_function(
        name="Mole\\1. Select LLIL Function as Source",
        description="Find paths using the selected LLIL function as source",
        action=lambda bv, func: find_paths_from_manual_func(bv, func, is_src=True),
    )
