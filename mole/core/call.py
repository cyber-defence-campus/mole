from __future__ import annotations
from mole.common.helper.function import FunctionHelper
from mole.common.helper.instruction import InstructionHelper
from typing import List
import binaryninja as bn
import networkx as nx


class MediumLevelILCallFrame:
    """
    TODO
    """

    def __init__(self, func: bn.MediumLevelILFunction) -> None:
        self.func = func
        self.inst_stack: List[bn.MediumLevelILInstruction] = []
        return

    def __repr__(self) -> str:
        return f"<MediumLevelILCallFrame: {self.func.source_function.name:s}>"

    def __str__(self) -> str:
        return (
            f"0x{self.func.source_function.start:x} {self.func.source_function.name:s}"
        )


class MediumLevelILCallTracker:
    """
    This class tracks the call stack and creates a call graph.
    """

    def __init__(self) -> None:
        self.call_stack: List[MediumLevelILCallFrame] = []
        self.call_graph = nx.DiGraph()  # TODO: Maybe use MediumLevelILFunctionGraph
        return

    def push_func(self, func: bn.MediumLevelILFunction, reverse: bool = False) -> None:
        """
        This method creates a new call frame with the given function `func` and pushes it to the top
        of the call stack. Also, it updates the call graph. If `reverse` is True, `func` is
        considered to be the caller (not the callee).
        """
        # Update call stack
        self.call_stack.append(MediumLevelILCallFrame(func))
        # Update call graph
        if len(self.call_stack) >= 2:
            if not reverse:
                caller = self.call_stack[-2].func
                self.call_graph.add_edge(caller, func)
            else:
                callee = self.call_stack[-2].func
                self.call_graph.add_edge(func, callee)
        return

    def pop_func(self) -> bn.MediumLevelILFunction | None:
        """
        This method pops the top call frame from the call stack and returns the call frame's
        function.
        """
        if self.call_stack:
            return self.call_stack.pop().func
        return None

    def is_top_func(self, func: bn.MediumLevelILFunction) -> bool:
        """
        This method checks if the given function `func` is at the top of the call stack.
        """
        return self.call_stack and self.call_stack[-1].func == func

    def push_inst(self, inst: bn.MediumLevelILInstruction) -> None:
        """
        This method pushes the given instruction `inst` to the call frame on the top of the call
        stack.
        """
        if self.call_stack:
            self.call_stack[-1].inst_stack.append(inst)
        return

    def pop_inst(self) -> bn.MediumLevelILInstruction | None:
        """
        This method pops an instruction from the call frame on the top of the call stack.
        """
        if self.call_stack:
            return self.call_stack[-1].inst_stack.pop()
        return None

    def print_call_stack(self) -> None:
        """
        TODO: This method prints the call stack.
        """
        for call_frame in self.call_stack:
            print(str(call_frame))
        return

    def print_call_graph(self) -> None:
        """
        TODO: This method prints the call graph.
        """
        for caller, callee in self.call_graph.edges():
            caller_info = FunctionHelper.get_func_info(caller, False)
            callee_info = FunctionHelper.get_func_info(callee, False)
            print(f"{caller_info} -> {callee_info}")
        return

    def print_inst_slice(self) -> None:
        """
        TODO: This method prints the instruction slice.
        """
        for call_frame in self.call_stack:
            print(str(call_frame))
            for inst in call_frame.inst_stack:
                inst_info = InstructionHelper.get_inst_info(inst, False)
                print(f"- {inst_info:s}")
        return
