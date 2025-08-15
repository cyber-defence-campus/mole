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
        self.func_params: List[int] = []
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
        self._call_stack: List[MediumLevelILCallFrame] = []
        self._call_graph = nx.DiGraph()  # TODO: Maybe use MediumLevelILFunctionGraph
        return

    def push_func(self, func: bn.MediumLevelILFunction, reverse: bool = False) -> None:
        """
        This method creates a new call frame with the given function `func` and pushes it to the top
        of the call stack. Also, it updates the call graph. If `reverse` is True, `func` is
        considered to be the caller (not the callee).
        """
        # Update call stack
        self._call_stack.append(MediumLevelILCallFrame(func))
        # Update call graph
        if len(self._call_stack) >= 2:
            if not reverse:
                caller = self._call_stack[-2].func
                self._call_graph.add_edge(caller, func)
            else:
                callee = self._call_stack[-2].func
                self._call_graph.add_edge(func, callee)
        return

    # def new_push_func(self, func: bn.MediumLevelILFunction) -> None:
    #     """
    #     TODO: c005d4d
    #     """
    #     # Update call stack
    #     self._call_stack.append(MediumLevelILCallFrame(func))
    #     # Update call graph
    #     if len(self._call_stack) >= 2:
    #         caller = self._call_stack[-2].func
    #         self._call_graph.add_edge(caller, func)
    #     return

    # def old_pop_func(self) -> bn.MediumLevelILFunction | None:
    #     """
    #     This method pops the top call frame from the call stack and returns the call frame's
    #     function.
    #     """
    #     if self._call_stack:
    #         return self._call_stack.pop().func
    #     return None

    def pop_func(self) -> List[int]:
        """
        This method pops the top call frame from the call stack and returns a list function
        parameter instructions that should be sliced further.
        """
        if self._call_stack:
            return self._call_stack.pop().func_params
        return []

    # def new_pop_func(
    #     self, func: bn.MediumLevelILFunction
    # ) -> bn.MediumLevelILFunction | None:
    #     """
    #     TODO: c005d4d
    #     """
    #     # Update call stack
    #     if self._call_stack and func is None:
    #         return self._call_stack.pop().func
    #     self._call_stack.append(MediumLevelILCallFrame(func))
    #     # Update call graph
    #     if len(self._call_stack) >= 2:
    #         self._call_graph.add_edge(func, self._call_stack[-2].func)
    #     return

    def is_func_at(self, func: bn.MediumLevelILFunction, idx: int = -1) -> bool:
        """
        This method checks if the given function `func` is at the given stack position `idx` (-1 for
        top).
        """
        try:
            return self._call_stack[idx].func == func
        except IndexError:
            pass
        return False

    def goes_downwards(self) -> bool:
        """
        TODO
        """
        if len(self._call_stack) >= 2:
            callee = self._call_stack[-1].func
            caller = self._call_stack[-2].func
            if self._call_graph.has_edge(caller, callee):
                return True
        return False

    def get_call_level(self) -> int:
        """
        This method returns the current call level.
        """
        return len(self._call_stack) - 1

    def push_inst(self, inst: bn.MediumLevelILInstruction) -> None:
        """
        This method pushes the given instruction `inst` to the call frame on the top of the call
        stack.
        """
        if self._call_stack:
            self._call_stack[-1].inst_stack.append(inst)
        return

    def pop_inst(self) -> bn.MediumLevelILInstruction | None:
        """
        This method pops an instruction from the call frame on the top of the call stack.
        """
        if self._call_stack:
            return self._call_stack[-1].inst_stack.pop()
        return None

    def push_param(self, param_idx: int) -> None:
        """
        This method pushes the given parameter index `param_idx` to the call frame on the top of the
        stack.
        """
        if self._call_stack:
            self._call_stack[-1].func_params.append(param_idx)
        return

    # def pop_param(self) -> int | None:
    #     """
    #     This method pops a parameter index from the call frame on the top of the call stack.
    #     """
    #     if self._call_stack:
    #         return self._call_stack[-1].func_params.pop()
    #     return None

    def print_call_stack(self) -> None:
        """
        TODO: This method prints the call stack.
        """
        for call_frame in self._call_stack:
            print(str(call_frame))
        return

    def print_call_graph(self) -> None:
        """
        TODO: This method prints the call graph.
        """
        for caller, callee in self._call_graph.edges():
            caller_info = FunctionHelper.get_func_info(caller, False)
            callee_info = FunctionHelper.get_func_info(callee, False)
            print(f"{caller_info} -> {callee_info}")
        return

    def print_inst_slice(self) -> None:
        """
        TODO: This method prints the instruction slice.
        """
        for call_frame in self._call_stack:
            print(str(call_frame))
            for inst in call_frame.inst_stack:
                inst_info = InstructionHelper.get_inst_info(inst, False)
                print(f"- {inst_info:s}")
        return
