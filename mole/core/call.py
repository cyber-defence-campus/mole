from __future__ import annotations
from mole.common.helper.function import FunctionHelper
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


class MediumLevelILCallTracker:
    """
    This class tracks the call stack and creates a call graph.
    """

    def __init__(self) -> None:
        # self.call_stack: List[bn.MediumLevelILFunction] = []
        self.call_stack: List[MediumLevelILCallFrame] = []
        self.call_graph = nx.DiGraph()  # TODO: Maybe use MediumLevelILFunctionGraph
        return

    def enter(self, callee: bn.MediumLevelILFunction) -> None:
        """
        TODO
        """
        # Update call stack
        # self.call_stack.append(func)
        self.call_stack.append(MediumLevelILCallFrame(callee))
        # Update call graph
        if len(self.call_stack) >= 2:
            caller = self.call_stack[-2].func
            self.call_graph.add_edge(caller, callee)
        return

    def leave(
        self, caller: bn.MediumLevelILFunction = None
    ) -> bn.MediumLevelILFunction | None:
        """
        TODO
        """
        # Update call stack
        if self.call_stack and caller is None:
            return self.call_stack.pop().func
        self.call_stack.append(MediumLevelILCallFrame(caller))
        # Update call graph
        if len(self.call_stack) >= 2:
            self.call_graph.add_edge(caller, self.call_stack[-2].func)
        return None

    def is_top(self, func: bn.MediumLevelILFunction) -> bool:
        """
        This method checks if the given function is at the top of the call stack.
        """
        return self.call_stack and self.call_stack[-1].func == func

    def print_call_stack(self) -> None:
        """
        TODO
        """
        for call_frame in reversed(self.call_stack):
            print(FunctionHelper.get_func_info(call_frame.func, False))
        return

    def print_call_graph(self) -> None:
        """
        TODO
        """
        for caller, callee in self.call_graph.edges():
            caller_info = FunctionHelper.get_func_info(caller, False)
            callee_info = FunctionHelper.get_func_info(callee, False)
            print(f"{caller_info} -> {callee_info}")
        return
