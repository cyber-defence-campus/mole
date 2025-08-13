from __future__ import annotations
from mole.common.helper.function import FunctionHelper
from typing import Dict, List, Set
import binaryninja as bn
import networkx as nx


class MediumLevelILCallTracker:
    """
    This class tracks the call stack and creates a call graph.
    """

    def __init__(self) -> None:
        self.call_stack: List[bn.MediumLevelILFunction] = []
        self.call_graph: Dict[
            bn.MediumLevelILFunction, Set[bn.MediumLevelILFunction]
        ] = {}
        return

    def enter(self, callee: bn.MediumLevelILFunction) -> None:
        # Update call stack
        self.call_stack.append(callee)
        # Update call graph
        if len(self.call_stack) >= 2:
            caller = self.call_stack[-2]
            self.call_graph.setdefault(caller, set()).add(callee)
        return

    def leave(
        self, caller: bn.MediumLevelILFunction = None
    ) -> bn.MediumLevelILFunction | None:
        # Update call stack
        if self.call_stack and caller is None:
            return self.call_stack.pop()
        self.call_stack.append(caller)
        # Update call graph
        callees = self.call_graph.setdefault(caller, set())
        if len(self.call_stack) >= 2:
            callees.add(self.call_stack[-2])
        return None

    def print_call_stack(self) -> None:
        for func in reversed(self.call_stack):
            print(FunctionHelper.get_func_info(func, False))
        return

    def print_call_graph(self) -> None:
        for caller, callees in self.call_graph.items():
            caller_info = FunctionHelper.get_func_info(caller, False)
            for callee in callees:
                callee_info = FunctionHelper.get_func_info(callee, False)
                print(f"{caller_info} -> {callee_info}")
        return

    def create_call_graph(self) -> nx.DiGraph:
        graph = nx.DiGraph()
        for caller, callees in self.call_graph.items():
            for callee in callees:
                graph.add_edge(caller, callee)
        return graph
