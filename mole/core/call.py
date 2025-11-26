from __future__ import annotations
from mole.common.helper.function import FunctionHelper
from mole.common.helper.instruction import InstructionHelper
from mole.core.graph import MediumLevelILFunctionGraph, MediumLevelILInstructionGraph
from typing import List, Set
import binaryninja as bn
import networkx as nx


class MediumLevelILCallFrame:
    """
    This class represents a call frame the call stack.
    """

    def __init__(self, func: bn.MediumLevelILFunction) -> None:
        self.func = func
        self.func_params: Set[int] = set()
        self.inst_stack: List[bn.MediumLevelILInstruction] = []
        self.last_inst: bn.MediumLevelILInstruction = None
        self.inst_graph: MediumLevelILInstructionGraph = MediumLevelILInstructionGraph()
        self.mem_def_insts: List[bn.MediumLevelILInstruction] = []
        return

    def __eq__(self, other: MediumLevelILCallFrame) -> bool:
        if not isinstance(other, MediumLevelILCallFrame):
            raise TypeError("Call frame is not of type MediumLevelILCallFrame")
        return self.func == other.func

    def __repr__(self) -> str:
        return f"<MediumLevelILCallFrame: {self.func.source_function.name:s}>"

    def __str__(self) -> str:
        return f"0x{self.func.source_function.start:x} {self.func.source_function.symbol.short_name:s}"


class MediumLevelILCallTracker:
    """
    This class tracks the call stack and creates a call graph.
    """

    def __init__(self) -> None:
        self._call_stack: List[MediumLevelILCallFrame] = []
        self._call_graph: MediumLevelILFunctionGraph = MediumLevelILFunctionGraph()
        self._inst_graph: MediumLevelILInstructionGraph = (
            MediumLevelILInstructionGraph()
        )
        return

    def get_call_level(self) -> int:
        """
        This method returns the current call level.
        """
        return len(self._call_stack) - 1

    def get_call_graph(self) -> MediumLevelILFunctionGraph:
        """
        This method returns the current call graph.
        """
        return self._call_graph

    def get_inst_graph(self) -> MediumLevelILInstructionGraph:
        """
        This method returns the current instruction graph.
        """
        return self._inst_graph

    def is_in_current_call_frame(self, inst: bn.MediumLevelILInstruction) -> bool:
        """
        This method checks if the given instruction `inst` is included in the instruction stack of
        the frame at top of the call stack.
        """
        return inst in self._call_stack[-1].inst_stack if self._call_stack else False

    def is_in_current_mem_def_insts(self, inst: bn.MediumLevelILInstruction) -> bool:
        """
        This method checks if the given instruction `inst` is included in the memory definition
        instructions of the frame at the top of the call stack.
        """
        return inst in self._call_stack[-1].mem_def_insts if self._call_stack else False

    def is_going_downwards(self) -> bool:
        """
        This method returns `True` if we are currently going down the call graph and `False`
        otherwise.
        """
        if len(self._call_stack) >= 2:
            callee = self._call_stack[-1].func
            caller = self._call_stack[-2].func
            if self._call_graph.has_edge(caller, callee):
                return True
        return False

    def push_func(
        self,
        to_inst: bn.MediumLevelILInstruction,
        reverse: bool = False,
        param_idx: int = 0,
    ) -> bool:
        """
        This method creates a new call frame with the function `to_inst.function` and pushes it to
        the top of the call stack. Further, it updates the call graph. If `reverse` is `False`,
        `to_inst.function` is treated as the callee; if `reverse` is `True`, it is treated as the
        caller. When traversing down the call graph (`reverse==False`), `param_idx` indicates the
        callee's output parameter that was followed, or `0` if the traversal followed a return
        instruction. When traversing up the call graph (`reverse==True`), `param_idx` indicates the
        caller's relevant parameter. The function returns `True` in case of recursion, `False`
        otherwise.
        """
        # Get the return instruction's function
        func = to_inst.function
        # Create new call frame
        new_call_frame = MediumLevelILCallFrame(func)
        # Push return instruction to the call frame's instruction stack
        new_call_frame.inst_stack.append(to_inst)
        # Detect recursion
        recursion = new_call_frame in self._call_stack
        # Pop return instruction from the call frame's instruction stack
        new_call_frame.inst_stack.pop()
        # Update call stack
        self._call_stack.append(new_call_frame)
        # Update call graph
        if not recursion:
            # Update call graph
            if len(self._call_stack) >= 2:
                if not reverse:
                    caller_frame = self._call_stack[-2]
                    self._call_graph.add_edge(
                        caller_frame.func, func, downwards=True, param_idx=param_idx
                    )
                else:
                    callee_frame = self._call_stack[-2]
                    self._call_graph.add_edge(
                        func, callee_frame.func, downwards=False, param_idx=param_idx
                    )
            else:
                self._call_graph.add_node(func)
        return recursion

    def pop_func(self) -> Set[int]:
        """
        This method pops the top call frame from the call stack and returns a set of parameter
        indices (`func_params`) that should be sliced further.
        """
        if self._call_stack:
            # Pop old call frame and get its last instruction
            old_call_frame = self._call_stack.pop()
            old_last_inst = old_call_frame.last_inst
            # Determine current call frame's last instruction
            cur_last_inst = None
            if len(self._call_stack) >= 1:
                # Get current call frame and its last instruction
                cur_call_frame = self._call_stack[-1]
                cur_last_inst = cur_call_frame.inst_stack[-1]
                # Determine previous call frame's last instruction
                pre_last_inst = None
                if len(self._call_stack) >= 2:
                    # Get previous call frame and its last instruction
                    pre_call_frame = self._call_stack[-2]
                    pre_last_inst = pre_call_frame.inst_stack[-1]
                # Add edge between current and old last instructions
                self._inst_graph.add_edge(
                    (pre_last_inst, cur_last_inst), (cur_last_inst, old_last_inst)
                )
            # Update instruction graph
            mapping = {
                node: (cur_last_inst, node) for node in old_call_frame.inst_graph.nodes
            }
            old_inst_graph = nx.relabel_nodes(old_call_frame.inst_graph, mapping)
            self._inst_graph = nx.compose(self._inst_graph, old_inst_graph)
            # Return indices of parameters to be sliced further
            return old_call_frame.func_params
        return set()

    def push_inst(
        self, inst: bn.MediumLevelILInstruction, call_params: Set[int] = set()
    ) -> None:
        """
        This method pushes the given instruction `inst` to the call frame on the top of the call
        stack. When `inst` is a call instruction, `call_params` may indicate the set of parameters
        (indices) that the slicer followed before reaching `inst`, or an empty set if it followed
        the call's return value.
        """
        if self._call_stack:
            curr_call_frame = self._call_stack[-1]
            # Update instruction stack
            curr_call_frame.inst_stack.append(inst)
            # Update instruction graph
            if len(curr_call_frame.inst_stack) >= 2:
                prev_inst = curr_call_frame.inst_stack[-2]
                curr_call_frame.inst_graph.add_edge(prev_inst, inst)
                # If any, store call parameters as edge attribute
                if call_params:
                    curr_call_frame.inst_graph.edges[prev_inst, inst]["call_params"] = (
                        call_params
                    )
            else:
                curr_call_frame.inst_graph.add_node(inst)
        return

    def pop_inst(self) -> bn.MediumLevelILInstruction | None:
        """
        This method pops an instruction from the call frame on the top of the call stack.
        """
        if self._call_stack:
            call_frame = self._call_stack[-1]
            call_frame.last_inst = call_frame.inst_stack.pop()
            return call_frame.last_inst
        return None

    def push_mem_def_inst(self, inst: bn.MediumLevelILInstruction) -> None:
        """
        This method pushes the given instruction `inst` to the memory definition instructions of
        the call frame on the top of the call stack.
        """
        if self._call_stack and inst not in self._call_stack[-1].mem_def_insts:
            self._call_stack[-1].mem_def_insts.append(inst)
        return

    def add_func_param(self, param_idx: int) -> None:
        """
        This method adds the given parameter to the `func_params` set of the current call frame.
        `func_params` is the set of parameters that should be sliced when returning back to the
        caller of the current function.
        """
        if self._call_stack:
            self._call_stack[-1].func_params.add(param_idx)
        return

    def print_call_stack(self) -> None:
        """
        This method prints the call stack (for debugging).
        """
        for call_frame in self._call_stack:
            print(str(call_frame))
        return

    def print_call_graph(self) -> None:
        """
        This method prints the call graph (for debugging).
        """
        for caller, callee, attrs in self._call_graph.edges(data=True):
            caller_level = self._call_graph.nodes[caller].get("level", 0)
            callee_level = self._call_graph.nodes[callee].get("level", 0)
            caller_info = FunctionHelper.get_func_info(caller, False)
            callee_info = FunctionHelper.get_func_info(callee, False)
            if attrs["downwards"]:
                if attrs["param_idx"] > 0:
                    follow = f"Followed out_param {attrs['param_idx']:d} downwards"
                else:
                    follow = "Followed all possible returns downwards"
            else:
                if attrs["param_idx"] > 0:
                    follow = f"Followed param {attrs['param_idx']:d} upwards"
                else:
                    follow = "Followed all possible params upwards"
            print(
                f"[{caller_level:+d}] {caller_info} -- '{follow:s}' -> [{callee_level:+d}] {callee_info}"
            )
        return

    def print_inst_slice(self) -> None:
        """
        This method prints the instruction slice (for debugging).
        """
        for call_level, call_frame in enumerate(self._call_stack):
            print(f"[{call_level:d}] {str(call_frame):s}")
            for inst in call_frame.inst_stack:
                inst_info = InstructionHelper.get_inst_info(inst, False)
                print(f"  - {inst_info:s}")
        return

    def print_inst_graph(self) -> None:
        """
        This method prints the instruction graph (for debugging).
        """
        for (from_call_inst, from_inst), (
            to_call_inst,
            to_inst,
        ) in self._inst_graph.edges():
            from_call_inst_info = (
                InstructionHelper.get_inst_info(from_call_inst, False)
                if from_call_inst
                else ""
            )
            from_inst_info = (
                InstructionHelper.get_inst_info(from_inst, False) if from_inst else ""
            )
            to_call_inst_info = (
                InstructionHelper.get_inst_info(to_call_inst, False)
                if to_call_inst
                else ""
            )
            to_inst_info = (
                InstructionHelper.get_inst_info(to_inst, False) if to_inst else ""
            )
            print(
                f"('{from_call_inst_info:s}', '{from_inst_info:s}') -> ('{to_call_inst_info:s}', '{to_inst_info:s}')"
            )
        return
