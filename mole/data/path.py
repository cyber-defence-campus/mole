from __future__ import annotations
from dataclasses import dataclass, field
from mole.common.helper.instruction import InstructionHelper
from mole.common.log import Logger
from mole.core.graph import MediumLevelILFunctionGraph
from mole.models.ai import AiVulnerabilityReport
from typing import Dict, List, Tuple, Type
import binaryninja as bn


tag = "Path"


@dataclass
class Path:
    """
    This class is a representation of the data associated with identified paths.
    """

    src_sym_addr: int
    src_sym_name: str
    src_par_idx: int | None
    src_par_var: bn.MediumLevelILInstruction | None
    src_inst_idx: int
    snk_sym_addr: int
    snk_sym_name: str
    snk_par_idx: int
    snk_par_var: bn.MediumLevelILInstruction
    insts: List[bn.MediumLevelILInstruction]
    comment: str = ""
    sha1_hash: str = ""
    phiis: List[bn.MediumLevelILInstruction] = field(default_factory=list)
    bdeps: Dict[int, bn.ILBranchDependence] = field(default_factory=dict)
    calls: List[Tuple[bn.MediumLevelILFunction, int]] = field(default_factory=list)
    call_graph: MediumLevelILFunctionGraph = MediumLevelILFunctionGraph()
    ai_report: AiVulnerabilityReport | None = None

    def __init__(
        self,
        src_sym_addr: int,
        src_sym_name: str,
        src_par_idx: int | None,
        src_par_var: bn.MediumLevelILInstruction | None,
        src_inst_idx: int,
        snk_sym_addr: int,
        snk_sym_name: str,
        snk_par_idx: int,
        snk_par_var: bn.MediumLevelILInstruction,
        insts: List[bn.MediumLevelILInstruction],
        comment: str = "",
        sha1_hash: str = "",
        ai_report: AiVulnerabilityReport | None = None,
    ) -> None:
        self.src_sym_addr = src_sym_addr
        self.src_sym_name = src_sym_name
        self.src_par_idx = src_par_idx
        self.src_par_var = src_par_var
        self.src_inst_idx = src_inst_idx
        self.snk_sym_addr = snk_sym_addr
        self.snk_sym_name = snk_sym_name
        self.snk_par_idx = snk_par_idx
        self.snk_par_var = snk_par_var
        self.insts = insts
        self.comment = comment
        self.sha1_hash = sha1_hash
        self.phiis = []
        self.bdeps = {}
        self.calls = []
        self.call_graph = MediumLevelILFunctionGraph()
        self.ai_report = ai_report
        return

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Path):
            return False
        return (
            # Equal source
            self.src_sym_addr == other.src_sym_addr
            and self.src_sym_name == other.src_sym_name
            and (
                self.src_par_idx is None
                or other.src_par_idx is None
                or self.src_par_idx == other.src_par_idx
            )
            and (
                self.src_par_var is None
                or other.src_par_var is None
                or self.src_par_var == other.src_par_var
            )
            # Equal sink
            and self.snk_sym_addr == other.snk_sym_addr
            and self.snk_sym_name == other.snk_sym_name
            and self.snk_par_idx == other.snk_par_idx
            and self.snk_par_var == other.snk_par_var
            # Equal instructions (ignoring the ones originating from slicing the
            # source, only considering the source's call instruction)
            and self.src_inst_idx == other.src_inst_idx
            and self.insts[: self.src_inst_idx - 1]
            == other.insts[: self.src_inst_idx - 1]
            and self.insts[-1] == other.insts[-1]
            # Equal binary
            and self.sha1_hash == other.sha1_hash
        )

    def __str__(self) -> str:
        src = f"0x{self.src_sym_addr:x} {self.src_sym_name:s}"
        if self.src_par_idx and self.src_par_var:
            src = f"{src:s}(arg#{self.src_par_idx:d}:{str(self.src_par_var):s})"
        else:
            src = f"{src:s}"
        snk = f"0x{self.snk_sym_addr:x} {self.snk_sym_name:s}"
        snk = f"{snk:s}(arg#{self.snk_par_idx:d}:{str(self.snk_par_var):s})"
        return f"{snk:s} <-- {src:s}"

    def init(self, call_graph: MediumLevelILFunctionGraph) -> None:
        # Create call graph
        self.call_graph = call_graph.copy()
        # Iterate instructions in path
        old_func = None
        prv_inst = None
        for inst in self.insts:
            # Mark instruction's function being in the path
            func = inst.function
            self.call_graph.nodes[func]["in_path"] = True
            # Path goes upwards
            if self.call_graph.has_edge(func, old_func):
                self.call_graph[func][old_func]["in_path"] = True
                self.call_graph[func][old_func]["call_site"] = inst.address
            # Path goes downwards
            if self.call_graph.has_edge(old_func, func):
                self.call_graph[old_func][func]["in_path"] = True
                self.call_graph[old_func][func]["call_site"] = prv_inst.address
            # Phi-instructions
            if isinstance(inst, bn.MediumLevelILVarPhi):
                self.phiis.append(inst)
            # Branch dependencies
            for bch_idx, bch_dep in inst.branch_dependence.items():
                self.bdeps.setdefault(bch_idx, bch_dep)
            # Function in path changes
            if old_func != func:
                self.calls.append((func, 0))
                old_func = func
            prv_inst = inst
        # Add `src` node attribute
        src_func = self.insts[-1].function
        if src_func in self.call_graph:
            src_info = f"src: {self.src_sym_name:s}"
            if self.src_par_var:
                src_info = f"{src_info:s} | {str(self.src_par_var):s}"
            self.call_graph.nodes[src_func]["src"] = src_info
        # Add `snk` node attribute
        snk_func = self.insts[0].function
        if snk_func in self.call_graph:
            snk_info = f"snk: {self.snk_sym_name:s} | {str(self.snk_par_var):s}"
            self.call_graph.nodes[snk_func]["snk"] = snk_info
        # Calculate call levels
        self.call_graph.update_call_levels()
        # Update call levels
        for i, call in enumerate(self.calls):
            call_func = call[0]
            call_level = self.call_graph.nodes[call_func].get("level", 0)
            self.calls[i] = (call_func, call_level)
        return

    def update(self) -> Path:
        """
        This method updates the symbol names of the source and sink functions.
        """
        # Ensure path has instructions
        if not self.insts:
            return self
        # Update source function's symbol name
        src_inst = self.insts[-1]
        if isinstance(
            src_inst,
            bn.MediumLevelILCall
            | bn.MediumLevelILCallSsa
            | bn.MediumLevelILTailcall
            | bn.MediumLevelILTailcallSsa,
        ):
            src_sym_name, _ = InstructionHelper.get_func_signature(src_inst)
            if src_sym_name:
                self.src_sym_name = src_sym_name
        # Update sink function's symbol name
        snk_inst = self.insts[0]
        if isinstance(
            snk_inst,
            bn.MediumLevelILCall
            | bn.MediumLevelILCallSsa
            | bn.MediumLevelILTailcall
            | bn.MediumLevelILTailcallSsa,
        ):
            snk_sym_name, _ = InstructionHelper.get_func_signature(snk_inst)
            if snk_sym_name:
                self.snk_sym_name = snk_sym_name
        return self

    def to_dict(self) -> Dict:
        # Serialize instructions
        insts: List[Dict[str, str]] = []
        for inst in self.insts:
            inst_dict = {
                "fun_addr": hex(inst.function.source_function.start),
                "expr_idx": hex(inst.expr_index),
                "inst": InstructionHelper.get_inst_info(inst, True),
            }
            insts.append(inst_dict)
        return {
            "src_sym_addr": hex(self.src_sym_addr),
            "src_sym_name": self.src_sym_name,
            "src_par_idx": self.src_par_idx,
            "src_inst_idx": self.src_inst_idx,
            "snk_sym_addr": hex(self.snk_sym_addr),
            "snk_sym_name": self.snk_sym_name,
            "snk_par_idx": self.snk_par_idx,
            "insts": insts,
            "call_graph": self.call_graph.to_dict(),
            "comment": self.comment,
            "sha1_hash": self.sha1_hash,
            "ai_report": self.ai_report.to_dict() if self.ai_report else None,
        }

    @classmethod
    def from_dict(cls: Type[Path], bv: bn.BinaryView, d: Dict) -> Path | None:
        log = Logger(bv)
        try:
            # Deserialize instructions
            insts: List[bn.MediumLevelILInstruction] = []
            for inst_dict in d["insts"]:
                inst_dict = inst_dict  # type: Dict[str, str]
                fun_addr = int(inst_dict["fun_addr"], 0)
                expr_idx = int(inst_dict["expr_idx"], 0)
                func = bv.get_function_at(fun_addr)
                inst = func.mlil.ssa_form.get_expr(expr_idx)
                inst_info = InstructionHelper.get_inst_info(inst, True)
                if inst_info != inst_dict["inst"]:
                    log.warn(tag, "Instruction mismatch:")
                    log.warn(tag, f"- Expected: {inst_dict['inst']:s}")
                    log.warn(tag, f"- Found   : {inst_info:s}")
                insts.append(inst)
            # Deserialize parameter variables
            src_par_idx = d["src_par_idx"]
            if src_par_idx is not None and src_par_idx > 0:
                inst: bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa = insts[-1]
                src_par_var = inst.params[src_par_idx - 1]
            else:
                src_par_var = None
            snk_par_idx = d["snk_par_idx"]
            if snk_par_idx is not None and snk_par_idx > 0:
                inst: bn.MediumLevelILCallSsa | bn.MediumLevelILTailcallSsa = insts[0]
                snk_par_var = inst.params[snk_par_idx - 1]
            else:
                snk_par_var = None
            # Deserialize path
            path: Path = cls(
                src_sym_addr=int(d["src_sym_addr"], 0),
                src_sym_name=d["src_sym_name"],
                src_par_idx=src_par_idx,
                src_par_var=src_par_var,
                src_inst_idx=d["src_inst_idx"],
                snk_sym_addr=int(d["snk_sym_addr"], 0),
                snk_sym_name=d["snk_sym_name"],
                snk_par_idx=snk_par_idx,
                snk_par_var=snk_par_var,
                insts=insts,
                comment=d["comment"],
                sha1_hash=d["sha1_hash"],
                ai_report=AiVulnerabilityReport(**d["ai_report"])
                if d["ai_report"]
                else None,
            )
            path.init(MediumLevelILFunctionGraph.from_dict(bv, d["call_graph"]))
            return path
        except Exception as e:
            src_sym_addr_str = str(d.get("src_sym_addr", "unknown"))
            src_sym_name_str = str(d.get("src_sym_name", "unknown"))
            snk_sym_addr_str = str(d.get("snk_sym_addr", "unknown"))
            snk_sym_name_str = str(d.get("snk_sym_name", "unknown"))
            log.error(tag, f"Failed to deserialize path: {str(e):s}")
            log.error(tag, f"- Source: {src_sym_addr_str:s} {src_sym_name_str:s}")
            log.error(tag, f"- Sink  : {snk_sym_addr_str:s} {snk_sym_name_str:s}")
        return None
