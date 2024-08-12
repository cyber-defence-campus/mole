import binaryninja     as bn
from   typing          import Callable, List, Tuple
from   ..common.helper import SymbolHelper
from   ..common.log    import Logger
from   ..model.slice   import MediumLevelILBackwardSlicer


class func:
    """
    This class implements a function.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.func",
            log: Logger = Logger(),
            sym_names: List[str] = []
        ) -> None:
        self._bv = bv
        self._tag = tag
        self._log = log
        self._sym_names = sym_names
        return

    
class src_func(func):
    """
    This class implements a source function.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.src_func",
            log: Logger = Logger(),
            sym_names: List[str] = [],
            par_cnt: Callable[[int], bool] = lambda x: x >= 0,
            par_dataflow: Callable[[int], bool] = lambda x: False,
            par_slice: Callable[[int], bool] = lambda x: False
        ) -> None:
        super().__init__(bv, tag, log, sym_names)
        self._target_insts = {}
        code_refs = SymbolHelper.get_code_refs(self._bv, self._sym_names)
        for symbol_name, insts in code_refs.items():
            for inst in insts:
                self._log.info(self._tag, f"Analyze source function '0x{inst.address:x} {symbol_name:s}'")
                # Ignore invalid calls
                if (inst.operation != bn.MediumLevelILOperation.MLIL_CALL_SSA and
                    inst.operation != bn.MediumLevelILOperation.MLIL_TAILCALL_SSA):
                    self._log.warn(self._tag, f"0x{inst.address:x} Ignore call '0x{inst.address:x} {symbol_name:s}' due to invalid call instruction")
                    continue
                # Add call to target instructions
                s = self._target_insts.get((inst.address, symbol_name), set())
                s.add(inst)
                self._target_insts[(inst.address, symbol_name)] = s
                # Ignore calls with an invalid number of parameters
                if not par_cnt(len(inst.params)):
                    self._log.warn(self._tag, f"0x{inst.address:x} Ignore arguments of call '0x{inst.address:x} {symbol_name:s}' due to an unexpected amount")
                    continue
                # Analyze parameters
                for parm_num, parm_var in enumerate(inst.params):
                    self._log.debug(self._tag, f"Analyze argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                    # Perform dataflow analysis
                    if par_dataflow(parm_num):
                        # Ignore constant parameters
                        if parm_var.operation != bn.MediumLevelILOperation.MLIL_VAR_SSA:
                            self._log.debug(self._tag, f"0x{inst.address:x} Ignore constant argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                            continue
                        # Ignore parameters that can be determined with dataflow analysis
                        possible_sizes = parm_var.possible_values
                        if possible_sizes.type != bn.RegisterValueType.UndeterminedValue:
                            self._log.debug(self._tag, f"0x{inst.address:x} Ignore dataflow determined argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                            continue
                    # Backward slice the parameter
                    if par_slice(parm_num):
                        slicer = MediumLevelILBackwardSlicer(self._bv, self._tag, self._log)
                        slicer.slice_backwards(parm_var)
                        # Add sliced instructions to target instructions
                        s = self._target_insts.get((inst.address, symbol_name), set())
                        s.update(slicer._sliced_insts)
                        self._target_insts[(inst.address, symbol_name)] = s
        return


class snk_func(func):
    """
    This class implements a sink function.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.snk_func",
            log: Logger = Logger(),
            sym_names: List[str] = [],
            par_cnt: Callable[[int], bool] = lambda x: x >= 0,
            par_dataflow: Callable[[int], bool] = lambda x: False,
            par_slice: Callable[[int], bool] = lambda x: True
        ) -> None:
        super().__init__(bv, tag, log, sym_names)
        self._par_cnt = par_cnt
        self._par_dataflow = par_dataflow
        self._par_slice = par_slice
        return
    
    def find(
            self,
            sources: List[src_func] = [],
            max_recursion = 10
        ) -> List[Tuple[
                str, bn.MediumLevelILInstruction,
                str, bn.MediumLevelILInstruction, int, bn.SSAVariable
            ]]:
        """
        This method tries to find paths, starting from the current sink and ending in one of the
        given `sources`, using static backward slicing.
        """
        paths = []
        code_refs = SymbolHelper.get_code_refs(self._bv, self._sym_names)
        for snk_name, snk_insts in code_refs.items():
            for snk_inst in snk_insts:
                self._log.info(self._tag, f"Analyze sink function '0x{snk_inst.address:x} {snk_name:s}'")
                # Ignore invalid calls
                if (snk_inst.operation != bn.MediumLevelILOperation.MLIL_CALL_SSA and
                    snk_inst.operation != bn.MediumLevelILOperation.MLIL_TAILCALL_SSA):
                    self._log.warn(self._tag, f"0x{snk_inst.address:x} Ignore call '0x{snk_inst.address:x} {snk_name:s}' due to invalid call instruction")
                    continue
                # Ignore calls with an invalid number of parameters
                if not self._par_cnt(len(snk_inst.params)):
                    self._log.warn(self._tag, f"0x{snk_inst.address:x} Ignore call '0x{snk_inst.address:x} {snk_name:s}' due to invalid number of arguments")
                    continue
                # Analyze parameters
                for parm_num, parm_var in enumerate(snk_inst.params):
                    self._log.debug(self._tag, f"Analyze argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                    # Perform dataflow analysis
                    if self._par_dataflow(parm_num):
                        # Ignore constant parameters
                        if parm_var.operation != bn.MediumLevelILOperation.MLIL_VAR_SSA:
                            self._log.debug(self._tag, f"0x{snk_inst.address:x} Ignore constant argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                            continue
                        # Ignore parameters that can be determined with dataflow analysis
                        possible_sizes = parm_var.possible_values
                        if possible_sizes.type != bn.RegisterValueType.UndeterminedValue:
                            self._log.debug(self._tag, f"0x{snk_inst.address:x} Ignore dataflow determined argument 'arg#{parm_num+1:d}:{str(parm_var):s}'")
                            continue
                    # Backward slice the parameter
                    if self._par_slice(parm_num):
                        slicer = MediumLevelILBackwardSlicer(self._bv, self._tag, self._log, max_recursion)
                        try:
                            slicer.slice_backwards(parm_var)
                        except Exception as e:
                            self._log.error(self._tag, f"Exception: {str(e):s}")
                        # Check whether the slice contains any source
                        for source in sources:
                            for (sym_addr, sym_name), src_insts in source._target_insts.items():
                                for src_inst in src_insts:
                                    if slicer.includes(src_inst):
                                        t_src = f"0x{sym_addr:x} {sym_name:s}()"
                                        t_snk = f"0x{snk_inst.address:x} {snk_name}"
                                        t_snk = f"{t_snk:s}(arg#{parm_num+1:d}:{str(parm_var):s})"
                                        self._log.info(
                                            self._tag,
                                            f"Interesting path: {t_src:s} --> {t_snk:s}!"
                                        )
                                        paths.append((sym_name, src_inst, snk_name, snk_inst, parm_num, parm_var))
        return paths