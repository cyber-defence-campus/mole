import binaryninja     as bn
from   typing          import List
from   .lib            import snk_func, src_func
from   ..common.log    import Logger


class fgets(src_func):
    """
    This class implements a source for `libc` function `fgets`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.fgets",
            log: Logger = Logger(),
            sym_names: List[str] = ["fgets", "__builtin_fgets"]
        ) -> None:
        super().__init__(
            bv, tag, log, sym_names,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 0
        )
        return
    

class getenv(src_func):
    """
    This class implements a source for `libc` function `getenv`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.getenv",
            log: Logger = Logger(),
            sym_names: List[str] = ["getenv", "__builtin_getenv"]
        ) -> None:
        super().__init__(
            bv, tag, log, sym_names,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        return


class memcpy(snk_func):
    """
    This class implements a sink for `libc` function `memcpy`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.memcpy",
            log: Logger = Logger(),
            sym_names: List[str] = ["memcpy", "__builtin_memcpy"]
        ) -> None:
        super().__init__(
            bv, tag, log, sym_names,
            par_cnt = lambda x: x == 3,
            # par_dataflow = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        return


class sscanf(snk_func):
    """
    This class implements a sink for `libc` function `sscanf`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.sscanf",
            log: Logger = Logger(),
            sym_names: List[str] = ["sscanf", "__builtin_sscanf"]
        ) -> None:
        super().__init__(
            bv, tag, log, sym_names,
            par_cnt = lambda x: x >= 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x < 2
        )
        return
    
class vsscanf(sscanf):
    """
    This class implements a sink for `libc` function `vsscanf`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.vsscanf",
            log: Logger = Logger(),
            sym_names: List[str] = ["vsscanf", "__builtin_vsscanf"]
        ) -> None:
        super().__init__(bv, tag, log, sym_names)
        return