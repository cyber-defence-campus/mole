import binaryninja  as bn
from   typing       import List
from   .lib         import function
from   ..common.log import Logger


class memcpy(function):
    """
    This class implements analysis testcases for `libc` function `memcpy`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.memcpy",
            log: Logger = Logger(),
            src_sym_names: List[str] = []
        ) -> None:
        super().__init__(
            bv, tag, log,
            synopsis="void* memcpy(void* dest, const void* src, size_t n)",
            par_cnt=lambda x: x == 3,
            par_dataflow=lambda x: x==2,
            src_sym_names=src_sym_names,
            snk_sym_names=["memcpy", "__builtin_memcpy"]
        )
        return
    

class sscanf(function):
    """
    This class implements analysis testcases for `libc` function `sscanf`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.sscanf",
            log: Logger = Logger(),
            src_sym_names: List[str] = []
        ) -> None:
        super().__init__(
            bv, tag, log,
            synopsis="int sscanf(const char* str, const char* format, ...)",
            par_cnt=lambda x: x >= 2,
            par_dataflow=lambda x: False,
            src_sym_names=src_sym_names,
            snk_sym_names=["sscanf", "__builtin_sscanf"]
        )
        return