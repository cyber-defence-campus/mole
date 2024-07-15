import binaryninja     as bn
from   .lib            import snk_func, src_func
from   ..common.log    import Logger


class fgets(src_func):
    """
    This class implements a source for `libc` function `fgets`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            bv, "libc.fgets", log, ["fgets", "__builtin_fgets"],
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
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            bv, "libc.getenv", log, ["getenv", "__builtin_getenv"],
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
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            bv, "libc.memcpy", log, ["memcpy", "__builtin_memcpy"],
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: x == 2,
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
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            bv, "libc.sscanf", log, ["sscanf", "__builtin_sscanf"],
            par_cnt = lambda x: x >= 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        return