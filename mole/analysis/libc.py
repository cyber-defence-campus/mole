import binaryninja   as bn
from   typing        import List
from   .lib          import src_func, snk_func
from   ..common.log  import Logger


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
    

class gets(src_func, snk_func):
    """
    This class implements a source and sink for `libc` function `gets`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.gets",
            log: Logger = Logger(),
            sym_names: List[str] = ["gets", "__builtin_gets"]
        ) -> None:
        src_func.__init__(
            self,
            bv, tag, log, sym_names,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        snk_func.__init__(
            self,
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
    
class memmove(memcpy):
    """
    This class implements a sink for `libc` function `memmove`.
    """
    
    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.memmove",
            log: Logger = Logger(),
            sym_names: List[str] = ["memmove", "__builtin_memmove"]
        ) -> None:
        super().__init__(bv, tag, log, sym_names)
        return


class strcpy(snk_func):
    """
    This class implements a sink for `libc` function `strcpy`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.strcpy",
            log: Logger = Logger(),
            sym_names: List[str] = ["strcpy", "__builtin_strcpy", "stpcpy", "__builtin_stpcpy"]
        ) -> None:
        super().__init__(
            bv, tag, log, sym_names,
            par_cnt = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        return
    
class strcat(strcpy):
    """
    This class implements a sink for `libc` function `strcat`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.strcat",
            log: Logger = Logger(),
            sym_names: List[str] = ["strcat", "__builtin_strcat"]
        ) -> None:
        super().__init__(bv, tag, log, sym_names)
        return
    
class strncpy(snk_func):
    """
    This class implements a sink for `libc` function `strncpy`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.strncpy",
            log: Logger = Logger(),
            sym_names: List[str] = ["strncpy", "__builtin_strncpy"]
        ) -> None:
        super().__init__(
            bv, tag, log, sym_names,
            par_cnt = lambda x: x == 3,
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
            sym_names: List[str] = ["sscanf", "__builtin_sscanf", "__isoc99_sscanf", "__isoc23_sscanf"]
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
            sym_names: List[str] = ["vsscanf", "__builtin_vsscanf", "__isoc99_vsscanf"]
        ) -> None:
        super().__init__(bv, tag, log, sym_names)
        return
    
class wcscpy(strcpy):
    """
    This class implements a sink for `libc` function `wcscpy`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libc.wcscpy",
            log: Logger = Logger(),
            sym_names: List[str] = ["wcscpy", "__builtin_wcscpy"]
        ) -> None:
        super().__init__(bv, tag, log, sym_names)
        return