from __future__   import annotations
from typing       import List
from ..common.log import Logger
from ..model.lib  import category, src_func, snk_func


class getenv(src_func):
    """
    This class represents a source for `libc` function `getenv`.
    """

    def __init__(
            self,
            name: str = "libc.getenv",
            description: str = "Read environment variable",
            category: category = category.env,
            symbols: List[str] = ["getenv", "__builtin_getenv"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        return
    

class gets(src_func, snk_func):
    """
    This class represents a source and sink for `libc` function `gets`.
    """

    def __init__(
            self,
            name: str = "libc.gets",
            description: str = "Read string from standard input stream",
            category: category = category.sfd,
            symbols: List[str] = ["gets", "__builtin_gets"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        src_func.__init__(
            self,
            name, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        snk_func.__init__(
            self,
            name, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        return


class fgets(src_func):
    """
    This class represents a source for `libc` function `fgets`.
    """

    def __init__(
            self,
            name: str = "libc.fgets",
            description: str = "Read string from given stream",
            category: category = category.sfd,
            symbols: List[str] = ["fgets", "__builtin_fgets"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 0
        )
        return


class memcpy(snk_func):
    """
    This class represents a sink for `libc` function `memcpy`.
    """

    def __init__(
            self,
            name: str = "libc.memcpy",
            description: str = "Copy memory area",
            category: category = category.mem,
            symbols: List[str] = ["memcpy", "__builtin_memcpy"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        return
    

class memmove(memcpy):
    """
    This class represents a sink for `libc` function `memmove`.
    """
    
    def __init__(
            self,
            name: str = "libc.memmove",
            description: str = "Copy memory area",
            category: category = category.mem,
            symbols: List[str] = ["memmove", "__builtin_memmove"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, description, category, symbols, enabled, log
        )
        return


class strcpy(snk_func):
    """
    This class represents a sink for `libc` function `strcpy`.
    """

    def __init__(
            self,
            name: str = "libc.strcpy",
            description: str = "Copy a string",
            category: category = category.str,
            symbols: List[str] = ["strcpy", "__builtin_strcpy", "stpcpy", "__builtin_stpcpy"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        return
    
class wcscpy(strcpy):
    """
    This class represents a sink for `libc` function `wcscpy`.
    """

    def __init__(
            self,
            name: str = "libc.wcscpy",
            description: str = "Copy a string",
            category: category = category.str,
            symbols: List[str] = ["wcscpy", "__builtin_wcscpy"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, description, category, symbols, enabled, log
        )
        return
    

class strcat(strcpy):
    """
    This class represents a sink for `libc` function `strcpy`.
    """

    def __init__(
            self,
            name: str = "libc.strcat",
            description: str = "Catenate a string",
            category: category = category.str,
            symbols: List[str] = ["strcat", "__builtin_strcat"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, description, category, symbols, enabled, log
        )
        return
    

class strncpy(snk_func):
    """
    This class represents a sink for `libc` function `strncpy`.
    """

    def __init__(
            self,
            name: str = "libc.strncpy",
            description: str = "Fill buffer with bytes from string",
            category: category = category.str,
            symbols: List[str] = ["strncpy", "__builtin_strncpy"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        return


class sscanf(snk_func):
    """
    This class represents a sink for `libc` function `sscanf`.
    """

    def __init__(
            self,
            name: str = "libc.sscanf",
            description: str = "Input string format conversion",
            category: category = category.str,
            symbols: List[str] = ["sscanf", "__builtin_sscanf", "__isoc99_sscanf", "__isoc23_sscanf"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, description, category, symbols, enabled, log,
            par_cnt = lambda x: x >= 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x < 2
        )
        return


class vsscanf(sscanf):
    """
    This class represents a sink for `libc` function `vsscanf`.
    """

    def __init__(
            self,
            name: str = "libc.vsscanf",
            description: str = "Input string format conversion",
            category: category = category.str,
            symbols: List[str] = ["vsscanf", "__builtin_vsscanf", "__isoc99_vsscanf"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, description, category, symbols, enabled, log
        )
        return