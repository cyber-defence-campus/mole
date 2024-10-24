from __future__   import annotations
from ..common.log import Logger
from ..model.lib  import categories, src_func, snk_func


class apr_socket_recv(src_func):
    """
    This class represents a source for `libapr` function `apr_socket_recv`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libapr",
            name = "apr_socket_recv",
            symbols = ["apr_socket_recv"],
            synopsis = "apr_status_t apr_socket_recv(apr_socket_t* sock, char* buf, apr_size_t* len)",
            description = "Read bytes from socket",
            category = categories.net,
            enabled = False,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 1,
            log = log
        )
        return
    

class apr_cpystrn(snk_func):
    """
    This class represents a sink for `libapr` function `apr_cpystrn`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libapr",
            name = "apr_cpystrn",
            symbols = ["apr_cpystrn", "__builtin_apr_cpystrn"],
            synopsis = "char* apr_cpystrn(char* dst, const char* src, apr_size_t dst_size)",
            description = "Fill buffer with bytes from string",
            category = categories.scp,
            enabled = False,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return