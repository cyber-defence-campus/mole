from __future__   import annotations
from typing       import List
from ..common.log import Logger
from ..model.lib  import category, src_func


class apr_socket_recv(src_func):
    """
    This class represents a source for `libapr` function `apr_socket_recv`.
    """

    def __init__(
            self,
            name: str = "libapr.apr_socket_recv",
            synopsis: str = "apr_status_t apr_socket_recv(apr_socket_t* sock, char* buf, apr_size_t* len)",
            description: str = "Read bytes from socket",
            category: category = category.net,
            symbols: List[str] = ["apr_socket_recv"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 1
        )
        return