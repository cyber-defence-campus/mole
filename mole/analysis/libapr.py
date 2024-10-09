from __future__     import annotations
from typing         import List
from .lib           import category, src_func
from ..common.log   import Logger
import binaryninja as bn


class apr_socket_recv(src_func):
    """
    This class represents a source for `libapr` function `apr_socket_recv`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            name: str = "libapr.apr_socket_recv",
            description: str = "Read bytes from socket",
            category: category = category.net,
            symbols: List[str] = ["apr_socket_recv"],
            enabled: bool = False,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            bv, name, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 1
        )
        return