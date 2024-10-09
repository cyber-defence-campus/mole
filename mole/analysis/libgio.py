from __future__     import annotations
from typing         import List
from .lib           import category, src_func
from ..common.log   import Logger
import binaryninja as bn


class g_socket_receive(src_func):
    """
    This class represents a source for `libgio` function `g_socket_receive`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            name: str = "libgio.g_socket_receive",
            description: str = "Read bytes from socket",
            category: category = category.net,
            symbols: List[str] = ["g_socket_receive"],
            enabled: bool = False,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            bv, name, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 5,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 1
        )
        return