import binaryninja   as bn
from   typing        import List
from   .lib          import src_func
from   ..common.log  import Logger


class g_socket_receive(src_func):
    """
    This class implements a source for `libgio` function `g_socket_receive`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libgio.g_socket_receive",
            log: Logger = Logger(),
            sym_names: List[str] = ["g_socket_receive"]
        ) -> None:
        super().__init__(
            bv, tag, log, sym_names,
            par_cnt = lambda x: x == 5,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 1
        )
        return