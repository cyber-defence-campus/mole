import binaryninja   as bn
from   typing        import List
from   .lib          import src_func
from   ..common.log  import Logger


class apr_socket_recv(src_func):
    """
    This class implements a source for `libapr` function `apr_socket_recv`.
    """

    def __init__(
            self,
            bv: bn.BinaryView,
            tag: str = "libapr.apr_socket_recv",
            log: Logger = Logger(),
            sym_names: List[str] = ["apr_socket_recv"]
        ) -> None:
        super().__init__(
            bv, tag, log, sym_names,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 1
        )
        return