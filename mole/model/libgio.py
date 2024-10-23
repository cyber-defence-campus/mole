from __future__   import annotations
from ..common.log import Logger
from ..model.lib  import categories, src_func


class g_socket_receive(src_func):
    """
    This class represents a source for `libgio` function `g_socket_receive`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libgio",
            name = "g_socket_receive",
            symbols = ["g_socket_receive"],
            synopsis = "gssize g_socket_receive(GSocket* socket, gchar* buffer, gsize size, GCancellable* cancellable, GError** error)",
            description = "Read bytes from socket",
            category = categories.net,
            enabled = False,
            par_cnt = lambda x: x == 5,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 1,
            log = log
        )
        return