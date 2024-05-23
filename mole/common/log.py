from binaryninja  import log_debug, log_info, log_warn, log_error


class Logger:
    """
    Class to print messages to Binary Ninja's log.
    """

    tag = "Plugin.Mole"

    def _tag_msg(tag: str = None, msg: str = None) -> str:
        m = ""
        if tag:
            m = f"[{tag:s}]"
        if msg:
            m = f"{m:s} {msg:s}"
        return m.strip()
    
    @staticmethod
    def debug(tag: str = None, msg: str = None) -> None:
        log_debug(Logger._tag_msg(tag, msg), Logger.tag)
        return
    
    @staticmethod
    def info(tag: str = None, msg: str = None) -> None:
        log_info(Logger._tag_msg(tag, msg), Logger.tag)
        return
    
    @staticmethod
    def warn(tag: str = None, msg: str = None) -> None:
        log_warn(Logger._tag_msg(tag, msg), Logger.tag)
        return
    
    @staticmethod
    def error(tag: str = None, msg: str = None) -> None:
        log_error(Logger._tag_msg(tag, msg), Logger.tag)
        return