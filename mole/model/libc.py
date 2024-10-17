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
            synopsis: str = "char* getenv(const char* name)",
            description: str = "Read environment variable",
            category: category = category.env,
            symbols: List[str] = [
                "getenv", "__builtin_getenv",
                "secure_getenv", "__builtin_secure_getenv"
            ],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False
        )
        return
    

class fgetc(src_func):
    """
    This class represents a source for `libc` function `fgetc`.
    """

    def __init__(
            self,
            name: str = "libc.fgetc",
            synopsis: str = "int fgetc(FILE* stream)",
            description: str = "Read character from given stream",
            category: category = category.sfd,
            symbols: List[str] = ["fgetc", "__builtin_fgetc"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False
        )
        return
    
class getc(src_func):
    """
    This class represents a source for `libc` function `getc`.
    """

    def __init__(
            self,
            name: str = "libc.getc",
            synopsis: str = "int getc(FILE* stream)",
            description: str = "Read character from given stream",
            category: category = category.sfd,
            symbols: List[str] = ["getc", "__builtin_getc"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False
        )
        return
    

class getchar(src_func):
    """
    This class represents a source for `libc` function `getchar`.
    """

    def __init__(
            self,
            name: str = "libc.getchar",
            synopsis: str = "int getchar(void)",
            description: str = "Read character from standard input stream",
            category: category = category.sfd,
            symbols: List[str] = ["getchar", "__builtin_getchar"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 0,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False
        )
        return
    

class fgets(src_func):
    """
    This class represents a source for `libc` function `fgets`.
    """

    def __init__(
            self,
            name: str = "libc.fgets",
            synopsis: str = "char* fgets(char* s, int size, FILE* stream)",
            description: str = "Read string from given stream",
            category: category = category.sfd,
            symbols: List[str] = ["fgets", "__builtin_fgets"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 0
        )
        return


class gets(src_func, snk_func):
    """
    This class represents a source and sink for `libc` function `gets`.
    """

    def __init__(
            self,
            name: str = "libc.gets",
            synopsis: str = "char* gets(char* s)",
            description: str = "Read string from standard input stream",
            category: category = category.sfd,
            symbols: List[str] = ["gets", "__builtin_gets"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        src_func.__init__(
            self,
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        snk_func.__init__(
            self,
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        return
    
    
class scanf(src_func):
    """
    This class represents a source for `libc` function `scanf`.
    """

    def __init__(
            self,
            name: str = "libc.scanf",
            synopsis: str = "int scanf(const char* format, ...)",
            description: str = "Read formatted input from standard input stream",
            category: category = category.sfd,
            symbols: List[str] = ["scanf", "__builtin_scanf"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x >= 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x > 0
        )
        return
    

class vscanf(src_func):
    """
    This class represents a source for `libc` function `vscanf`.
    """

    def __init__(
            self,
            name: str = "libc.vscanf",
            synopsis: str = "int vscanf(const char* format, va_list ap)",
            description: str = "Read formatted input from standard input stream",
            category: category = category.sfd,
            symbols: List[str] = ["vscanf", "__builtin_vscanf"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x > 0
        )
        return
    

class fscanf(src_func):
    """
    This class represents a source for `libc` function `fscanf`.
    """

    def __init__(
            self,
            name: str = "libc.fscanf",
            synopsis: str = "int fscanf(FILE* stream, const char* format, ...)",
            description: str = "Read formatted input from given stream",
            category: category = category.sfd,
            symbols: List[str] = ["fscanf", "__builtin_fscanf"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x >= 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x > 1
        )
        return
    

class vfscanf(src_func):
    """
    This class represents a source for `libc` function `vfscanf`.
    """

    def __init__(
            self,
            name: str = "libc.vfscanf",
            synopsis: str = "int vfscanf(FILE* stream, const char* format, va_list ap)",
            description: str = "Read formatted input from given stream",
            category: category = category.sfd,
            symbols: List[str] = ["vfscanf", "__builtin_vfscanf"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x > 1
        )
        return


class fopen(src_func):
    """
    This class represents a source for `libc` function `fopen`.
    """

    def __init__(
            self,
            name: str = "libc.fopen",
            synopsis: str = "FILE* fopen(const char* pathname, const char* mode)",
            description: str = "Open file",
            category: category = category.sfd,
            symbols: List[str] = ["fopen", "__builtin_fopen"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False
        )
        return


class fdopen(src_func):
    """
    This class represents a source for `libc` function `fdopen`.
    """

    def __init__(
            self,
            name: str = "libc.fdopen",
            synopsis: str = "FILE* fdopen(int fd, const char* mode)",
            description: str = "Open file",
            category: category = category.sfd,
            symbols: List[str] = ["fdopen", "__builtin_fdopen"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False
        )
        return
    

class freopen(src_func):
    """
    This class represents a source for `libc` function `freopen`.
    """

    def __init__(
            self,
            name: str = "libc.freopen",
            synopsis: str = "FILE* freopen(const char* pathname, const char* mode, FILE* stream)",
            description: str = "Open file",
            category: category = category.sfd,
            symbols: List[str] = ["freopen", "__builtin_freopen"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False
        )
        return
    

class opendir(src_func):
    """
    This class represents a source for `libc` function `opendir`.
    """

    def __init__(
            self,
            name: str = "libc.opendir",
            synopsis: str = "DIR* opendir(const char* name)",
            description: str = "Open file",
            category: category = category.sfd,
            symbols: List[str] = ["opendir", "__builtin_opendir"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False
        )
        return


class fdopendir(src_func):
    """
    This class represents a source for `libc` function `fdopendir`.
    """

    def __init__(
            self,
            name: str = "libc.fdopendir",
            synopsis: str = "DIR* fdopendir(int fd)",
            description: str = "Open file",
            category: category = category.sfd,
            symbols: List[str] = ["fdopendir", "__builtin_fdopendir"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False
        )
        return


class recv(src_func):
    """
    This class represents a source for `libc` function `recv`.
    """

    def __init__(
            self,
            name: str = "libc.recv",
            synopsis: str = "ssize_t recv(int sockfd, void* buf, size_t len, int flags)",
            description: str = "Receive message from socket",
            category: category = category.net,
            symbols: List[str] = ["recv", "__builtin_recv"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 4,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 1
        )
        return
    

class recvfrom(src_func):
    """
    This class represents a source for `libc` function `recvfrom`.
    """

    def __init__(
            self,
            name: str = "libc.recvfrom",
            synopsis: str = "ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen)",
            description: str = "Receive message from socket",
            category: category = category.net,
            symbols: List[str] = ["recvfrom", "__builtin_recvfrom"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 6,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 1
        )
        return
    

class recvmsg(src_func):
    """
    This class represents a source for `libc` function `recvmsg`.
    """

    def __init__(
            self,
            name: str = "libc.recvmsg",
            synopsis: str = "ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags)",
            description: str = "Receive message from socket",
            category: category = category.net,
            symbols: List[str] = ["recvmsg", "__builtin_recvmsg"],
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
    

class sscanf(snk_func):
    """
    This class represents a sink for `libc` function `sscanf`.
    """

    def __init__(
            self,
            name: str = "libc.sscanf",
            synopsis: str = "int sscanf(const char* str, const char* format, ...)",
            description: str = "Input string format conversion",
            category: category = category.str,
            symbols: List[str] = ["sscanf", "__builtin_sscanf", "__isoc99_sscanf", "__isoc23_sscanf"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
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
            synopsis: str = "int vsscanf(const char* s, const char* format, va_list arg)",
            description: str = "Input string format conversion",
            category: category = category.str,
            symbols: List[str] = ["vsscanf", "__builtin_vsscanf", "__isoc99_vsscanf"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log
        )
        return


class memcpy(snk_func):
    """
    This class represents a sink for `libc` function `memcpy`.
    """

    def __init__(
            self,
            name: str = "libc.memcpy",
            synopsis: str = "void* memcpy(void* dest, const void* src, size_t n)",
            description: str = "Copy memory area",
            category: category = category.mem,
            symbols: List[str] = ["memcpy", "__builtin_memcpy"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
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
            synopsis: str = "void* memmove(void* dest, const void* src, size_t n)",
            description: str = "Copy memory area",
            category: category = category.mem,
            symbols: List[str] = ["memmove", "__builtin_memmove"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log
        )
        return


class strcpy(snk_func):
    """
    This class represents a sink for `libc` function `strcpy`.
    """

    def __init__(
            self,
            name: str = "libc.strcpy",
            synopsis: str = "char* strcpy(char* dst, const char* src)",
            description: str = "Copy a string",
            category: category = category.str,
            symbols: List[str] = ["strcpy", "__builtin_strcpy", "stpcpy", "__builtin_stpcpy"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
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
            synopsis: str = "wchar_t* wcscpy(wchar_t* dest, const wchar_t* src)",
            description: str = "Copy a string",
            category: category = category.str,
            symbols: List[str] = ["wcscpy", "__builtin_wcscpy"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log
        )
        return
    

class strcat(strcpy):
    """
    This class represents a sink for `libc` function `strcpy`.
    """

    def __init__(
            self,
            name: str = "libc.strcat",
            synopsis: str = "char* strcat(char* s1, const char* s2)",
            description: str = "Catenate a string",
            category: category = category.str,
            symbols: List[str] = ["strcat", "__builtin_strcat"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log
        )
        return
    

class strncpy(snk_func):
    """
    This class represents a sink for `libc` function `strncpy`.
    """

    def __init__(
            self,
            name: str = "libc.strncpy",
            synopsis: str = "char* strncpy(char* s1, const char* s2, size_t n)",
            description: str = "Fill buffer with bytes from string",
            category: category = category.str,
            symbols: List[str] = ["strncpy", "__builtin_strncpy"],
            enabled: bool = True,
            log: Logger = Logger()
        ) -> None:
        super().__init__(
            name, synopsis, description, category, symbols, enabled, log,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True
        )
        return