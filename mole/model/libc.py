from __future__   import annotations
from ..common.log import Logger
from ..model.lib  import categories, src_func, snk_func


class getenv(src_func):
    """
    This class represents a source for `libc` function `getenv`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "getenv",
            symbols = ["getenv", "__builtin_getenv"],
            synopsis = "char* getenv(const char* name)",
            description = "Read environment variable",
            category = categories.env,
            enabled = True,
            par_cnt = lambda x: x==1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return
    

class secure_getenv(src_func):
    """
    This class represents a source for `libc` function `secure_getenv`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "secure_getenv",
            symbols = ["secure_getenv", "__builtin_secure_getenv"],
            synopsis = "char* secure_getenv(const char* name)",
            description = "Read environment variable",
            category = categories.env,
            enabled = True,
            par_cnt = lambda x: x==1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return
    

class fgetc(src_func):
    """
    This class represents a source for `libc` function `fgetc`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fgetc",
            symbols = ["fgetc", "__builtin_fgetc"],
            synopsis = "int fgetc(FILE* stream)",
            description = "Read character from given stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return


class fgetwc(src_func):
    """
    This class represents a source for `libc` function `fgetwc`.
    """
    
    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fgetwc",
            symbols = ["fgetwc", "__builtin_fgetwc"],
            synopsis = "wint_t fgetwc(FILE *stream)",
            description = "Read character from given stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return


class fgetc_unlocked(src_func):
    """
    This class represents a source for `libc` function `fgetc_unlocked`.
    """
    
    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fgetc_unlocked",
            symbols = ["fgetc_unlocked", "__builtin_fgetc_unlocked"],
            synopsis = "int fgetc_unlocked(FILE *stream)",
            description = "Read character from given stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return


class fgetwc_unlocked(src_func):
    """
    This class represents a source for `libc` function `fgetwc_unlocked`.
    """
    
    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fgetwc_unlocked",
            symbols = ["fgetwc_unlocked", "__builtin_fgetwc_unlocked"],
            synopsis = "wint_t fgetwc_unlocked(FILE *stream)",
            description = "Read character from given stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return


class getc(src_func):
    """
    This class represents a source for `libc` function `getc`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "getc",
            symbols = ["getc", "__builtin_getc"],
            synopsis = "int getc(FILE* stream)",
            description = "Read character from given stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return


class getwc(src_func):
    """
    This class represents a source for `libc` function `getwc`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "getwc",
            symbols = ["getwc", "__builtin_getwc"],
            synopsis = "wint_t getc(FILE* stream)",
            description = "Read character from given stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return


class getc_unlocked(src_func):
    """
    This class represents a source for `libc` function `getc_unlocked`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "getc_unlocked",
            symbols = ["getc_unlocked", "__builtin_getc_unlocked"],
            synopsis = "int getc_unlocked(FILE* stream)",
            description = "Read character from given stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return
    

class getwc_unlocked(src_func):
    """
    This class represents a source for `libc` function `getwc_unlocked`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "getwc_unlocked",
            symbols = ["getwc_unlocked", "__builtin_getwc_unlocked"],
            synopsis = "wint_t getwc_unlocked(FILE* stream)",
            description = "Read character from given stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return
    

class getchar(src_func):
    """
    This class represents a source for `libc` function `getchar`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "getchar",
            symbols = ["getchar", "__builtin_getchar"],
            synopsis = "int getchar(void)",
            description = "Read character from standard input stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==0,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return
    

class getwchar(src_func):
    """
    This class represents a source for `libc` function `getwchar`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "getwchar",
            symbols = ["getwchar", "__builtin_getwchar"],
            synopsis = "wint_t getwchar(void)",
            description = "Read character from standard input stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==0,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return
    

class getchar_unlocked(src_func):
    """
    This class represents a source for `libc` function `getchar_unlocked`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "getchar_unlocked",
            symbols = ["getchar_unlocked", "__builtin_getchar_unlocked"],
            synopsis = "int getchar_unlocked(void)",
            description = "Read character from standard input stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==0,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return
    

class getwchar_unlocked(src_func):
    """
    This class represents a source for `libc` function `getwchar_unlocked`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "getwchar_unlocked",
            symbols = ["getwchar_unlocked", "__builtin_getwchar_unlocked"],
            synopsis = "wint_t getwchar_unlocked(void)",
            description = "Read character from standard input stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==0,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return
    

class getw(src_func):
    """
    This class represents a source for `libc` function `getw`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "getw",
            symbols = ["getw", "__builtin_getw"],
            synopsis = "int getw(FILE* stream)",
            description = "Read word from given stream",
            category = categories.chr,
            enabled = True,
            par_cnt = lambda x: x==1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return
    

class getline(src_func):
    """
    This class represents a source for `libc` function `getline`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "getline",
            symbols = ["getline", "__builtin_getline"],
            synopsis = "ssize_t getline(char** lineptr, size_t* n, FILE* stream)",
            description = "Read line from given stream",
            category = categories.lin,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 0,
            log = log
        )
        return


class getdelim(src_func):
    """
    This class represents a source for `libc` function `getdelim`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "getdelim",
            symbols = ["getdelim", "__builtin_getdelim"],
            synopsis = "ssize_t getdelim(char** lineptr, size_t* n, int delimiter, FILE* stream)",
            description = "Read line from given stream",
            category = categories.lin,
            enabled = True,
            par_cnt = lambda x: x == 4,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 0,
            log = log
        )
        return


class fgets(src_func):
    """
    This class represents a source for `libc` function `fgets`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fgets",
            symbols = ["fgets", "__builtin_fgets"],
            synopsis = "char* fgets(char* s, int n, FILE* stream)",
            description = "Read string from given stream",
            category = categories.lin,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 0,
            log = log
        )
        return


class fgetws(src_func):
    """
    This class represents a source for `libc` function `fgetws`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fgetws",
            symbols = ["fgetws", "__builtin_fgetws"],
            synopsis = "wchar_t* fgetws(wchar_t* ws, int n, FILE* stream)",
            description = "Read string from given stream",
            category = categories.lin,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 0,
            log = log
        )
        return


class fgets_unlocked(src_func):
    """
    This class represents a source for `libc` function `fgets_unlocked`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fgets_unlocked",
            symbols = ["fgets_unlocked", "__builtin_fgets_unlocked"],
            synopsis = "char* fgets_unlocked(char* s, int n, FILE* stream)",
            description = "Read string from given stream",
            category = categories.lin,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 0,
            log = log
        )
        return


class fgetws_unlocked(src_func):
    """
    This class represents a source for `libc` function `fgetws_unlocked`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fgetws_unlocked",
            symbols = ["fgetws_unlocked", "__builtin_fgetws_unlocked"],
            synopsis = "wchar_t* fgetws_unlocked(wchar_t* ws, int n, FILE* stream)",
            description = "Read string from given stream",
            category = categories.lin,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 0,
            log = log
        )
        return


class gets(src_func, snk_func):
    """
    This class represents a source and sink for `libc` function `gets`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        lib = "libc"
        name = "gets"
        symbols = ["gets", "__builtin_gets"]
        synopsis = "char* gets(char* s)"
        description = "Read string from standard input stream"
        category = categories.lin
        enabled = True
        par_cnt = lambda x: x == 1
        par_dataflow = lambda x: False
        par_slice = lambda x: True
        src_func.__init__(
            self,
            lib = lib,
            name = name,
            symbols = symbols,
            synopsis = synopsis,
            description = description,
            category = category,
            enabled = enabled,
            par_cnt = par_cnt,
            par_dataflow = par_dataflow,
            par_slice = par_slice,
            log = log
        )
        snk_func.__init__(
            self,
            lib = lib,
            name = name,
            symbols = symbols,
            synopsis = synopsis,
            description = description,
            category = category,
            enabled = enabled,
            par_cnt = par_cnt,
            par_dataflow = par_dataflow,
            par_slice = par_slice,
            log = log
        )
        return
    
    
class scanf(src_func):
    """
    This class represents a source for `libc` function `scanf`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "scanf",
            symbols = ["scanf", "__builtin_scanf", "__isoc99_scanf", "__isoc23_scanf"],
            synopsis = "int scanf(const char* format, ...)",
            description = "Read formatted input from standard input stream",
            category = categories.fmt,
            enabled = True,
            par_cnt = lambda x: x >= 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x >= 1,
            log = log
        )
        return


class wscanf(src_func):
    """
    This class represents a source for `libc` function `wscanf`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "wscanf",
            symbols = ["wscanf", "__builtin_wscanf", "__isoc99_wscanf", "__isoc23_wscanf"],
            synopsis = "int wscanf(const wchar_t* format, ...)",
            description = "Read formatted input from standard input stream",
            category = categories.fmt,
            enabled = True,
            par_cnt = lambda x: x >= 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x >= 1,
            log = log
        )
        return
    

class fscanf(src_func):
    """
    This class represents a source for `libc` function `fscanf`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fscanf",
            symbols = ["fscanf", "__builtin_fscanf", "__isoc99_fscanf", "__isoc23_fscanf"],
            synopsis = "int fscanf(FILE* stream, const char* format, ...)",
            description = "Read formatted input from given stream",
            category = categories.fmt,
            enabled = True,
            par_cnt = lambda x: x >= 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x >= 2,
            log = log
        )
        return


class fwscanf(src_func):
    """
    This class represents a source for `libc` function `fwscanf`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fwscanf",
            symbols = ["fwscanf", "__builtin_fwscanf", "__isco99_fwscanf", "__isoc23_fwscanf"],
            synopsis = "int fwscanf(FILE* stream, const wchar_t* format, ...)",
            description = "Read formatted input from given stream",
            category = categories.fmt,
            enabled = True,
            par_cnt = lambda x: x >= 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x >= 2,
            log = log
        )
        return
    

class vscanf(src_func):
    """
    This class represents a source for `libc` function `vscanf`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "vscanf",
            symbols = ["vscanf", "__builtin_vscanf", "__isoc99_vscanf", "__isoc23_vscanf"],
            synopsis = "int vscanf(const char* format, va_list ap)",
            description = "Read formatted input from standard input stream",
            category = categories.fmt,
            enabled = True,
            par_cnt = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x > 0,
            log = log
        )
        return
    

class vfscanf(src_func):
    """
    This class represents a source for `libc` function `vfscanf`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "vfscanf",
            symbols = ["vfscanf", "__builtin_vfscanf", "__isoc99_vfscanf", "__isoc23_vfscanf"],
            synopsis = "int vfscanf(FILE* stream, const char* format, va_list ap)",
            description = "Read formatted input from given stream",
            category = categories.fmt,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x > 1,
            log = log
        )
        return


class fopen(src_func):
    """
    This class represents a source for `libc` function `fopen`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fopen",
            symbols = ["fopen", "__builtin_fopen"],
            synopsis = "FILE* fopen(const char* pathname, const char* mode)",
            description = "Open file",
            category = categories.fad,
            enabled = True,
            par_cnt = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return


class freopen(src_func):
    """
    This class represents a source for `libc` function `freopen`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "freopen",
            symbols = ["freopen", "__builtin_freopen"],
            synopsis = "FILE* freopen(const char* pathname, const char* mode, FILE* stream)",
            description = "Open file",
            category = categories.fad,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return


class fdopen(src_func):
    """
    This class represents a source for `libc` function `fdopen`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fdopen",
            symbols = ["fdopen", "__builtin_fdopen"],
            synopsis = "FILE* fdopen(int fd, const char* mode)",
            description = "Open file",
            category = categories.fad,
            enabled = True,
            par_cnt = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return
    

class opendir(src_func):
    """
    This class represents a source for `libc` function `opendir`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "opendir",
            symbols = ["opendir", "__builtin_opendir"],
            synopsis = "DIR* opendir(const char* name)",
            description = "Open directory",
            category = categories.fad,
            enabled = True,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return


class fdopendir(src_func):
    """
    This class represents a source for `libc` function `fdopendir`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "fdopendir",
            symbols = ["fdopendir", "__builtin_fdopendir"],
            synopsis = "DIR* fdopendir(int fd)",
            description = "Open directory",
            category = categories.fad,
            enabled = True,
            par_cnt = lambda x: x == 1,
            par_dataflow = lambda x: False,
            par_slice = lambda x: False,
            log = log
        )
        return


class recv(src_func):
    """
    This class represents a source for `libc` function `recv`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "recv",
            symbols = ["recv", "__builtin_recv"],
            synopsis = "ssize_t recv(int sockfd, void* buf, size_t len, int flags)",
            description = "Receive message from socket",
            category = categories.net,
            enabled = True,
            par_cnt = lambda x: x == 4,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 1,
            log = log
        )
        return
    

class recvfrom(src_func):
    """
    This class represents a source for `libc` function `recvfrom`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "recvfrom",
            symbols = ["recvfrom", "__builtin_recvfrom"],
            synopsis = "ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen)",
            description = "Receive message from socket",
            category = categories.net,
            enabled = True,
            par_cnt = lambda x: x == 6,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 1,
            log = log
        )
        return
    

class recvmsg(src_func):
    """
    This class represents a source for `libc` function `recvmsg`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "recvmsg",
            symbols = ["recvmsg", "__builtin_recvmsg"],
            synopsis = "ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags)",
            description = "Receive message from socket",
            category = categories.net,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: x == 1,
            log = log
        )
        return


class memcpy(snk_func):
    """
    This class represents a sink for `libc` function `memcpy`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "memcpy",
            symbols = ["memcpy", "__builtin_memcpy"],
            synopsis = "void* memcpy(void* dest, const void* src, size_t n)",
            description = "Copy memory area",
            category = categories.mem,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return
    

class memmove(snk_func):
    """
    This class represents a sink for `libc` function `memmove`.
    """
    
    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "memmove",
            symbols = ["memmove", "__builtin_memmove"],
            synopsis = "void* memmove(void* dest, const void* src, size_t n)",
            description = "Copy memory area",
            category = categories.mem,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return


class strcpy(snk_func):
    """
    This class represents a sink for `libc` function `strcpy`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "strcpy",
            symbols = ["strcpy", "__builtin_strcpy"],
            synopsis = "char* strcpy(char* dst, const char* src)",
            description = "Copy string",
            category = categories.scp,
            enabled = True,
            par_cnt = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return


class stpcpy(snk_func):
    """
    This class represents a sink for `libc` function `stpcpy`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "stpcpy",
            symbols = ["stpcpy", "__builtin_stpcpy"],
            synopsis = "char* stpcpy(char* dst, const char* src)",
            description = "Copy string",
            category = categories.scp,
            enabled = True,
            par_cnt = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return
    

class wcscpy(snk_func):
    """
    This class represents a sink for `libc` function `wcscpy`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "wcscpy",
            symbols = ["wcscpy", "__builtin_wcscpy"],
            synopsis = "wchar_t* wcscpy(wchar_t* dest, const wchar_t* src)",
            description = "Copy string",
            category = categories.scp,
            enabled = True,
            par_cnt = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return
    

class wcsncpy(snk_func):
    """
    This class represents a sink for `libc` function `wcsncpy`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "wcsncpy",
            symbols = ["wcsncpy", "__builtin_wcsncpy"],
            synopsis = "wchar_t* wcsncpy(wchar_t* dest, const wchar_t* src, size_t n)",
            description = "Copy string",
            category = categories.scp,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return
    

class strncpy(snk_func):
    """
    This class represents a sink for `libc` function `strncpy`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "strncpy",
            symbols = ["strncpy", "__builtin_strncpy", "stpncpy", "__builtin_stpncpy"],
            synopsis = "char* strncpy(char* s1, const char* s2, size_t n)",
            description = "Fill buffer with bytes from string",
            category = categories.scp,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return


class strcat(snk_func):
    """
    This class represents a sink for `libc` function `strcat`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "strcat",
            symbols = ["strcat", "__builtin_strcat"],
            synopsis = "char* strcat(char* s1, const char* s2)",
            description = "Copy string",
            category = categories.cat,
            enabled = True,
            par_cnt = lambda x: x == 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return


class strncat(snk_func):
    """
    This class represents a sink for `libc` function `strncat`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "strncat",
            symbols = ["strncat", "__builtin_strncat"],
            synopsis = "char* strncat(char* dst, const char* src, size_t ssize)",
            description = "Copy string",
            category = categories.cat,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return
    

class sscanf(snk_func):
    """
    This class represents a sink for `libc` function `sscanf`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "sscanf",
            symbols = ["sscanf", "__builtin_sscanf", "__isoc99_sscanf", "__isoc23_sscanf"],
            synopsis = "int sscanf(const char* str, const char* format, ...)",
            description = "Input string format conversion",
            category = categories.sfc,
            enabled = True,
            par_cnt = lambda x: x >= 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return


class swscanf(snk_func):
    """
    This class represents a sink for `libc` function `swscanf`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "swscanf",
            symbols = ["swscanf", "__builtin_swscanf", "__isoc99_swscanf", "__isoc23_swscanf"],
            synopsis = "int sscanf(const wchar_t* ws, const wchar_t* format, ...)",
            description = "Input string format conversion",
            category = categories.sfc,
            enabled = True,
            par_cnt = lambda x: x >= 2,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return


class vsscanf(snk_func):
    """
    This class represents a sink for `libc` function `vsscanf`.
    """

    def __init__(self, log: Logger = Logger()) -> None:
        super().__init__(
            lib = "libc",
            name = "vsscanf",
            symbols = ["vsscanf", "__builtin_vsscanf", "__isoc99_vsscanf", "__isoc23_vsscanf"],
            synopsis = "int vsscanf(const char* s, const char* format, va_list arg)",
            description = "Input string format conversion",
            category = categories.sfc,
            enabled = True,
            par_cnt = lambda x: x == 3,
            par_dataflow = lambda x: False,
            par_slice = lambda x: True,
            log = log
        )
        return