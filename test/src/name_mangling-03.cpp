#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- Function in a namespace (C++ name mangling)
*/

namespace ns
{
    __attribute__ ((noinline, optimize("O0")))
    int my_func(char *cmd) {
        return system(cmd);
    }
}

int main(int argc, char *argv[]) {
    char *cmd = getenv("CMD");
    if(cmd != NULL) {
        ns::my_func(cmd);
    }
    return EXIT_SUCCESS;
}