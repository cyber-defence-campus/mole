#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- Function with overloading (C++ name mangling)
*/

__attribute__ ((noinline, optimize("O0")))
int overloaded_func(char *cmd) {
    return system(cmd);
}

__attribute__ ((noinline, optimize("O0")))
int overloaded_func(char *cmd, int debug) {
    if(debug) {
        printf("overloaded_func called with cmd='%s'\n", cmd);
    }
    return overloaded_func(cmd);
}


int main(int argc, char *argv[]) {
    char *cmd = getenv("CMD");
    int debug = 1;
    if(cmd != NULL) {
        overloaded_func(cmd, debug);
    }
    return EXIT_SUCCESS;
}