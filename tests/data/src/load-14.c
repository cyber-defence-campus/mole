#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD with HLIL dereferencing of a pointer parameter source
- Pointed-to memory written locally (must-def) and then by a callee through the pointer
- The callee's write lies between the local store and the load, so it should be followed
*/

__attribute__ ((noinline, optimize("O0")))
void set_cmd(char** p) {
    *p = getenv("CMD");
}

__attribute__ ((noinline, optimize("O0")))
int run(char** p) {
    *p = "ls";
    set_cmd(p);
    return system(*p);
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    char* cmd = NULL;
    return run(&cmd);
}
