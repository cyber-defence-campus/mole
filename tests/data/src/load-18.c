#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD through a pointer loaded from a constant global address (global array element)
- Pointed-to heap buffer allocated and written in a callee, which returns it
- Callee's store to the returned buffer defines the loaded memory, so it should be followed
*/

char** cmds[4];

__attribute__ ((noinline, optimize("O0")))
char** new_cmds(char* cmd) {
    char** p = malloc(sizeof(char*));
    p[0] = cmd;
    return p;
}

__attribute__ ((noinline, optimize("O0")))
void set_cmds(void) {
    cmds[2] = new_cmds(getenv("CMD"));
}

__attribute__ ((noinline, optimize("O0")))
char* get_cmd(void) {
    return cmds[2][0];
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    set_cmds();
    return system(get_cmd());
}
