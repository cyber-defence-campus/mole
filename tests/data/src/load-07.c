#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD_STRUCT with global union member dereferencing source
- Union member written in a different function than it is read
*/

typedef union {
    char* cmd1;
    char* cmd2;
} MyUnion;

MyUnion u;

__attribute__ ((noinline, optimize("O0")))
char* my_getenv(char* name) {
    return getenv(name);
}

__attribute__ ((noinline, optimize("O0")))
void set_cmd(void) {
    u.cmd1 = my_getenv("CMD1");
    u.cmd2 = getenv("CMD2");
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    set_cmd();
    return system(u.cmd2);
}
