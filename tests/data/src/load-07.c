#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD from a constant global address with HLIL global union member source
- Union member written locally and then in a different function (callee) than it is read
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
    u.cmd2 = getenv("CMD2");
    u.cmd1 = my_getenv("CMD1");
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    u.cmd2 = "ls";
    set_cmd();
    return system(u.cmd2);
}
