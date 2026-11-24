#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD from a constant global address with HLIL global struct member source
- Struct member written locally and then in a different function (callee) than it is read
*/

typedef struct {
    int id;
    char* cmd;
} MyStruct;

MyStruct s;

__attribute__ ((noinline, optimize("O0")))
void set_cmd(void) {
    s.id = 1;
    s.cmd = getenv("CMD");
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    s.cmd = "ls";
    set_cmd();
    return system(s.cmd);
}