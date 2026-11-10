#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD_STRUCT with global struct member dereferencing source
- Struct member written in a different function than it is read
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
    set_cmd();
    return system(s.cmd);
}