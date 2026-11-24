#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD_STRUCT with HLIL field dereferencing of a struct pointer parameter source
- Struct member written locally (must-def) and then by a callee through the struct pointer
- The callee's write lies between the local store and the load, so it should be followed
*/

typedef struct {
    int id;
    char* cmd;
} MyStruct;

__attribute__ ((noinline, optimize("O0")))
void set_cmd(MyStruct* p) {
    p->cmd = getenv("CMD");
}

__attribute__ ((noinline, optimize("O0")))
int run(MyStruct* p) {
    p->cmd = "ls";
    set_cmd(p);
    return system(p->cmd);
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    MyStruct s;
    s.id = 1;
    return run(&s);
}
