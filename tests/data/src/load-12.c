#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD_STRUCT with HLIL field dereferencing of a struct pointer parameter source
- Struct member written on both branches of a condition (mem phi-node before the load)
- Each branch's store is a must-def on its own path, so both stores should be followed
*/

typedef struct {
    int id;
    char* cmd;
} MyStruct;

__attribute__ ((noinline, optimize("O0")))
int run(MyStruct* p, int use_cmd) {
    if(use_cmd) {
        p->cmd = getenv("CMD1");
    } else {
        p->cmd = getenv("CMD2");
    }
    return system(p->cmd);
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    MyStruct s;
    s.id = 1;
    return run(&s, argc > 1);
}
