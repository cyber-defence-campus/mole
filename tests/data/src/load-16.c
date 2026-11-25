#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD from a constant global address with HLIL global struct array element member source
- Element member written in a function that the reading function does not call (runtime index)
- Store through the runtime index may define the loaded element, so it should be followed
*/

typedef struct {
    int id;
    char* cmd;
} MyStruct;

MyStruct s[8];

__attribute__ ((noinline, optimize("O0")))
void set_cmd(int i) {
    s[i].cmd = getenv("CMD");
}

__attribute__ ((noinline, optimize("O0")))
char* get_cmd(void) {
    return s[2].cmd;
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    set_cmd(argc > 1 ? 3 : 2);
    return system(get_cmd());
}
