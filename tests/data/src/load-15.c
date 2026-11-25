#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD from a constant global address with HLIL global struct array element member source
- Element member written in a function that the reading function does not call (constant index)
*/

typedef struct {
    int id;
    char* cmd;
} MyStruct;

MyStruct s[8];

__attribute__ ((noinline, optimize("O0")))
void set_cmd(void) {
    s[2].cmd = getenv("CMD");
}

__attribute__ ((noinline, optimize("O0")))
char* get_cmd(void) {
    return s[2].cmd;
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    set_cmd();
    return system(get_cmd());
}
