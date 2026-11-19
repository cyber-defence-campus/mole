#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD_STRUCT with global struct member dereferencing source
- Struct member written by multiple callees, each a may-def of the loaded member
- One callee writes the member conditionally (source on one path, constant on the other)
- Local store in the caller is followed by the callees' stores before the load
*/

typedef struct {
    int id;
    char* cmd;
} MyStruct;

MyStruct s;

__attribute__ ((noinline, optimize("O0")))
void set_cmd1() {
    s.id = 1;
    s.cmd = getenv("CMD");
}

__attribute__ ((noinline, optimize("O0")))
void set_cmd2(char* name) {
    s.id = 2;
    if(strcmp(name, "CMD1") == 0) {
        s.cmd = "pwd";
    } else {
        s.cmd = getenv(name);
    }
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    s.cmd = "ls";
    set_cmd1();
    set_cmd2("CMD1");
    set_cmd2("CMD2");
    return system(s.cmd);
}