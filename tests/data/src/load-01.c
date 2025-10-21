#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD with HLIL constant pointer dereferencing source
*/

char* cmd;

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    cmd = getenv("CMD");
    return system(cmd);
}