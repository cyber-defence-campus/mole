#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD with variable source (array index)
*/

#define BUF_SIZE 32

__attribute__ ((noinline, optimize("O1")))
int main(int argc, char *argv[]) {
    char cmd[BUF_SIZE];
    argv[1] = getenv("FILE");
    argv[2] = getenv("TERM");
    snprintf(cmd, sizeof(cmd), "grep %s %s", argv[1], argv[2]);
    return system(cmd);
}