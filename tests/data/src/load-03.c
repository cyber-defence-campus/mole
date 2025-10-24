#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD with HLIL variable+offset dereferencing source
*/

#define BUF_SIZE 32

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    char cmd[BUF_SIZE];
    char** my_array = (char**) malloc(3 * sizeof(char*));
    my_array[1] = getenv("FILE");
    my_array[2] = getenv("TERM");
    snprintf(cmd, sizeof(cmd), "grep %s %s", my_array[1], my_array[2]);
    return system(cmd);
}