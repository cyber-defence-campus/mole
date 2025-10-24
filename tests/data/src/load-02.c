#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD with HLIL variable dereferencing source
*/

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    char** my_array = (char**) malloc(1 * sizeof(char*));
    my_array[0] = getenv("CMD");
    return system(my_array[0]);
}