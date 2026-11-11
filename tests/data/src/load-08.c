#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD with HLIL struct field of an indexed variable (array of structs) source
- Store and load use distinct MLIL address variables; only HLIL shows the same member
*/

typedef struct {
    int id;
    char* cmd;
} MyStruct;

__attribute__ ((noinline, optimize("O0")))
int run(MyStruct* arr, int i) {
    arr[i].cmd = getenv("CMD");
    return system(arr[i].cmd);
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    MyStruct arr[4];
    return run(arr, argc & 3);
}