#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD with HLIL variable+shifted-index dereferencing source
- Store and load are lifted with commuted operands: `*((i << 4) + arr)` vs `*(arr + (i << 4))`
*/

typedef struct {
    char* cmd;
    int id;
} MyStruct;

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    MyStruct* arr = (MyStruct*) malloc(4 * sizeof(MyStruct));
    int i = argc & 3;
    arr[i].cmd = getenv("CMD");
    return system(arr[i].cmd);
}