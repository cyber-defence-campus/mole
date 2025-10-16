#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- `MediumLevelILLoadSsa` with `MediumLevelILConstPtr` as source
*/

typedef struct {
    char* src;
} MyStruct;

MyStruct s;

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    MyStruct *p = &s;
    p->src = getenv("CMD");
    system(p->src);
    return 0;
}