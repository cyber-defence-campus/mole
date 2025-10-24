#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_LOAD_STRUCT with HLIL field dereferencing source
*/

#define BUF_SIZE 32

char dest[BUF_SIZE];

typedef struct {
    char* src;
    int size;
} MyStruct;

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    MyStruct s, *p = &s;
    p->src = getenv("CMD");
    p->size = atoi(getenv("SIZE"));
    memcpy(dest, p->src, p->size);
    return 0;
}