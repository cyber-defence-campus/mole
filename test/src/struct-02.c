#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- structs
- MediumLevelILLoadSsa and MediumLevelILStoreSsa instructions
*/

# define DEST_SIZE 16

typedef struct {
    int size_1;
    int size_2;
} MyStruct;

char dest[DEST_SIZE];
MyStruct s;

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    char* env_size = getenv("SIZE");
    if(env_size != NULL) {
        int size = atoi(env_size);
        MyStruct *p = &s;
        p->size_1 = size;
        p->size_2 = size * 2;
        memcpy(dest, "Hello", p->size_1);
        memcpy(dest, "World", p->size_2);
    }
    return EXIT_SUCCESS;
}