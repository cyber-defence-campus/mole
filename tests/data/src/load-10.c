#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- MLIL_VAR_ALIASED_FIELD with HLIL struct field of a local (aliased) variable source
- Struct is aliased since its address escapes; only the store to the loaded member should be followed
*/

typedef struct {
    char* cmd1;
    char* cmd2;
} MyStruct;

__attribute__ ((noinline, optimize("O0")))
void print_struct(MyStruct* p) {
    printf("%p\n", (void*) p);
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    MyStruct s;
    s.cmd1 = getenv("CMD1");
    s.cmd2 = getenv("CMD2");
    print_struct(&s);
    return system(s.cmd2);
}
