#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Load using array indexing
*/

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    if(argc >= 2) {
        argv[1] = getenv("CMD");
        system(argv[1]);
    }
    return 0;
}