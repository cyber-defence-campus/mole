#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- disallow function inlining
- with tail calls
- direct recursion
*/

__attribute__ ((noinline, optimize("O0")))
char* getenv_2() {
    return getenv("CMD");
}

__attribute__ ((noinline, optimize("O0")))
char* getenv_1(int* cnt) {
    char* cmd = NULL;
    if(*cnt > 0) {
        (*cnt)--;
        cmd = getenv_1(cnt);
    } else{
        cmd = getenv_2();
    }
    return cmd;
}

int main(int argc, char *argv[]) {
    int cnt = argc;
    char *env_cmd = getenv_1(&cnt);
    if(env_cmd == NULL) {
        fprintf(stderr, "CMD environment variable not set.\n");
        return EXIT_FAILURE;
    }
    return system(env_cmd);
}