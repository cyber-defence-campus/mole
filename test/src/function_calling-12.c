#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- disallow function inlining
- with tail calls
- indirect recursion
*/

char* getenv_4();
char* getenv_3(int* cnt);
char* getenv_2(int* cnt);
char* getenv_1(int* cnt);

__attribute__ ((noinline, optimize("O0")))
char* getenv_4() {
    return getenv("CMD");
}

__attribute__ ((noinline, optimize("O0")))
char* getenv_3(int* cnt) {
    char* cmd = NULL;
    if(*cnt > 0) {
        (*cnt)--;
        return getenv_1(cnt);
    } else {
        cmd = getenv_4();
    }
    return cmd;
}

__attribute__ ((noinline, optimize("O0")))
char* getenv_2(int* cnt) {
    return getenv_3(cnt);
}

__attribute__ ((noinline, optimize("O0")))
char* getenv_1(int* cnt) {
    return getenv_2(cnt);
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