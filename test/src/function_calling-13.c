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
int system_1(char *cmd, int* cnt) {
    if(*cnt <= 0) {
        return system(cmd);
    } else {
        (*cnt)--;
        return system_1(cmd, cnt);
    }
}

int main(int argc, char *argv[]) {
    int cnt = argc;
    char *env_cmd = getenv("CMD");
    if(env_cmd == NULL) {
        fprintf(stderr, "CMD environment variable not set.\n");
        return EXIT_FAILURE;
    }
    return system_1(env_cmd, &cnt);
}