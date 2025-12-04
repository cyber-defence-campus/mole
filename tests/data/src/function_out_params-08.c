#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Output parameter 1 (char**): written in a callee
*/

__attribute__ ((noinline, optimize("O0")))
void get_cmd(char** cmd){
    *cmd = getenv("CMD");
    return;
}

__attribute__ ((noinline, optimize("O0")))
int check_cmd(char** cmd){
    get_cmd(cmd);
    if(*cmd != NULL){
        return 0;
    }
    return -1;
}

int main() {
    char *cmd = NULL;
    if (check_cmd(&cmd) == 0) {
        system(cmd);
    } else {
        fprintf(stderr, "CMD environment variable not set.\n");
    }
    return 0;
}