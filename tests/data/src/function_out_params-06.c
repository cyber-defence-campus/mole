#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Output parameter 1 (char**): not written and influence on the sink
*/

__attribute__ ((noinline, optimize("O0")))
int check_cmd(char** cmd){
    if(*cmd != NULL){
        return 0;
    }
    return -1;
}

int main() {
    char *cmd = getenv("CMD");
    if (check_cmd(&cmd) == 0) {
        system(cmd);
    } else {
        fprintf(stderr, "CMD environment variable not set.\n");
    }
    return 0;
}