#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Function with output parameter (char**)
*/

__attribute__ ((noinline, optimize("O0")))
int get_cmd(char **out, char** cmd){
    *out = "Test";
    if(*cmd != NULL){
        return 0;
    }
    return -1;
}

int main() {
    char *out = NULL;
    char *cmd = getenv("CMD");
    if (get_cmd(&out, &cmd) == 0) {
        system(cmd);
    } else {
        fprintf(stderr, "CMD environment variable not set.\n");
    }
    return 0;
}