#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Function with output parameter
*/

__attribute__ ((noinline))
int get_cmd(char **out_cmd){
    char *env_cmd = getenv("CMD");
    if (env_cmd != 0) {
        *out_cmd = env_cmd;
        return 0;
    }
    return -1;
}

int main() {
    char *cmd = NULL;
    if (get_cmd(&cmd) == 0) {
        system(cmd);
    } else {
        fprintf(stderr, "CMD environment variable not set.\n");
    }
    return 0;
}