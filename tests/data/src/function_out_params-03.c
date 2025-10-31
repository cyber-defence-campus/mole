#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Function with output parameter (char**)
*/

__attribute__ ((noinline, optimize("O0")))
int get_cmd(char **out_cmd){
    char* env_cmd = getenv("CMD");
    char** out_cmd_cpy = out_cmd;
    if (env_cmd != NULL) {
        *out_cmd_cpy = env_cmd;
        return 0;
    }
    *out_cmd_cpy = "Test";
    printf("%s\n", *out_cmd_cpy);
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