#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Output parameter 1 (char**): written but no influence on the sink
- Output parameter 2 (char**): written and influence on the sink
*/

__attribute__ ((noinline))
int get_cmd(char **out_msg, char **out_cmd){
    char *env_cmd = getenv("CMD");
    if (env_cmd != NULL) {
        *out_cmd = env_cmd;
        return 0;
    }
    *out_msg = getenv("MSG");
    return -1;
}

int main() {
    char *msg = NULL;
    char *cmd = NULL;
    if (get_cmd(&msg, &cmd) == 0) {
        system(cmd);
    } else {
        fprintf(stderr, "CMD environment variable not set.\n");
    }
    return 0;
}