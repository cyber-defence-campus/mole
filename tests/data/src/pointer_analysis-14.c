#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CMD_LEN 64

/*
Testcase Description:
- pointer analysis
- system with user-controllabel command
*/

int main() {
    char cmd[CMD_LEN];
    char *env_cmd = getenv("CMD");
    if(env_cmd == NULL) {
        printf("CMD not set.\n");
        return EXIT_FAILURE;
    }
    snprintf(cmd, CMD_LEN, "%s", env_cmd);
    int res = system(cmd);
    printf("CMD: %s\n", cmd);
    return res;
}