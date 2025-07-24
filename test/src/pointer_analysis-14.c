#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CMD_LEN 64

/*
Testcase Description:
- pointer analysis
- system with user-controllabel command
*/

int main(int argc, char *argv[]) {
    char cmd[CMD_LEN];

    char *env_cmd = getenv("SYSTEM_COMMAND");
    if(env_cmd == NULL) {
        fprintf(stderr, "SYSTEM_COMMAND environment variable not set.\n");
        return EXIT_FAILURE;
    }
    snprintf(cmd, CMD_LEN, "%s", env_cmd);
    int res = system(cmd);
    fprintf(stdout, "Executed command: %s\n", cmd);
    return res;
}