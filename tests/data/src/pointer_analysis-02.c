#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CMD_LEN 64

/*
Testcase Description:
- pointer analysis
- system command written from user input, then overwritten by constants
- calls are may-defs, so the user input is still followed
*/

int main(int argc, char *argv[]) {
    char cmd[CMD_LEN];
    
    char *env_cmd = getenv("SYSTEM_COMMAND");
    if(env_cmd == NULL) {
        fprintf(stderr, "SYSTEM_COMMAND environment variable not set.\n");
        return EXIT_FAILURE;
    }
    snprintf(cmd, CMD_LEN, "%s", env_cmd);
    snprintf(cmd, CMD_LEN, "%d", 1337);
    snprintf(cmd, CMD_LEN, "%d", 31337);
    return system(cmd);
}