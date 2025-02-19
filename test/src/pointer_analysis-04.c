#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CMD_LEN 64

/*
Testcase Description:
- pointer analysis
*/

int main(int argc, char *argv[]) {
    char cmd[CMD_LEN];
    char *env_cmd = getenv("SYSTEM_COMMAND");
    snprintf(cmd, CMD_LEN, "%s %s", cmd, env_cmd);
    snprintf(cmd, CMD_LEN, "%s %d", cmd, 1337);
    return system(cmd);
}