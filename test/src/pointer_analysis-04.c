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
    char *env_magic = getenv("MAGIC");
    int value = atoi(env_magic);
    
    char *env_cmd = getenv("SYSTEM_COMMAND");
    if(env_cmd == NULL) {
        fprintf(stderr, "SYSTEM_COMMAND environment variable not set.\n");
        return EXIT_FAILURE;
    }
    snprintf(cmd, CMD_LEN, "%s", env_cmd);
    int *ptr_value = &value;
    snprintf(cmd, CMD_LEN, "%s %d", cmd, *ptr_value);
    return system(cmd);
}