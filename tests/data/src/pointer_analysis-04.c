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
    
    char *env_cmd_str = getenv("SYSTEM_COMMAND_STR");
    if(env_cmd_str == NULL) {
        fprintf(stderr, "SYSTEM_COMMAND_STR environment variable not set.\n");
        return EXIT_FAILURE;
    }
    char *env_cmd_int = getenv("SYSTEM_COMMAND_INT");
    if(env_cmd_int == NULL) {
        fprintf(stderr, "SYSTEM_COMMAND_INT environment variable not set.\n");
        return EXIT_FAILURE;
    }
    size_t value = atoi(env_cmd_int);
    
    snprintf(cmd, CMD_LEN, "%s", env_cmd_str);
    size_t *ptr_value = &value;
    snprintf(cmd, CMD_LEN, "%s %d", cmd, *ptr_value);
    return system(cmd);
}