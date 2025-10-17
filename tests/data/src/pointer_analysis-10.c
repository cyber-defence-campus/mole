#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CMD_LEN 64

/*
Testcase Description:
- pointer analysis
- system with user-controllabel command
*/

__attribute__((noinline))
void dummy(int *value) {
    *value = 0;
}

int main(int argc, char *argv[]) {
    int value = 1;
    char cmd[CMD_LEN];

    char *env_cmd = getenv("SYSTEM_COMMAND");
    if(env_cmd == NULL) {
        fprintf(stderr, "SYSTEM_COMMAND environment variable not set.\n");
        return EXIT_FAILURE;
    }
    for(int i=0; i<10; i++) {
        snprintf(cmd, CMD_LEN, "%s %i", env_cmd, i);
        dummy(&value);
    }
    system(cmd);
    fprintf(stdout, "cmd: %s, value: %d\n", cmd, value);

    return EXIT_SUCCESS;
}