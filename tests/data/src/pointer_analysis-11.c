#include <stdlib.h>
#include <stdio.h>

#define CMD_LEN 64

__attribute__ ((noinline, optimize("O0")))
char* validate(char *cmd) {
    if(cmd == NULL) cmd = "";
    return cmd;
}

__attribute__ ((noinline))
int execute(char *cmd) {
    cmd = validate(cmd);
    return system(cmd);
}

int main(int argc, char *argv[]) {
    char cmd[CMD_LEN];
    char *env_cmd = getenv("CMD");
    snprintf(cmd, CMD_LEN, "%s", env_cmd);
    return execute(cmd);
}