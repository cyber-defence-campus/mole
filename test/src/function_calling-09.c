#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- Call function twice
*/

__attribute__ ((noinline))
char* func(char* env) {
    return env;
}

__attribute__((optimize("O0")))
int main(int argc, char *argv[]) {
    char *env_cmd, *cmd;
    env_cmd = getenv("ENV_CMD");
    cmd = func(env_cmd);
    cmd = func(cmd);
    return system(cmd);
}