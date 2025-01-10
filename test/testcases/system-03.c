#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__ ((noinline)) char* getenv_2() {
    char *env_cmd = getenv("SYSTEM_COMMAND");
    fprintf(stdout, "SYSTEM_COMMAND_2: '%s'", env_cmd);
    return env_cmd;
}

__attribute__ ((noinline)) char* getenv_1() {
    char *env_cmd = getenv_2();
    fprintf(stdout, "SYSTEM_COMMAND_1: '%s'", env_cmd);
    return env_cmd;
}

int main(int argc, char *argv[]) {
    char *env_cmd = getenv_1();
    if(env_cmd == NULL) {
        fprintf(stderr, "SYSTEM_COMMAND environment variable not set.\n");
        return EXIT_FAILURE;
    }
    return system(env_cmd);
}