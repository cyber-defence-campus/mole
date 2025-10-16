#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- marking function parameters
*/

__attribute__ ((noinline, optimize("O0")))
char* getenv_2(char *cmd, int debug) {
    if (debug) {
        printf("[DEBUG] getenv_2 called with cmd='%s'\n", cmd);
    }
    return getenv(cmd);
}

__attribute__ ((noinline, optimize("O0")))
char* getenv_1(char* cmd, int debug) {
    if (debug) {
        printf("[DEBUG] getenv_1");
    }
    return getenv_2(cmd, debug);
}

__attribute__ ((noinline, optimize("O0")))
int system_2(char *cmd, int debug) {
    if(debug) {
        printf("[DEBUG] system_2");
    }
    return system(cmd);
}

__attribute__ ((noinline, optimize("O0")))
int system_1(char *cmd, int debug) {
    if(debug) {
        printf("[DEBUG] system_1");
    }
    return system_2(cmd, debug);
}

int main(int argc, char *argv[]) {
    char *env_cmd;
    int debug = 1;

    env_cmd = getenv_1("CMD", debug);
    if(env_cmd == NULL) {
        fprintf(stderr, "CMD environment variable not set.\n");
        return EXIT_FAILURE;
    }

    system_1(env_cmd, debug);
    return EXIT_SUCCESS;
}