#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- disallow function inlining
- with tail calls
*/

__attribute__ ((noinline))
char* getenv_2(char *cmd) {
    return getenv(cmd);
}

__attribute__ ((noinline))
char* getenv_1() {
    return getenv_2("CMD");
}

__attribute__ ((noinline))
char* system_3(char *cmd) {
    return cmd;
}

__attribute__ ((noinline))
char* system_2(char *cmd) {
    return system_3(cmd);
}

__attribute__ ((noinline))
int system_1(char *cmd) {
    cmd = system_2(cmd);
    return system(cmd);
}

int main(int argc, char *argv[]) {
    char *env_cmd = getenv_1();
    if(env_cmd == NULL) {
        fprintf(stderr, "SYSTEM_COMMAND environment variable not set.\n");
        return EXIT_FAILURE;
    }
    system_1(env_cmd);
    return EXIT_SUCCESS;
}