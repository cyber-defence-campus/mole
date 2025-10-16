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
char* getenv_1a() {
    return getenv_2("SYSTEM_COMMAND_1a");
}

__attribute__ ((noinline))
char* getenv_1b() {
    return getenv_2("SYSTEM_COMMAND_1b");
}

__attribute__ ((noinline))
char* getenv_1c() {
    return getenv("NOT_DANGEROUS");
}

__attribute__ ((noinline))
int system_2(char *cmd) {
    return system(cmd);
}

__attribute__ ((noinline))
int system_1a(char *cmd) {
    return system_2(cmd);
}

__attribute__ ((noinline))
int system_1b(char *cmd) {
    return system_2(cmd);
}

int main(int argc, char *argv[]) {
    char *env_cmd;

    if(argc <= 1) {
        env_cmd = getenv_1a();
    } else {
        env_cmd = getenv_1b();
    }
    fprintf(stdout, "main: '%s'\n", env_cmd);
    if(env_cmd == NULL) {
        fprintf(stderr, "SYSTEM_COMMAND environment variable not set.\n");
        return EXIT_FAILURE;
    }
    system_1a(env_cmd);
    system_1b("whoami");
    getenv_1c();
    return EXIT_SUCCESS;
}