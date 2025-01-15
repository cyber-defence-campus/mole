#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- source in callee
- disallowing function inlining
- without tail calls
*/

__attribute__ ((noinline)) 
char* getenv_2() {
    char *env_cmd = getenv("SYSTEM_COMMAND");
    fprintf(stdout, "SYSTEM_COMMAND_2: '%s'", env_cmd);
    return env_cmd;
}

__attribute__ ((noinline)) 
char* getenv_1a() {
    char *env_cmd = getenv_2();
    fprintf(stdout, "SYSTEM_COMMAND_1a: '%s'", env_cmd);
    return env_cmd;
}

__attribute__ ((noinline)) 
char* getenv_1b() {
    char *env_cmd = getenv_2();
    fprintf(stdout, "SYSTEM_COMMAND_1b: '%s'", env_cmd);
    return env_cmd;
}

int main(int argc, char *argv[]) {
    char *env_cmd;

    if(argc <= 1) {
        env_cmd = getenv_1a();
        fprintf(stdout, "Calling getenv_1a\n");
    } else {
        env_cmd = getenv_1b();
        fprintf(stdout, "Calling getenv_1b\n");
    }
    if(env_cmd == NULL) {
        fprintf(stderr, "SYSTEM_COMMAND environment variable not set.\n");
        return EXIT_FAILURE;
    }
    return system(env_cmd);
}