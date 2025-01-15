#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- source in callee
- disallowing function inlining
- with tail calls
*/

__attribute__ ((noinline)) 
char* getenv_2() {
    return getenv("SYSTEM_COMMAND");
}

__attribute__ ((noinline)) 
char* getenv_1a() {
    return getenv_2();
}

__attribute__ ((noinline)) 
char* getenv_1b() {
    return getenv_2();
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