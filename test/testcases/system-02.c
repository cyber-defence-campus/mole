#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__ ((noinline)) char* getenv_2() {
    return getenv("SYSTEM_COMMAND");
}

__attribute__ ((noinline)) char* getenv_1() {
    return getenv_2();
}

int main(int argc, char *argv[]) {
    char *env_cmd = getenv_1();
    if(env_cmd == NULL) {
        fprintf(stderr, "SYSTEM_COMMAND environment variable not set.\n");
        return EXIT_FAILURE;
    }
    return system(env_cmd);
}