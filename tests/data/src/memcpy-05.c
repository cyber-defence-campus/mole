#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- controllable source and size
- source in function without inlining
*/

__attribute__ ((noinline, optimize("O0"))) char* my_getenv(const char* name) {
    char *env = getenv(name);
    if(env == NULL) {
        return NULL;
    }
    for(size_t i=0; i<strlen(env); i++) {
        env[i] += 1;
    }
    return env;
}

int main(int argc, char *argv[]) {
    char dest[16];

    char* env_src = my_getenv("MEMCPY_SRC");
    if(env_src == NULL) {
        fprintf(stderr, "MEMCPY_SRC environment variable not set.\n");
        return EXIT_FAILURE;
    }
    size_t n = strlen(env_src);

    memcpy(dest, env_src, n);
    dest[n] = '\0';
    fprintf(stdout, "dest: '%s'\n", dest);

    return EXIT_SUCCESS;
}