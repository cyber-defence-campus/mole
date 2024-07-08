#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__ ((noinline)) char* my_getenv(const char* name) {
    return getenv(name);
}

int main(int argc, char *argv[]) {
    char dest[16];
    char src[] = "01-memcpy";

    char* env_size = my_getenv("MEMCPY_SIZE");
    if(env_size == NULL) {
        fprintf(stderr, "MEMCPY_SIZE environment variable not set.\n");
        return EXIT_FAILURE;
    }
    int n = atoi(env_size);

    memcpy(dest, src, n);
    dest[n] = '\0';
    fprintf(stdout, "dest: '%s'\n", dest);

    return EXIT_SUCCESS;
}