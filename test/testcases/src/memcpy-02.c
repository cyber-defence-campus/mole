#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char dest[16];

    char* env_src = getenv("MEMCPY_SRC");
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