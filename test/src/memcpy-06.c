#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[]) {
    char dest[16];
    char src[] = "01-memcpy";
    size_t n = strlen(src);

    char *env_select = getenv("MEMCPY_SELECT");
    if(env_select == NULL) {
        fprintf(stderr, "MEMCPY_SELECT environment variable not set.\n");
        return EXIT_FAILURE;
    }
    env_select = src;

    memcpy(dest, env_select, n);
    dest[n] = '\0';
    fprintf(stdout, "dest: '%s'\n", dest);

    return EXIT_SUCCESS;
}