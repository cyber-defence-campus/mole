#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- controllable destination
*/

int main(int argc, char *argv[]) {
    char src[] = "03-memcpy";

    char* env_dest = getenv("MEMCPY_DEST");
    if(env_dest == NULL) {
        fprintf(stderr, "MEMCPY_DEST environment variable not set.\n");
        return EXIT_FAILURE;
    }
    size_t n = strlen(src);

    memcpy(env_dest, src, n);
    env_dest[n] = '\0';
    fprintf(stdout, "dest: '%s'\n", env_dest);

    return EXIT_SUCCESS;
}