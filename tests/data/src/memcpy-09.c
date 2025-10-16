#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- uncontrollable
*/

int main(int argc, char *argv[]) {
    char dest[16];
    char src[] = "01-memcpy";

    char* env_unused = getenv("MEMCPY_UNUSED");
    if(env_unused == NULL) {
        fprintf(stderr, "MEMCPY_UNUSED environment variable not set.\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "unused: '%s'\n", env_unused);

    size_t n = strlen(src);
    memcpy(dest, src, n);
    dest[n] = '\0';
    fprintf(stdout, "dest: '%s'\n", dest);

    return EXIT_SUCCESS;
}