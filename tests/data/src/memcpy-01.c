#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- controllable size
*/

int main(int argc, char *argv[]) {
    char dest[16];
    char src[] = "memcpy-01";

    char* env_size = getenv("MEMCPY_SIZE");
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