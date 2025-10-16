#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- controllable source and size
- unexploitable do to validation
*/

int main(int argc, char *argv[]) {
    size_t dest_size = 16;
    char dest[dest_size];
    char* env_src = getenv("MEMCPY_SRC");
    if(env_src == NULL) {
        fprintf(stderr, "MEMCPY_SRC environment variable not set.\n");
        return EXIT_FAILURE;
    }
    size_t src_size = strlen(env_src);
    if(src_size >= dest_size) {
        fprintf(stderr, "MEMCPY_SRC size >= %zu\n.", dest_size);
        return EXIT_FAILURE;
    }
    memcpy(dest, env_src, src_size);
    dest[src_size] = '\0';
    fprintf(stdout, "dest: '%s'\n", dest);
    return EXIT_SUCCESS;
}