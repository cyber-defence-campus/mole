#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- controllable source and size
- copying source
*/

int main() {
    char dest[16];
    
    char* env_src = getenv("MEMCPY_SRC");
    if(env_src == NULL) {
        fprintf(stderr, "MEMCPY_SRC environment variable not set.\n");
        return EXIT_FAILURE;
    }

    size_t size = strlen(env_src);
    char* buf = (char*) malloc(size + 1);
    if(buf == NULL) {
        fprintf(stderr, "Failed to allocate memory.\n");
        return EXIT_FAILURE;
    }

    for(size_t i=0; i<size; i++) {
        buf[i] = env_src[i];
    }
    buf[size] = '\0';

    memcpy(dest, buf, size+1);
    fprintf(stdout, "dest: '%s'\n", dest);
    free(buf);

    return EXIT_SUCCESS;
}
