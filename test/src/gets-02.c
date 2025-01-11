#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char dest[16];
    char src[16];

    if(gets(src) == NULL) {
        fprintf(stderr, "Could not read from STDIN.\n");
        return EXIT_FAILURE;
    }

    memcpy(dest, src, 16);
    fprintf(stdout, "dest: '%s'\n", dest);
    return EXIT_SUCCESS;
}