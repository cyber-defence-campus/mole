#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char s[16];

    if(gets(s) == NULL) {
        fprintf(stderr, "Could not read from STDIN.\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "s: '%s'\n", s);
    return EXIT_SUCCESS;
}