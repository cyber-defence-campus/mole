#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_LEN 16

/*
Testcase Description:
- gets with memcpy
*/

char *gets(char *s);

int main(int argc, char *argv[]) {
    char dest[BUF_LEN];
    char src[BUF_LEN];

    if(gets(src) == NULL) {
        fprintf(stderr, "Could not read from STDIN.\n");
        return EXIT_FAILURE;
    }

    memcpy(dest, src, BUF_LEN);
    fprintf(stdout, "dest: '%s'\n", dest);
    return EXIT_SUCCESS;
}