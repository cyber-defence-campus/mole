#include <stdio.h>
#include <stdlib.h>

#define BUF_LEN 16

/*
Testcase Description:
- gets
*/

char *gets(char *s);

int main(int argc, char *argv[]) {
    char s[BUF_LEN];

    if(gets(s) == NULL) {
        fprintf(stderr, "Could not read from STDIN.\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "s: '%s'\n", s);
    return EXIT_SUCCESS;
}