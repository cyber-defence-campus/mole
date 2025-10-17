#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_LEN 64

/*
Testcase Description:
- pointer analysis
- memcpy with user-controllabel source
*/

char* src;

__attribute__((noinline))
void dummy(int *value) {
    *value = 0;
}

__attribute__((noinline))
void my_getenv(char **env_src) {
    *env_src = getenv("MEMCPY_SRC");
}

int main(int argc, char *argv[]) {
    int value = 1;
    char dest[BUF_LEN];

    my_getenv(&src);
    dummy(&value);
    memcpy(dest, src, BUF_LEN);
    fprintf(stdout, "dest: %s, value: %d\n", dest, value);

    return EXIT_SUCCESS;
}