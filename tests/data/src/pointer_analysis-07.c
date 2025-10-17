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
void my_getenv(char **env_src) {
    *env_src = getenv("MEMCPY_SRC");
}

int main(int argc, char *argv[]) {
    char dest[BUF_LEN];

    my_getenv(&src);
    memcpy(dest, src, BUF_LEN);
    fprintf(stdout, "dest: %s\n", dest);

    return EXIT_SUCCESS;
}