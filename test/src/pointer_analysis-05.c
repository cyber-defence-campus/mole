#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_LEN 64

/*
Testcase Description:
- pointer aliasing
- memcpy size is not user-controllable
*/

__attribute__((noinline))
void modify_n(int *n) {
    *n = BUF_LEN;
}

int main(int argc, char *argv[]) {
    char dest[BUF_LEN], src[] = "pointer_analysis";
    int n, *n_alias;

    n = BUF_LEN;
    n_alias = &n;

    char* env_n = getenv("MEMCPY_SIZE");
    if(env_n != NULL) {
        n = atoi(env_n);
        modify_n(n_alias);
        memcpy(dest, src, n);
        fprintf(stdout, "n: '%d'\n", n);
    }

    return EXIT_SUCCESS;
}