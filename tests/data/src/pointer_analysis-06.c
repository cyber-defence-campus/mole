#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_LEN 64

/*
Testcase Description:
- pointer analysis
- memcpy size is user-controllable
*/

__attribute__((noinline))
void modify_n(int *n) {
    char* env_n = getenv("MEMCPY_SIZE");
    if(env_n != NULL) {
        *n = atoi(env_n);
    }
}

int main(int argc, char *argv[]) {
    char dest[BUF_LEN], src[] = "pointer_analysis";
    int n, *n_ptr;

    n = BUF_LEN;
    n_ptr = &n;
    
    modify_n(n_ptr);
    memcpy(dest, src, n);
    fprintf(stdout, "n: '%d'\n", n);

    return EXIT_SUCCESS;
}