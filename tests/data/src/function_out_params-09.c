#include <stdio.h>
#include <string.h>

#define BUF_SIZE 8

/*
Testcase Description:
- Output parameter 1 (size_t*): written and influence on the sink
- Function output parameters are pointers
*/

__attribute__ ((noinline, optimize("O0")))
void read_size(size_t* size) {
    fscanf(stdin, "%zu", size);
}

int main() {
    char dest[BUF_SIZE];
    char src[] = "Hello, World!";
    size_t size = 0;
    read_size(&size);
    memcpy(dest, src, size);
    printf("%s\n", dest);
    return 0;
}