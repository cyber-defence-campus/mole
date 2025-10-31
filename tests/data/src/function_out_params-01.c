#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 8

/*
Testcase Description:
- Function with output parameter
*/

char dest[BUF_SIZE];
char src[] = "Hello, World!";

__attribute__ ((noinline))
int get_size(int* size){
    char* env_size = getenv("SIZE");
    if(env_size != NULL) {
        *size = atoi(env_size);
        return 0;
    }
    return -1;
}

int main() {
    int size = 0;
    if (get_size(&size) == 0) {
        memcpy(dest, src, size);
    } else {
        fprintf(stderr, "SIZE environment variable not set.\n");
    }
    return 0;
}