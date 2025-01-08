#include <stdio.h>
#include <stdlib.h>

__attribute__ ((noinline)) int sum(int a, int b) {
    return a + b;
}

int main(int argc, char *argv[]) {
    int env_size = (int) getenv("MEMCPY_SIZE");
    int result = sum(env_size, 2);
    sprintf("Result: %d\n", result);
    return 0;
}