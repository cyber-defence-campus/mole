#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Function with no declared arguments to confuse Binary Ninja
*/

__attribute__ ((noinline))
void my_exec() {
    char *cmd;
    asm("mov %%rdi, %0" : "=r"(cmd));
    system(cmd);
}

int main(int argc, char *argv[]) {
    char *env_cmd = getenv("CMD");
    if(env_cmd != NULL) {
        my_exec(env_cmd);
    }
    return EXIT_SUCCESS;
}