#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Function with output parameter (char**)
*/

__attribute__ ((noinline, optimize("O0")))
int check_cmd(char* msg, char** cmd){
    if(*cmd != NULL){
        return 0;
    }
    msg = getenv("MSG");
    if(msg != NULL){
        fprintf(stderr, "%s!\n", msg);
    }
    return -1;
}

int main() {
    char *msg = NULL;
    char *cmd = getenv("CMD");
    if (check_cmd(msg, &cmd) == 0) {
        system(cmd);
    }
    return 0;
}