#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Output parameter 1 (char*) : written but no influence on the sink
- Output parameter 2 (char**): not written and influence on the sink
*/

__attribute__ ((noinline, optimize("O0")))
int check_cmd(char* msg, char** cmd){
    if(*cmd != NULL){
        return 0;
    }
    msg = getenv("MSG");
    if(msg != NULL){
        printf("%s!\n", msg);
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