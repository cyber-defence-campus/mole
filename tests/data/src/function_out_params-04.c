#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Output parameter 1 (MyStruct*): member written and influence on the sink
*/

typedef struct {
    char* cmd;
} MyStruct;

__attribute__ ((noinline))
int get_cmd(MyStruct *s){
    char *env_cmd = getenv("CMD");
    if (env_cmd != NULL) {
        s->cmd = env_cmd;
        return 0;
    }
    return -1;
}

int main() {
    MyStruct s;
    if (get_cmd(&s) == 0) {
        system(s.cmd);
    } else {
        fprintf(stderr, "CMD environment variable not set.\n");
    }
    return 0;
}