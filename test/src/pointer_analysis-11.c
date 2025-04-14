#include <stdlib.h>

__attribute__ ((noinline))
char* validate(char *cmd) {
    if(cmd == NULL) cmd = "";
    return cmd;
}

__attribute__ ((noinline))
int execute(char *cmd) {
    cmd = validate(cmd);
    return system(cmd);
}

int main(int argc, char *argv[]) {
    char *cmd = getenv("CMD");
    return execute(cmd);
}