#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- allow function inlining
- do not follow all function parameters blindly (negative)
*/

char* func(char* env) {
    char *cmd = (char *) malloc(4);
    cmd[0] = 'l';
    cmd[1] = 's';
    cmd[2] = '\0';
    cmd[3] = '\0';
    fprintf(stdout, "--- FUN ---\n");
    fprintf(stdout, "env: '%s'\ncmd: '%s'\n", env, cmd);
    return cmd;
}

int main(int argc, char *argv[]) {
    char *env, *cmd;
    env = getenv("CMD");
    cmd = func(env);
    system(cmd);
    return EXIT_SUCCESS;
}