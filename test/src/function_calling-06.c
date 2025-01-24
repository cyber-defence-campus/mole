#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- allow function inlining
- do not follow all function parameters blindly (positive)
*/

char* func(char* env) {
    char *cmd = (char *) malloc(strlen(env) + 1);
    strcpy(cmd, env);
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