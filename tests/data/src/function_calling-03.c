#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- allow function inlining
- without tail calls
*/

char* getenv_2(char *cmd) {
    char *env_cmd = getenv(cmd);
    fprintf(stdout, "getenv_2: '%s'\n", env_cmd);
    return env_cmd;
}

char* getenv_1a() {
    char *env_cmd = getenv_2("SYSTEM_COMMAND_1a");
    fprintf(stdout, "getenv_1a: '%s'\n", env_cmd);
    return env_cmd;
}

char* getenv_1b() {
    char *env_cmd = getenv_2("SYSTEM_COMMAND_1b");
    fprintf(stdout, "getenv_1b: '%s'\n", env_cmd);
    return env_cmd;
}

char* getenv_1c() {
    char *env_cmd = getenv("NOT_DANGEROUS");
    fprintf(stdout, "getenv_1c: '%s'\n", env_cmd);
    return env_cmd;
}

int system_2(char *cmd) {
    int res = system(cmd);
    fprintf(stdout, "system_2: '%d'\n", res);
    return res;
}

int system_1a(char *cmd) {
    int res = system_2(cmd);
    fprintf(stdout, "system_1a: '%d'\n", res);
    return res;
}

int system_1b(char *cmd) {
    int res = system_2(cmd);
    fprintf(stdout, "system_1b: '%d'\n", res);
    return res;
}

int main(int argc, char *argv[]) {
    char *env_cmd;

    if(argc <= 1) {
        env_cmd = getenv_1a();
    } else {
        env_cmd = getenv_1b();
    }
    fprintf(stdout, "main: '%s'\n", env_cmd);
    if(env_cmd == NULL) {
        fprintf(stderr, "SYSTEM_COMMAND environment variable not set.\n");
        return EXIT_FAILURE;
    }
    system_1a(env_cmd);
    system_1b("whoami");
    getenv_1c();
    return EXIT_SUCCESS;
}