#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 64

/*
Testcase Description:
- Memory defined by multiple instructions (mem phi-node)
*/

int main(int argc, char *argv[]) {
    char *env_dst;
    char cmd[BUF_SIZE];

    env_dst = getenv("DESTINATION");
    if(env_dst == NULL) {
        strcpy(cmd, "ping -c 1 127.0.0.1 &");
    } else {
        snprintf(cmd, BUF_SIZE, "ping -c 1 \"%s\" &", env_dst);
    }
    system(cmd);
    return EXIT_SUCCESS;
}