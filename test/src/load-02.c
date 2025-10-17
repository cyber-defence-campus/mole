#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Load using non-constant pointer dereferencing
*/

#define BUF_SIZE 32

int main(int argc, char *argv[]) {
    if(argc >= 3) {
        char path[BUF_SIZE];
        char cmd[BUF_SIZE];
        argv[1] = getenv("FILE_PATH");
        argv[2] = getenv("SEARCH_TERM");
        snprintf(path, sizeof(path), "%s", argv[1]);
        snprintf(cmd, sizeof(cmd), "grep %s %s", argv[2], path);
        system(cmd);
    }
    return 0;
}