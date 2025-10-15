#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
Testcase Description:
- getopt param ended up in a strcpy call
*/

int main(int argc, char *argv[]) {
    char buffer[128];
    int opt;
    char *source = NULL;

    while ((opt = getopt(argc, argv, "s:")) != -1) {
        switch (opt) {
            case 's':
                source = optarg;
                break;
            default:
                return EXIT_FAILURE;
        }
    }

    if (source != NULL) {
        // User-controlled source from getopt ends up in memcpy
        strcpy(buffer, source);
        printf("Copied: %s\n", buffer);
    }

    return EXIT_SUCCESS;
}