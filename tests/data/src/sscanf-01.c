#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- sscanf
*/

int main(int argc, char *argv[]) {
    int result, integer;

    char *env_input = getenv("SSCANF_STR");
    if(env_input == NULL) {
        fprintf(stderr, "SSCANF_STR environment variable not set.\n");
        return EXIT_FAILURE;
    }

    result = sscanf(env_input, "%d", &integer);
    fprintf(stdout, "result: '%d', integer: '%d'\n", result, integer);

    return EXIT_SUCCESS;
}