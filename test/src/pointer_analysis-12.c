#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Multiple source memory definitions
*/

int execute(int user_id, char* user_name, char* user_pass) {
    char *cmd = NULL;
    if(user_id == 0) {
        if(asprintf(&cmd, "echo %s:%s (root)", user_name, user_pass) == -1) {
            fprintf(stderr, "Failed to allocate memory for user '%s' (root).\n", user_name);
            return EXIT_FAILURE;
        }
    } else {
        if(asprintf(&cmd, "echo %s:%s (user)", user_name, user_pass) == -1) {
            fprintf(stderr, "Failed to allocate memory for user '%s' (user).\n", user_name);
            return EXIT_FAILURE;
        }
    }
    if(system(cmd) == -1) {
        fprintf(stderr, "Failed to execute command.\n");
        return EXIT_FAILURE;
    }
    free(cmd);
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    
    char *user_id   = getenv("USER_ID");
    char *user_name = getenv("USER_NAME");
    char *user_pass = getenv("USER_PASS");

    if(user_id == NULL || user_name == NULL || user_pass == NULL) {
        fprintf(stderr, "Missing environment variables.\n");
        return EXIT_FAILURE;
    }
    
    return execute(atoi(user_id), user_name, user_pass);
}