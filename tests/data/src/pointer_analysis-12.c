#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Multiple source memory definitions
*/

__attribute__ ((noinline))
int create_cmd(char** str_ptr, const char* user_name) {
    const char* fmt = "echo %s";
    // Compute length of formatted string
    int len = snprintf(NULL, 0, fmt, user_name);
    if(len < 0) return -1;
    // Allocate memory for the string
    *str_ptr = (char*) malloc(len + 1);
    if(*str_ptr == NULL) {
        return -1;
    }
    // Write formatted string to allocated memory
    int res = snprintf(*str_ptr, len + 1, fmt, user_name);
    if(res < 0) {
        free(*str_ptr);
        *str_ptr = NULL;
        return -1;
    }
    return res;
}

int main(int argc, char *argv[]) {
    // Source: User inputs via environment variables
    char *env_user_id   = getenv("USER_ID");
    char *env_user_name = getenv("USER_NAME");
    if(env_user_id == NULL || env_user_name == NULL) {
        fprintf(stderr, "Missing environment variables.\n");
        return EXIT_FAILURE;
    }
    int user_id = atoi(env_user_id);
    // Create command string
    char *cmd = NULL;
    if(user_id == 0) {
        if(create_cmd(&cmd, env_user_name) < 0) {
            fprintf(stderr, "Failed to create command for root user '%s'.\n", env_user_name);
            return EXIT_FAILURE;
        }
    } else {
        if(create_cmd(&cmd, env_user_name) < 0) {
            fprintf(stderr, "Failed to create command for user '%s'.\n", env_user_name);
            return EXIT_FAILURE;
        }
    }
    // Sink: Execute command
    if(system(cmd) == -1) {
        fprintf(stderr, "Failed to execute command.\n");
        free(cmd);
        return EXIT_FAILURE;
    }
    free(cmd);
    return EXIT_SUCCESS;
}