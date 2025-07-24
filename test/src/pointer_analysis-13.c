#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/*
Testcase Description:
- Multiple source memory definitions
- Usage of va structs
*/

__attribute__ ((noinline))
int create_cmd(char** str_ptr, const char* fmt, ...) {
    va_list args, args_cpy;
    // Compute length of formatted string
    va_start(args, fmt);
    va_copy(args_cpy, args);
    int len = vsnprintf(NULL, 0, fmt, args_cpy);
    va_end(args_cpy);
    if(len < 0) {
        va_end(args);
        return -1;
    }
    // Allocate memory for the string
    *str_ptr = (char*) malloc(len + 1);
    if(*str_ptr == NULL) {
        va_end(args);
        return -1;
    }
    // Write formatted string to allocated memory
    int res = vsnprintf(*str_ptr, len + 1, fmt, args);
    va_end(args);
    return res;
}

int main(int argc, char *argv[]) {
    // Source: User inputs via environment variables
    char *env_user_id   = getenv("USER_ID");
    char *env_user_name = getenv("USER_NAME");
    char *env_user_pass = getenv("USER_PASS");
    if(env_user_id == NULL || env_user_name == NULL || env_user_pass == NULL) {
        fprintf(stderr, "Missing environment variables.\n");
        return EXIT_FAILURE;
    }
    int user_id = atoi(env_user_id);
    // Create command string
    char *cmd = NULL;
    if(user_id == 0) {
        if(create_cmd(&cmd, "echo %s:%s", env_user_name, env_user_pass) < 0) {
            fprintf(stderr, "Failed to create command for root user '%s'.\n", env_user_name);
            return EXIT_FAILURE;
        }
    } else {
        if(create_cmd(&cmd, "echo %s:%s", env_user_name, env_user_pass) < 0) {
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