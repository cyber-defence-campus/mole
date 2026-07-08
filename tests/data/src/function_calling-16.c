#include <stdlib.h>

/*
Testcase Description:
- indirect call via global function pointer
*/

static int (*env_handler)(char *);

int _getenv(char* cmd) {
    if(cmd == NULL) {
        return -1;
    }
    return system(cmd);
}

__attribute__ ((noinline))
static void init_handlers(void)
{
    env_handler = _getenv;
}

int main()
{
    init_handlers();
    char* env_cmd = getenv("SYSTEM_COMMAND");
    return env_handler(env_cmd);
}