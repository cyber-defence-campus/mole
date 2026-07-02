#include <stdlib.h>

/*
Testcase Description:
- indirect call via function pointer
*/

__attribute__ ((noinline, optimize("O0")))
void _getenv(char* cmd) {
    system(cmd);
}

__attribute__ ((noinline, optimize("O0")))
void triggerEvent(void (*handler)(char *), char* arg) {
    if(handler != NULL) {
        return handler(arg);
    }
}

int main()
{
    triggerEvent(_getenv, getenv("SYSTEM_COMMAND"));
    return 0;
}