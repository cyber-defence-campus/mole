#include <stdint.h>
#include <stdlib.h>

/*
Testcase Description:
- pointer analysis
- union aliasing a pointer with a byte array
- partial overwrite of the pointer's bytes with user-controlled data after an
  escaping call
*/

union Cmd {
    char* ptr;
    uint8_t bytes[sizeof(char*)];
};

__attribute__ ((noinline))
void log_cmd(union Cmd* cmd) {
    __asm__ volatile("" : : "r"(cmd) : "memory");
}

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char *argv[]) {
    union Cmd cmd;
    cmd.ptr = "ls";
    log_cmd(&cmd);
    cmd.bytes[1] = (uint8_t) getenv("CMD")[0];
    cmd.bytes[2] = 0;
    system(cmd.ptr);
    return 0;
}
