#include <string>

/*
Testcase Description:
- Template instantiation (C++ name mangling)
*/

template<typename T>
__attribute__ ((noinline, optimize("O0")))
int my_func(char *cmd, T dummy) {
    if(dummy) {
        printf("[+] template function called with cmd='%s'\n", cmd);
    }
    return system(cmd);
}

int main(int argc, char *argv[]) {
    char *cmd = getenv("CMD");
    if(cmd != NULL) {
        my_func(cmd, 1);
    }
    return EXIT_SUCCESS;
}