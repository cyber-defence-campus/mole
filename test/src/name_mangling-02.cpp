#include <cstdlib>

/*
Testcase Description:
- Member function of a class (C++ name mangling)
*/

struct MyStruct {
    __attribute__ ((noinline, optimize("O0")))
    int my_func(char *cmd) {
        return system(cmd);
    }
};

class MyClass {
    public:
    __attribute__ ((noinline, optimize("O0")))
    int my_func(char *cmd) {
        return system(cmd);
    }
};

int main(int argc, char *argv[]) {
    char *cmd = getenv("CMD");
    if(cmd != NULL) {
        MyStruct s;
        s.my_func(cmd);
        MyClass c;
        c.my_func(cmd);
    }
    return EXIT_SUCCESS;
}