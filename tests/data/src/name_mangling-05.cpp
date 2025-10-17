#include <cstdlib>

/*
Testcase Description:
- Static data member of a class (C++ name mangling)
*/

struct MyStruct {
    static char* cmd;

    __attribute__ ((noinline, optimize("O0")))
    static int my_func() {
        return system(cmd);
    }
};
char* MyStruct::cmd = getenv("CMD");

class MyClass {
    public:
    static char* cmd;

    __attribute__ ((noinline, optimize("O0")))
    static int my_func() {
        return system(cmd);
    }
};
char* MyClass::cmd = getenv("CMD");

int main(int argc, char *argv[]) {
    if(MyStruct::cmd != NULL) {
        MyStruct::my_func();
    }
    if(MyClass::cmd != NULL) {
        MyClass::my_func();
    }
    return EXIT_SUCCESS;
}