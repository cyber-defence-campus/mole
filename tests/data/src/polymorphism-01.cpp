#include <cstdio>
#include <cstdlib>

/*
Testcase Description:
- Virtual functions
*/

class MyParent {
public:
    __attribute__ ((noinline, optimize("O0")))
    int my_func(char* cmd) {
        printf("MyParent::my_func\n");
        return system(cmd);
    }

    __attribute__ ((noinline, optimize("O0")))
    virtual void my_virt_func1(char* cmd) {
        printf("MyParent::my_virt_func1\n");
        return;
    }

    __attribute__ ((noinline, optimize("O0")))
    virtual int my_virt_func2(char* cmd) {
        printf("MyParent::my_virt_func2\n");
        return system(cmd);
    }
};

class MyChild : public MyParent {
public:
    __attribute__ ((noinline, optimize("O0")))
    int my_func(char* cmd) {
        printf("MyChild::my_func\n");
        FILE* fp = popen(cmd, "r");
        if(fp == NULL) {
            return EXIT_FAILURE;
        }
        pclose(fp);
        return EXIT_SUCCESS;
    }

    __attribute__ ((noinline, optimize("O0")))
    void my_virt_func1(char* cmd) override {
        printf("MyChild::my_virt_func1\n");
        return;
    }

    __attribute__ ((noinline, optimize("O0")))
    int my_virt_func2(char* cmd) override {
        printf("MyChild::my_virt_func2\n");
        FILE* fp = popen(cmd, "r");
        if(fp == NULL) {
            return EXIT_FAILURE;
        }
        pclose(fp);
        return EXIT_SUCCESS;
    }
};

int main(int argc, char *argv[]) {
    MyParent* p = new MyChild();
    char* cmd = getenv("CMD");
    if(cmd != NULL) {
        // Non-virtual function resolved statically AT COMPILE-TIME based on pointer type
        p->my_func(cmd);
        // Virtual functions resolved dynamically AT RUNTIME based on object type
        p->my_virt_func1(cmd);
        p->my_virt_func2(cmd);
    }
    return EXIT_SUCCESS;
}