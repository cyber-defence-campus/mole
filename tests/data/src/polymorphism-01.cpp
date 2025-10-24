#include <stdio.h>
#include <stdlib.h>

/*
Testcase Description:
- Virtual functions
*/

struct MyParentStruct {
    __attribute__ ((noinline, optimize("O0")))
    int my_func(char* cmd) {
        printf("MyParentStruct::my_func\n");
        return system(cmd);
    }

    __attribute__ ((noinline, optimize("O0")))
    virtual void my_virt_func1(char* cmd) {
        printf("MyParentStruct::my_virt_func1\n");
        return;
    }

    __attribute__ ((noinline, optimize("O0")))
    virtual int my_virt_func2(char* cmd) {
        printf("MyParentStruct::my_virt_func2\n");
        return system(cmd);
    }
};

struct MyChildStruct : MyParentStruct {
    __attribute__ ((noinline, optimize("O0")))
    int my_func(char* cmd) {
        printf("MyChildStruct::my_func\n");
        FILE* fp = popen(cmd, "r");
        if(fp == NULL) {
            return EXIT_FAILURE;
        }
        pclose(fp);
        return EXIT_SUCCESS;
    }

    __attribute__ ((noinline, optimize("O0")))
    void my_virt_func1(char* cmd) {
        printf("MyChildStruct::my_virt_func1\n");
        return;
    }

    __attribute__ ((noinline, optimize("O0")))
    int my_virt_func2(char* cmd) {
        printf("MyChildStruct::my_virt_func2\n");
        FILE* fp = popen(cmd, "r");
        if(fp == NULL) {
            return EXIT_FAILURE;
        }
        pclose(fp);
        return EXIT_SUCCESS;
    }
};

int main(int argc, char *argv[]) {
    MyParentStruct* p = new MyChildStruct();
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