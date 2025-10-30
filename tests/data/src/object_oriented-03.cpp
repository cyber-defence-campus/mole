#include <iostream>
#include <cstdlib>

using namespace std;

#define MAX_CMD_LENGTH 256

/*
Testcase Description:
- Inheritance
- With virtual functions (polymorphism)
- Using member variable assigned in constructor
*/

class MyParent {
protected:
    const char* name;

public:
    __attribute__ ((noinline, optimize("O0")))
    MyParent(const char* name) {
        this->name = name;
        cout << "MyParent Constructor: Hello " << this->name << "!" << endl;
    }

    __attribute__ ((noinline, optimize("O0")))
    virtual ~MyParent() {
        cout << "MyParent Destructor: Goodbye " << this->name << "!" << endl;
    }

    __attribute__ ((noinline, optimize("O0")))
    virtual void my_func() {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "echo Hello %s!", this->name);
        cout << "MyParent::my_func: " << this->name << " calls `system('" << string(cmd) << "'`!" << endl;
        system(cmd);
    }
};

class MyChild : public MyParent {
public:
    __attribute__ ((noinline, optimize("O0")))
    MyChild(const char* name) : MyParent(name) {
        cout << "MyChild Constructor: Hello " << this->name << "!" << endl;
    }

    __attribute__ ((noinline, optimize("O0")))
    ~MyChild() override {
        cout << "MyChild Destructor: Goodbye " << this->name << "!" << endl;
    }

    __attribute__ ((noinline, optimize("O0")))
    void my_func() override {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "echo Hello %s!", this->name);
        cout << "MyChild::my_func: " << this->name << " calls `popen('" << string(cmd) << "', 'r')`!" << endl;
        FILE* fp = popen(cmd, "r");
        if(fp != NULL) {
            pclose(fp);
        }
    }
};

__attribute__ ((noinline, optimize("O3")))
int main(int argc, char *argv[]) {
    char* p_name = getenv("PARENT_NAME");
    if(p_name != NULL) {
        MyParent* p = new MyParent(p_name);
        p->my_func();
        delete p;
    }
    char* c_name = getenv("CHILD_NAME");
    if(c_name != NULL) {
        MyParent* c = new MyChild(c_name);
        c->my_func();
        delete c;
    }
    return EXIT_SUCCESS;
}