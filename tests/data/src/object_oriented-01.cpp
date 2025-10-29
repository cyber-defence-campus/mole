#include <iostream>
#include <cstdlib>

using namespace std;

/*
Testcase Description:
- Inheritance
- Without virtual functions (no polymorphism)
*/

class MyParent {
protected:
    const char* name;

public:
    __attribute__ ((noinline, optimize("O0")))
    MyParent(const char* name) {
        this->name = name;
        cout << "MyParent Constructor: Hello " << name << "!" << endl;
    }

    __attribute__ ((noinline, optimize("O0")))
    ~MyParent() {
        cout << "MyParent Destructor: Goodbye " << name << "!" << endl;
    }

    __attribute__ ((noinline, optimize("O0")))
    void my_func(const char* cmd) {
        cout << "MyParent::my_func: " << name << " calls `system('" << cmd << "')`!" << endl;
        system(cmd);
    }
};

class MyChild : public MyParent {
public:
    __attribute__ ((noinline, optimize("O0")))
    MyChild(const char* name) : MyParent(name) {
        cout << "MyChild Constructor: Hello " << name << "!" << endl;
    }

    __attribute__ ((noinline, optimize("O0")))
    ~MyChild() {
        cout << "MyChild Destructor: Goodbye " << name << "!" << endl;
    }

    __attribute__ ((noinline, optimize("O0")))
    void my_func(const char* cmd) {
        cout << "MyChild::my_func: " << name << " calls `popen('" << cmd << "', 'r')`!" << endl;
        FILE* fp = popen(cmd, "r");
        if(fp != NULL) {
            pclose(fp);
        }
    }
};

int main(int argc, char *argv[]) {
    MyParent* p = new MyParent("Alice");
    MyParent* c = new MyChild("Bob");
    char* cmd = getenv("CMD");
    if(cmd != NULL) {
        p->my_func(cmd);
        c->my_func(cmd);
    }
    delete p;
    delete c;
    return EXIT_SUCCESS;
}