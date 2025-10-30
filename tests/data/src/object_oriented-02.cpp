#include <iostream>
#include <cstdlib>

using namespace std;

/*
Testcase Description:
- Inheritance
- With virtual functions (polymorphism)
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
    virtual void my_func(const char* cmd) {
        cout << "MyParent::my_func: " << this->name << " calls `system('" << cmd << "')`!" << endl;
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
    void my_func(const char* cmd) override {
        cout << "MyChild::my_func: " << this->name << " calls `popen('" << cmd << "', 'r')`!" << endl;
        FILE* fp = popen(cmd, "r");
        if(fp != NULL) {
            pclose(fp);
        }
    }
};

__attribute__ ((noinline, optimize("O3")))
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