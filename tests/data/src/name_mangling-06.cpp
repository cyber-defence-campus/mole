#include <string>

/*
Testcase Description:
- Operator overloading (C++ name mangling)
*/

struct MyStruct {
    std::string cmd;

    MyStruct(const std::string& cmd) : cmd(cmd) {}

    MyStruct operator+(const MyStruct &other) {
        char *env_cmd = getenv("CMD");
        if(env_cmd != NULL) {
            this->cmd = std::string(this->cmd + ";" + std::string(env_cmd) + ";" + other.cmd);
        } else {
            this->cmd = std::string(this->cmd + ";" + other.cmd);
        }
        return *this;
    }

    __attribute__ ((noinline, optimize("O0")))
    int my_func() {
        return system(this->cmd.c_str());
    }
};

int main(int argc, char *argv[]) {
    MyStruct s1("echo '>>'");
    MyStruct s2("echo '<<'");
    MyStruct s3 = s1 + s2;
    s3.my_func();
    return EXIT_SUCCESS;
}