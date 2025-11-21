#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define BUF_SIZE 1024

/*
Testcase Description:
- pointer analysis
*/

struct MyStruct {
    int sock_fd;
    char buf[BUF_SIZE];
};

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char * argv[]) {
    int n;
    char buf[BUF_SIZE];
    struct MyStruct* s;

    s = malloc(sizeof(struct MyStruct));
    s->sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    n = recv(s->sock_fd, &buf, BUF_SIZE, 0);
    memcpy(&s->buf, &buf, n);
    system((const char*) &s->buf);

    return 0;
}