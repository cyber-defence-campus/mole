#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
Testcase Description:
- structs
- MediumLevelILLoadStructSsa instruction
*/

#define BUF_LEN 8

struct Person {
    char *name;
    int   age;
};

typedef struct {
    char *name;
    int   age;
} Animal;

__attribute__((optimize("O0")))
int main(int argc, char *argv[]) {
    int age;
    char name[BUF_LEN];
    char *env_name, *env_age;
    struct Person i, *p = &i;

    // Get person name
    env_name = getenv("NAME");
    if(env_name == NULL) {
        env_name = "Alice";
    }

    // Get person age
    env_age = getenv("AGE");
    if(env_age == NULL) {
        env_age = "19";
    }
    age = atoi(env_age);

    p->name = env_name;
    p->age  = age;

    // Sink
    memcpy(name, p->name, BUF_LEN);
    printf("Hello %s!\n", name);
    return EXIT_SUCCESS;
}