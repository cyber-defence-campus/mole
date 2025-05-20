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


    // struct my_struct1 s1 = {1337, 1338};
    // // struct my_struct1 s2;
    // // my_struct2 s3 = {1339, 1340};
    // // my_struct2 s4;

    // // volatile struct my_struct1 *vs1 = &s1;
    // // volatile struct my_struct1 *vs2 = &s2;
    // s1.field_a += argc;
    // s1.field_b += argc;

    // // *vs2 = *vs1;
    // // s4 = s3;
    // // memcpy(&s2, &s1, sizeof(struct my_struct1));

    // fprintf(stdout, "s1.field_a = %d\n", s1.field_a);
    // fprintf(stdout, "s1.field_b = %d\n", s1.field_b);
    // // fprintf(stdout, "s4.field_a = %d\n", s4.field_a);
    // // fprintf(stdout, "s4.field_b = %d\n", s4.field_b);
    
    return EXIT_SUCCESS;
}