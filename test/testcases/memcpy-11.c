#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    size_t dest_size = 16;
    char dest[dest_size];
    char* env_src = getenv("MEMCPY_SRC");
    if(env_src != NULL) {
        memcpy(dest, "IF", 3);
        
    } else {
        memcpy(dest, "ELSE", 5);
    }
    fprintf(stdout, "dest: '%s'\n", dest);
    return EXIT_SUCCESS;
}