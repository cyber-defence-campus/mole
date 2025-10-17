#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUF_SIZE 16

/*
Testcase Description:
- getopt param ends up in a call to strcpy

Testcase Analysis (linux-x86_64):
- Backward slicing ends in:
  ```
  0x4010f5 src#3 = [0x404020] (MediumLevelILSetVarSsa)
  0x4010f5 [0x404020] (MediumLevelILImport)
  ```
- This corresponds to the source code line:
  ```
  src = optarg;
  ```
- `optarg` is an (external) global variable defined in the `.bss` section:
  ```
  .bss (NOBITS) section started  {0x404020-0x404030}
  00404020  char* optarg = 0x0
  ```
- Our current **pointer analysis** implementation is not able to track global variables. More specifically for the listed example, slicing does not enter `getopt`, since it does not explicitely get `optarg` as a function parameter.
*/

// External global variable defined in libc
extern char* optarg;

int main(int argc, char *argv[]) {
    int opt;
    char dest[BUF_SIZE];
    char *src = NULL;
    
    // Parse command-line options
    while ((opt = getopt(argc, argv, "s:")) != -1) {
        switch (opt) {
            case 's':
                src = optarg;
                break;
            default:
                return EXIT_FAILURE;
        }
    }
    // Copy src to dest
    if (src != NULL) {
        strcpy(dest, src);
        printf("dest: '%s'\n", dest);
    }
    return EXIT_SUCCESS;
}