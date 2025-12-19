#include <stdlib.h>
#include <string.h>

# define BUF_SIZE 64

/*
Testcase Description:
- Array element
*/

__attribute__ ((noinline, optimize("O0")))
int main(int argc, char * argv[])
{
    char data_buf[BUF_SIZE] = "ls";
    char* data = &data_buf[0];
    char* env_cmd = getenv("CMD");
    int data_len = strlen(data);
    if (env_cmd != NULL)
    {
        strncat(data+data_len, env_cmd, BUF_SIZE-data_len-1);
    }
    system(data);
    return 0;
}