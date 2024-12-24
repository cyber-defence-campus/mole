#include <stdio.h>
#include <stdlib.h>

FILE* open_file(const char* filename, const char* mode) {
    FILE *file = fopen(filename, mode);
    if (file == NULL) {
        fprintf(stderr, "Failed to open file\n");
    }
    return file;
}

char* allocate_buffer(size_t size) {
    char *buffer = (char *)malloc(size);
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
    }
    return buffer;
}

void read_file(FILE *file, char *buffer, size_t size) {
    fread(buffer, 1, size, file);
}

void print_buffer(const char *buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
    }
    printf("\n");
}

int main() {
    FILE *file = open_file("/dev/urandom", "rb");
    if (file == NULL) {
        return 1;
    }

    size_t padding = 10;
    size_t buffer_size = 20;
    char *buffer = allocate_buffer(buffer_size);
    if (buffer == NULL) {
        fclose(file);
        return 1;
    }

    read_file(file, buffer, buffer_size + padding);
    fclose(file);

    print_buffer(buffer, buffer_size);

    free(buffer);
    return 0;
}
