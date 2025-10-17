#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 256

/*
Testcase Description:
- server example
- allow function inlining
*/

void handle_client(int client_socket);
void execute_cgi_command(const char *buffer);
void send_response(int client_socket, const char *response);
int create_server_socket(struct sockaddr_in *address);
void handle_get_request(int client_socket);
void handle_post_request(int client_socket);
char* receive_data(int client_socket, int *size);

int main() {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    server_fd = create_server_socket(&address);

    while (1) {
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            close(server_fd);
            exit(EXIT_FAILURE);
        }
        handle_client(client_socket);
    }

    close(server_fd);
    return 0;
}

void handle_client(int client_socket) {
    int size;
    char *method = receive_data(client_socket, &size);

    if (method == NULL) {
        close(client_socket);
        return;
    }

    if (strncmp(method, "GET ", 4) == 0) {
        handle_get_request(client_socket);
    } else if (strncmp(method, "POST", 4) == 0) {
        handle_post_request(client_socket);
    } else {
        send_response(client_socket, "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nMethod Not Allowed.\n");
        close(client_socket);
    }

    free(method);
}

void handle_get_request(int client_socket) {
    int size;
    char *buffer = receive_data(client_socket, &size);

    if (buffer == NULL) {
        close(client_socket);
        return;
    }

    execute_cgi_command(buffer);
    send_response(client_socket, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nGET request received.\n");
    close(client_socket);
    free(buffer);
}

void handle_post_request(int client_socket) {
    int size;
    char *buffer = receive_data(client_socket, &size);

    if (buffer == NULL) {
        close(client_socket);
        return;
    }

    execute_cgi_command(buffer);
    send_response(client_socket, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nPOST request received.\n");
    close(client_socket);
    free(buffer);
}

void execute_cgi_command(const char *buffer) {
    char *cgi_start = strstr(buffer, "/cgi-bin/");
    if (cgi_start) {
        cgi_start += strlen("/cgi-bin/");
        char *cgi_end = strchr(cgi_start, ' ');
        if (cgi_end) {
            *cgi_end = '\0';
            system(cgi_start);
        }
    }
}

void send_response(int client_socket, const char *response) {
    write(client_socket, response, strlen(response));
}

int create_server_socket(struct sockaddr_in *address) {
    int server_fd;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address->sin_family = AF_INET;
    address->sin_addr.s_addr = INADDR_ANY;
    address->sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)address, sizeof(*address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    return server_fd;
}

char* receive_data(int client_socket, int *size) {
    char *buffer = (char *)malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        perror("malloc");
        return NULL;
    }

    int bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_read < 0) {
        perror("recv");
        free(buffer);
        return NULL;
    }

    buffer[bytes_read] = '\0';
    *size = bytes_read;
    return buffer;
}