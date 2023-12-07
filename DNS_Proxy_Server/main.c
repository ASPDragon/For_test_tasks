#include "utility.h"

int main(int argc, const char *argv[]) {
    if (argc < 2) {
        printf("%s\n", "Error: Invalid number of arguments!");
        printf("%s\n", "proxy <config file name>");
        return 1;
    }

    const char *name = argv[0];

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int dns_server_port;
    struct in_addr ip;
    struct in_addr dns_server_ip;
    char *upstr = "upstream\0";
    char *blklst = "blacklist\0";
    char *address = "";
    char *blacklist[2];

    // Reading of the file and getting configuration
    FILE* f;
    f = fopen(argv[1], "r");

    if (f == NULL)
        exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, f)) != -1) {
        if (starts_with(line, upstr)) {
            address = substr(line, strlen(upstr) + 1, strlen(line) + 1);
            char delim[] = " ";
            posix_unwrap(inet_pton(AF_INET, strtok(address, delim), &dns_server_ip), "");
            dns_server_port = atoi(strtok(NULL, delim));
        }
        else  if (starts_with(line, blklst)) {
            char *lst = substr(line, strlen(blklst) + 1, strlen(line) + 1);
            char delim[] = " ";
            blacklist[0] = strtok(lst, delim);
            blacklist[1] = strtok(NULL, delim);
        }
    }

    printf("%s", line);

    fclose(f);

    int incoming_connection_sock = posix_unwrap(socket(AF_INET, SOCK_DGRAM, 0), "socket");
    posix_unwrap(inet_pton(AF_INET, "127.0.0.1", &ip), "");
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(4444),
        .sin_addr = ip,
        .sin_zero = 0,
    };

    posix_unwrap(bind(incoming_connection_sock, 
                     (struct sockaddr*)(&addr), sizeof(addr)), "bind");

    int dns_server_socket = posix_unwrap(socket(AF_INET, SOCK_DGRAM, 0), "socket");
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(dns_server_port),
        .sin_addr = dns_server_ip,
        .sin_zero = 0,
    };

    char buffer[256] = {0};
    struct sockaddr_in client_address = {0};
    socklen_t client_address_len = sizeof(struct sockaddr_in);
    ssize_t recv_len;
    ssize_t recv_len_1;

    while (true) {
            recv_len = posix_unwrap(recvfrom(incoming_connection_sock, buffer, sizeof(buffer), 0, 
                                (struct sockaddr*)(&client_address), &client_address_len), "recvfrom");

            if (recv_len > 0) {
                if (!is_blacklisted(incoming_connection_sock, blacklist, 2)){
                    for (int i = 0; i < recv_len; ++i)
                        printf("%c", buffer[i]);
                    putchar('\n');
                    posix_unwrap(sendto(dns_server_socket, buffer, recv_len, 0, 
                      (const struct sockaddr*)(&server_addr), client_address_len), "send1");
                }
                else {
                    posix_unwrap(sendto(incoming_connection_sock, line, recv_len_1, 0, 
                      (const struct sockaddr*)(&client_address), client_address_len), "send");
                }
            }

            recv_len_1 = posix_unwrap(recvfrom(dns_server_socket, buffer, sizeof(buffer), 0, 
                                (struct sockaddr*)(&server_addr), &client_address_len), "recvfrom");

            if (recv_len_1 > 0) {
                posix_unwrap(sendto(incoming_connection_sock, buffer, recv_len_1, 0, 
                      (const struct sockaddr*)(&client_address), client_address_len), "send2");
            }
    }
}
