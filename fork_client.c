#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>

#define MAIN_PORT 8080

#define MAX_MESSAGE_SIZE 2000

int main() {
    int sock;
    struct sockaddr_in serverAddr;
    char buffer[MAX_MESSAGE_SIZE];
    pthread_t receive_thread, send_thread;
    int nread;
    fd_set read_write_set, testset;
    int x;
    int port = MAIN_PORT;

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Set up the server address structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);  // Server port
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  // Server address (localhost)

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Connection to server failed");
        close(sock);
        return -1;
    }

    FD_ZERO(&read_write_set);
    FD_SET(sock, &read_write_set);
    FD_SET(STDIN_FILENO, &read_write_set);
    fflush(stdout);
    while (1) {

        // Receive message from the server
        testset = read_write_set;
        if (select(FD_SETSIZE, &testset, NULL, NULL, NULL) < 1) {
            perror("chat_server1");
            return 0;
        }

        if(port == MAIN_PORT){
            if (FD_ISSET(sock, &testset)) {
                nread = recv(sock, buffer, MAX_MESSAGE_SIZE, 0);
                if (nread > 0) {
                    buffer[nread] = '\0';  // Null-terminate the received message
                    printf("%s", buffer);
                    printf("Please enter the port number \n");
                    fflush(stdout);
                    FD_CLR(sock, &read_write_set);
                    close(sock);
                } 
            }

            if (FD_ISSET(STDIN_FILENO, &testset)) {
                // Read user input
                if (fgets(buffer, MAX_MESSAGE_SIZE, stdin) != NULL) {
                    port = atoi(buffer);
                    printf("%d\n", port);

                    // Create socket
                    sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (sock < 0) {
                        perror("Socket creation failed");
                        return -1;
                    }
                    // Set up the server address structure
                    serverAddr.sin_family = AF_INET;
                    serverAddr.sin_port = htons(port);  // Server port
                    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  // Server address (localhost)
                    // Connect to the server
                    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
                        perror("Connection to server failed");
                        close(sock);
                        return -1;
                    }
                    FD_SET(sock, &read_write_set);             
                }
            }
        }else if (port > MAIN_PORT){
            if (FD_ISSET(sock, &testset)) {
                nread = recv(sock, buffer, MAX_MESSAGE_SIZE, 0);
                if (nread > 0) {
                    buffer[nread] = '\0';  // Null-terminate the received message
                    printf("%s", buffer);
                }
            }

            if (FD_ISSET(STDIN_FILENO, &testset)) {
                if(fgets(buffer, MAX_MESSAGE_SIZE, stdin) != NULL){
                    nread = strlen(buffer);
                    buffer[nread] = '\n';
                    if(send(sock, buffer, nread, 0) <= 0){
                        printf("The server socket %d disconnected.\n", sock);
                        break;
                    }
                }
            }
        }
    }
    // Close the socket after exiting
    wait(NULL);
    close(sock);
    printf("Disconnected from server.\n");
    return 0;
}