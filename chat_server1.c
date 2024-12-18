#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>

#define MAX_CLIENTS 32
#define MAIN_PORT 8080

int client_sockets[MAX_CLIENTS];

void* thread_proc(void *arg);
void* main_proc(void *arg);
void broadcastMessage(char buffer[], int *clientSocket);

pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

struct arg_struct {
    int sock;
    int child_size;
}args;

void handle_sigchld(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char *args[]){
    struct sockaddr_in serverAddr, clientAddr;
    int listensock;
    int newsock;
    int nPreChildren = 1;
    int nPreThread = 1;
    int x,y, val, pid;
    pthread_t thread_id;

    memset(client_sockets, 0, MAX_CLIENTS*sizeof(int));

    // get number of children for forkings and multithreads.
    if(argc > 2){ 
        nPreChildren = atoi(args[1]);
        nPreThread = atoi(args[2]);
        if(nPreChildren > 10) nPreChildren = 10;
        if(nPreThread > 32) nPreThread = 32;
    }

    struct sigaction sig;
    sig.sa_handler = handle_sigchld;
    sig.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sig, NULL);

    // create each prechildren as forkings.
    for (x = 0; x < nPreChildren; x++) {
        if ((pid = fork()) == 0) {
            int port = MAIN_PORT + x;
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(port);
            serverAddr.sin_addr.s_addr = INADDR_ANY;

            // create the socket
            listensock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            val = 1;
            if(setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0){
                perror("chat_server1");
                return 0;
            }

            // bind the socket with sockaddr
            if(bind(listensock, (struct sockaddr *) &serverAddr, sizeof(serverAddr))){
                perror("chat_server1");
                return 0;
            }

            // listen the socket
            if(listen(listensock, 5)  < 0){
               // fprintf(stderr, "chat_server1/%d",port);
                perror("chat_server1");
                return 0;
            }

            if(x == 0){
                for (y = 0; y < nPreThread; y++) {
                    struct arg_struct *arguments = malloc(sizeof(struct arg_struct));
                    arguments->child_size = nPreChildren;
                    arguments->sock = listensock;
                    if (pthread_create(&thread_id, NULL, main_proc, (void *) arguments) != 0) {
                        perror("chat_server1\n");
                    }else{
                        
                        sched_yield();
                        pthread_detach(thread_id);
                    }
                }
                
                
            }else{
                for (y = 0; y < nPreThread; y++) {
                    int* client_sock = malloc(sizeof(int));
                    *client_sock = listensock;
                    if (pthread_create(&thread_id, NULL, thread_proc, (void *) client_sock) != 0) {
                        //fprintf(stderr, "chat_server/%d",port);
                        perror("chat_server1\n");
                    }else{
                        sched_yield();
                        pthread_detach(thread_id);
                    }
                }
            }
            // create premultithreads for each prechildren forkings.

            // pthread_join (thread_id, NULL);
            pause();
        }
    }
    wait(NULL);
    close(listensock);
    return 0;
}

void* main_proc (void *arg){
    int listensock;
    int sock;
    char buffer[2000];
    int nread;
    int child_size;
    int i;
    struct arg_struct *arguments = (struct arg_struct *) arg;
    listensock = arguments->sock;
    child_size = arguments->child_size;
    free(arguments);
    snprintf(buffer, 2000, "Open Room List:\n");
    for(i = 1; i < child_size; i++){
        char portchar[20];
        snprintf(portchar,20,"Port: %i\n",i+MAIN_PORT);
        strcat(buffer, portchar);
    }
    printf("%s\n", buffer);
    while (1) {
        sock = accept(listensock, NULL, NULL);
        if(sock >= 0){
            printf("A client connected to the main server. Thread: %i, pid: #%i\n", pthread_self(), getpid());

            if (send(sock, buffer, strlen(buffer), 0) <= 0) {
                fprintf(stderr, "chat_server/%d", MAIN_PORT);
            }
            close(sock); // Dereference the socket pointer for closing
            printf("A client disconnected to the main server. Thread: %i, pid: #%i\n", pthread_self(), getpid());
        }
        sleep(1);
    }
}

void* thread_proc(void *arg)
{
    int listensock;
    int sock;
    char buffer[2000];
    int nread;
    listensock = *((int*) arg);
    free(arg);
    while (1) {
        sock = accept(listensock, NULL, NULL);
        if(sock >= 0){
            printf("client connected to child thread %i with pid %i.\n", pthread_self(), getpid());
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = sock;
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex);
            
            while((nread = recv(sock, buffer, 2000, 0)) > 0){
                printf("sock: %d\n", sock);
                buffer[nread] = '\0';
                broadcastMessage(buffer, &sock);
                sleep(1);
            }

            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_sockets[i] == sock) {
                    client_sockets[i] = 0;
                    close(sock); // Dereference the socket pointer for closing
                    printf("client disconnected from child thread %i with pid %i.\n", pthread_self(), getpid());
                    sock = -1;
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex); 
        }
    }
}

void broadcastMessage(char buffer[], int *clientSocket){ 
    int socket = *clientSocket;
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_sockets[i] != 0 && client_sockets[i] != socket) {
            if (send(client_sockets[i], buffer, strlen(buffer), 0) <= 0) {
                printf("Client socket %d disconnected. Removing from list.\n", client_sockets[i]);
                close(client_sockets[i]);
                client_sockets[i] = 0;
            } else {
                printf("Message sent to client socket %d.\n", client_sockets[i]);
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);

}