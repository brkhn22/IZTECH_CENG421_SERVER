#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>
#include "users.h"

#define MAIN_PORT 8080
#define MAX_HEADER_SIZE 2100

int client_sockets[MAX_USERS];

// prefixes
char prefix_authenticate[] = "/authenticate ";
char prefix_exit[] = "/exit";
char prefix_private[] = "/private ";

struct private_message {
    char *message;
    char *sender_name;
    int socket;
};

struct arg_struct {
    int sock;
    int child_size;
}args;

void* thread_proc(void *arg);
void* main_proc(void *arg);
void broadcastMessage(char buffer[], int *clientSocket);
void time_stamp_message(char *buffer, char name[]);
void free_private_message(struct private_message *pm);
int prefix_control(char prefix[], char buffer[]);


int user_authentication(char buffer[], int prefix_len, int socket);
int user_exit_authentication(char buffer[], int prefix_len, int socket);
int user_private_message(char buffer[], int prefix_len, int socket, struct private_message *pm);

pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;


void handle_sigchld(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char *args[]){
    struct sockaddr_in serverAddr, clientAddr;
    int listensock;
    int nPreChildren = 1;
    int nPreThread = 1;
    int x,y, val, pid;
    pthread_t thread_id;

    memset(client_sockets, 0, MAX_USERS*sizeof(int));

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
    char buffer[MAX_HEADER_SIZE];
    int nread;
    int child_size;
    int i;
    struct arg_struct *arguments = (struct arg_struct *) arg;
    listensock = arguments->sock;
    child_size = arguments->child_size;
    free(arguments);
    snprintf(buffer, MAX_HEADER_SIZE, "Open Room List:\n");
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
    char buffer[MAX_HEADER_SIZE];
    int nread;
    int authenticated = 0;
    int authentication_checker = 0;
    int prefix_len;
    struct private_message *pm = malloc(sizeof(struct private_message));
    listensock = *((int*) arg);
    free(arg);

    initialize_users();
    while (1) {
        sock = accept(listensock, NULL, NULL);
        if(sock >= 0){
            printf("client connected to child thread %i with pid %i.\n", pthread_self(), getpid());
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_USERS; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = sock;
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex);
            
            while((nread = recv(sock, buffer, MAX_HEADER_SIZE, 0)) > 0){
                buffer[nread-1] = '\0';
                if(buffer[0] == '/'){
                    // the client communicates with the server
                    if(prefix_control(prefix_authenticate, buffer)){
                        if(authenticated){
                            strcpy(buffer, "You have already been authenticated!");
                            time_stamp_message(buffer, SERVER);
                            send(sock, buffer, strlen(buffer), 0);
                        }else{
                            // authenticaton is selected.
                            prefix_len = strlen(prefix_authenticate);
                            authentication_checker = user_authentication(buffer, prefix_len, sock);
                            if(authentication_checker){
                                authenticated = authentication_checker;
                                strcpy(buffer, "Authentication is done!");
                                time_stamp_message(buffer, SERVER);
                                send(sock, buffer, strlen(buffer), 0);
                            }else {
                                authenticated = 0;
                                strcpy(buffer, "Authentication is failed!");
                                time_stamp_message(buffer, SERVER);
                                send(sock, buffer, strlen(buffer), 0);
                            }
                        }
                        
                    }else if(prefix_control(prefix_exit, buffer)){
                        prefix_len = strlen(prefix_exit);
                        if(authenticated && user_exit_authentication(buffer, prefix_len, sock)){
                            authenticated = 0;
                            strcpy(buffer, "Authentication is removed!");
                            time_stamp_message(buffer, SERVER);
                            send(sock, buffer, strlen(buffer), 0);
                        
                        }else if(!authenticated) {
                            strcpy(buffer, "Authentication is already not exist!");
                            time_stamp_message(buffer, SERVER);
                            send(sock, buffer, strlen(buffer), 0);
                        }
                    }else if(prefix_control(prefix_private, buffer)){
                        prefix_len = strlen(prefix_private);
                        if(!authenticated){
                            strcpy(buffer, "Only authenticated users can do private message!");
                            time_stamp_message(buffer, SERVER);
                            send(sock, buffer, strlen(buffer), 0);
                        }else{
                            // valid private message example is /private name message
                            if(user_private_message(buffer, prefix_len, sock, pm)){
                                snprintf(buffer, MAX_HEADER_SIZE, "[private] %s", pm->message);
                                printf("%s\n", buffer);
                                time_stamp_message(buffer, pm->sender_name);
                                send(pm->socket, buffer, strlen(buffer), 0);
                                if (pm->message) {
                                    free(pm->message);
                                    pm->message = NULL;
                                }
                            }else{
                                strcpy(buffer, "Private message could not be sent!");
                                time_stamp_message(buffer, SERVER);
                                send(sock, buffer, strlen(buffer), 0);
                            }
                        }
                    }
                }else{
                    if(!authenticated) {
                        // user has  not been authenticated.
                        time_stamp_message(buffer, ANONYMOUS);
                        broadcastMessage(buffer, &sock);
                    } else {
                        // user has been authenticated.
                        char *name = get_user_name(sock);
                        time_stamp_message(buffer, name);
                        broadcastMessage(buffer, &sock);
                    }
                }
                sleep(1);
            }

            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_USERS; i++) {
                if (client_sockets[i] == sock) {
                    client_sockets[i] = 0;
                    free_private_message(pm);
                    remove_user_by_socket(sock);
                    authenticated = 0;
                    authentication_checker = 0;
                    close(sock);
                    printf("client disconnected from child thread %i with pid %i.\n", pthread_self(), getpid());
                    sock = -1;
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex); 
        }
    }
}

int user_private_message(char buffer[], int prefix_len, int socket, struct private_message *pm){
    int buffer_len = strlen(buffer);
    char *name_p = &buffer[prefix_len];
    char *message_p = strchr(name_p, ' ');
    if(message_p == NULL) return 0;

    int idx = (int)(message_p - name_p);
    if(idx <= 0) return 0;
    char name [MAX_NAME_LEN];
    int i = 0;
    while(name_p < message_p){
        name[i] = *name_p;
        name_p += 1;
        i++;
    }
    name[i] = '\0';
    
    char *sender_name;
    int target_socket;
    if((target_socket = get_user_socket(name)) < 0) return 0;
    if((sender_name = get_user_name(socket)) == NULL) return 0;
    
    message_p += 1;
    int message_len = strlen(message_p);
    pm->message = malloc((message_len + 1) * sizeof(char));
    strncpy(pm->message, message_p, message_len);
    pm->message[message_len] = '\0';

    pm->sender_name = sender_name;
    pm->socket = target_socket;
    printf("%s, %s, %d\n", pm->message, pm->sender_name, pm->socket);
    return 1;
}

int prefix_control(char prefix[], char buffer[]){

    int prefix_len = strlen(prefix);
    if(strncmp(buffer, prefix, prefix_len) == 0) return 1;

    return 0;
}

int user_authentication(char buffer[], int prefix_len, int socket){
    int buffer_len = strlen(buffer);
    int name_len = buffer_len - prefix_len;
    if(name_len >= MIN_NAME_LEN && name_len < MAX_NAME_LEN){
        // name is in valid length.
        char *name = malloc(sizeof(char)*MAX_NAME_LEN);
        strcpy(name, buffer+prefix_len);
        if(strstr(name, " ") == NULL){
            return add_user(name, socket);
        }
        return 0;  
    }
    return 0;
}

int user_exit_authentication(char buffer[], int prefix_len, int socket){
    if((strlen(buffer) - prefix_len) > 0) return 0;

    return remove_user_by_socket(socket);
}

void broadcastMessage(char buffer[], int *clientSocket){ 
    int socket = *clientSocket;
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_USERS; i++) {
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

void time_stamp_message(char *buffer, char name[]){
    time_t now = time(NULL);
    struct tm *time_info = localtime(&now);
    char time_stamp[50];
    char temp_buffer[MAX_HEADER_SIZE];

    strftime(time_stamp, sizeof(time_stamp), "%d/%m/%Y, %H:%M:%S", time_info);
    snprintf(temp_buffer, MAX_HEADER_SIZE, "[%s] %s: %s\n", time_stamp, name,  buffer);
    strncpy(buffer, temp_buffer, MAX_HEADER_SIZE);
    printf("%s\n", buffer);
}

void free_private_message(struct private_message *pm){
    if(pm){
        if (pm->message) {
            free(pm->message);
            pm->message = NULL;
        }
        free(pm);
    }

}