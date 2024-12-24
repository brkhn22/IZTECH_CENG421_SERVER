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
char prefix_online[] = "/online";
char prefix_register[] = "/register ";
char prefix_request[] = "/request ";
char prefix_accept[] = "/accept ";

struct register_struct { // this is used for requesting too, for they got same size char sequences.
    char *name; // name should be unique
    char *password; 
};

struct request_struct {
    char *data;
    int line;
    int count;
};

struct private_message {
    char *message;
    char *sender_name;
    int socket;
};

struct arg_struct {
    int sock;
    int child_size;
};

void* thread_proc(void *arg);
void* main_proc(void *arg);
void broadcast_message(char buffer[], int *clientSocket);
void time_stamp_message(char *buffer, char name[]);
void free_private_message(struct private_message *pm);

int prefix_control(char prefix[], char buffer[]);
char * user_online();
int user_name_control(char name[]);

int user_authentication (char name[], char password[], int socket);
int user_exit_authentication(char buffer[], int prefix_len, int socket);
int user_private_message(char buffer[], int prefix_len, int socket, struct private_message *pm);


int user_register(char buffer[], int prefix_len, struct register_struct *us);
int user_registration_control(char name[]);
int user_register_append(char name[], char password[]);

int user_request(char buffer[], int prefix_len, int socket, struct register_struct *us);
int user_request_control(char *sender_name, char *target_name, struct request_struct *rs);
int user_request_rewrite_append(char *sender_name, char *target_name, char data[], int line, int count);
int user_request_rewrite_remove(char *sender_name, char *target_name, char data[], int line, int count);
int user_request_append(char *target_name);

int user_accept(char buffer[], int prefix_len, int socket, struct register_struct *us);
int user_accept_append(char *target_name);

int server_registration_failed(char buffer [], int socket);

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
            serverAddr.sin_addr.s_addr = inet_addr("0.0.0.0");

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
    printf("Thread %i with pid: #%i listening the port %d!\n", pthread_self(), getpid(), MAIN_PORT);
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
    printf("Thread %i with pid: #%i is not listening the port %d anymore!\n", pthread_self(), getpid(), MAIN_PORT);
}

void* thread_proc(void *arg)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int listensock;
    int sock;
    char buffer[MAX_HEADER_SIZE];
    int nread;
    int authenticated = 0;
    int authentication_checker = 0;
    int prefix_len;
    struct private_message *pm = malloc(sizeof(struct private_message));
    struct request_struct *rs = malloc(sizeof(struct request_struct));
    struct register_struct *us = malloc(sizeof(struct register_struct));
    listensock = *((int*) arg);
    free(arg);

    if(getsockname(listensock, (struct sockaddr *)&addr, &addr_len) == -1) return 0;
    int port = ntohs(addr.sin_port);

    printf("Thread %i with pid: #%i listening the port %d!\n", pthread_self(), getpid(), port);
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
                buffer[strcspn(buffer, "\r\n")] = '\0';
                if(buffer[0] == '/'){
                    // the client communicates with the server
                    if(prefix_control(prefix_authenticate, buffer)){
                        if(authenticated){
                            strcpy(buffer, "You have already been authenticated!");
                            time_stamp_message(buffer, SERVER);
                            send(sock, buffer, strlen(buffer), 0);
                        }else{
                            // authenticaton is selected.
                            // valid authentication type is /authenticate name password.
                            // start like registration for they have the same type.
                            prefix_len = strlen(prefix_authenticate);
                            if(user_register(buffer, strlen(prefix_authenticate), us)){
                                authentication_checker = user_authentication(us->name, us->password, sock);
                                if(authentication_checker){
                                    authenticated = authentication_checker;
                                    strcpy(buffer, "Authentication is done!");
                                    time_stamp_message(buffer, SERVER);
                                    send(sock, buffer, strlen(buffer), 0);
                                }else{
                                    authenticated = 0;
                                    strcpy(buffer, "Authentication is failed!");
                                    time_stamp_message(buffer, SERVER);
                                    send(sock, buffer, strlen(buffer), 0);
                                }
                                free(us->name);
                                free(us->password);
                            }else{
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
                        
                        }else if(!authenticated){
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
                                time_stamp_message(buffer, pm->sender_name);
                                if(send(pm->socket, buffer, strlen(buffer), 0))
                                    printf("Private message has been sent to %d socket\n", pm->socket);
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
                    }else if(prefix_control(prefix_online, buffer)){
                        // get online list of the server
                        char *user_list = user_online();
                        strcpy(buffer, user_list);
                        time_stamp_message(buffer, SERVER);
                        send(sock, buffer, strlen(buffer), 0);
                        free(user_list);
                    }else if(prefix_control(prefix_register, buffer)){
                        if(!authenticated){
                            // valid registration type is /register name password
                            prefix_len = strlen(prefix_register);
                            if(user_register(buffer, prefix_len, us)){
                                // us successfully get name and password.
                                if(!user_registration_control(us->name)){
                                    pthread_mutex_lock(&clients_mutex);
                                    if(user_register_append(us->name, us->password)){
                                        if(user_request_append(us->name) && user_accept_append(us->name)){
                                            // requests list has been appended
                                            strcpy(buffer, "Registration has been succeded!");
                                            time_stamp_message(buffer, SERVER);
                                            send(sock, buffer, strlen(buffer), 0);
                                        }
                                    }else{
                                        if(!server_registration_failed(buffer, sock))
                                            break;
                                    }
                                    pthread_mutex_unlock(&clients_mutex);
                                }else{
                                    if(!server_registration_failed(buffer, sock))
                                        break;
                                }
                                free(us->name);
                                free(us->password);
                            }else{
                                if(!server_registration_failed(buffer, sock))
                                    break;
                            }
                            
                        }else{
                            if(!server_registration_failed(buffer, sock))
                                break;
                        }
                                
                        

                    }else if(prefix_control(prefix_request, buffer)){
                        prefix_len = strlen(prefix_request);
                        if(user_request(buffer, prefix_len, sock, us)){
                            if(user_request_control(us->name, us->password, rs)) {
                                // user have not send any request
                                if(user_request_rewrite_append(us->name, us->password, rs->data, rs->line, rs->count)) {
                                    strcpy(buffer, "Request has been sent!");
                                    time_stamp_message(buffer, SERVER);
                                    send(sock, buffer, strlen(buffer), 0);
                                }
                                free(rs->data);
                                rs->line = 0;
                                rs->count = 0;
                            }

                            free(us->name);
                            free(us->password);
                        }
                    }else if(prefix_control(prefix_accept, buffer)){
                        prefix_len = strlen(prefix_accept);
                        if(user_accept(buffer, prefix_len, sock, us)){
                            if(!user_request_control(us->name, us->password, rs)) {
                                // an user have sent a request
                                if(user_request_rewrite_remove(us->name, us->password, rs->data, rs->line, rs->count)){
                                    printf("request is successfully removed!\n");
                                }
                                free(rs->data);
                                rs->line = 0;
                                rs->count = 0;
                              /*  if(user_accept_control(us->name, us->password, rs)){
                                    if(user_accept_rewrite_append()){
                                        
                                    }
                                } */
                            }

                            free(us->name);
                            free(us->password);
                        }
                    }
                }else{
                    if(!authenticated) {
                        // user has  not been authenticated.
                        time_stamp_message(buffer, ANONYMOUS);
                        broadcast_message(buffer, &sock);
                    } else {
                        // user has been authenticated.
                        char *name = get_user_name(sock);
                        time_stamp_message(buffer, name);
                        broadcast_message(buffer, &sock);
                    }
                }
            //    sleep(1);
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
    printf("Thread %i with pid: #%i is not listening the port %d anymore!\n", pthread_self(), getpid(), port);
}

int server_registration_failed(char buffer [], int socket){
    strcpy(buffer, "Registration has been failed!");
    time_stamp_message(buffer, SERVER);
    return send(socket, buffer, strlen(buffer), 0);
}

int user_accept_rewrite_append(char *sender_name, char *target_name, char data[], int line, int count){
    if(!sender_name || !target_name) return 0;

    FILE *file = fopen(ACCEPT_FILE, "r");
    if(!file) return 0;
    FILE *temp_file = fopen("temp_accepts.txt", "w");
    if(!temp_file) return 0;

    int line_len = MAX_NAME_LEN*(MAX_REQUEST+2);
    char temp_line[line_len];
    int counter = 1;
    int i;
    int data_len = strlen(data);
    if(count > 0){
        data[data_len-2] = ' ';
        for(i = 0; i < strlen(sender_name); i++)
            data[i+data_len-1] = sender_name[i];
        data[i+data_len-1] = '}';
        data[i+data_len] = '\0';
    }else{
        for(i = 0; i < strlen(sender_name); i++)
            data[i+data_len-2] = sender_name[i];
        data[i+data_len-2] = '}';
        data[i+data_len-1] = '\0';
    }

    while (fgets(temp_line, sizeof(temp_line), file)) {
        if (counter == line) {
            // Replace the specific line with updated data
            fprintf(temp_file, "%s\n", data);
        } else {
            // Copy the existing line
            fputs(temp_line, temp_file);
        }
        counter++;
    }

    fclose(file);
    fclose(temp_file);

    // Replace the original file with the updated temp file
    remove(ACCEPT_FILE);
    rename("temp_accepts.txt", ACCEPT_FILE);
    return 1;
}

int user_accept(char buffer[], int prefix_len, int socket, struct register_struct *us){
    char *name_p;
    int buffer_len = strlen(buffer);
    name_p = &buffer[prefix_len];
    if(name_p == NULL) return 0;
    int name_len = buffer_len - prefix_len;
    if(name_len <= 0) return 0;
    int i = 0;
    char sender_name[MAX_NAME_LEN];

    while(i < name_len){
        sender_name[i] = *name_p;
        name_p++;
        i++;
    }
    sender_name[i] = '\0';
    if(!user_name_validation(sender_name)) return 0;
    char *target_name = get_user_name(socket);
    if(target_name == NULL) return 0;
    if(compare_strings(target_name, sender_name)) return 0; // cannot accept request to themselves.
    if(!user_registration_control(sender_name)) return 0; // sender user must be registered.

    us->name = malloc(strlen(sender_name)*sizeof(char));
    if(!us->name) return 0;
    us->password = malloc(name_len*sizeof(char));
    if(!us->password) return 0;
    strcpy(us->name, sender_name);
    strcpy(us->password, target_name);

    return 1;

}

int user_accept_append(char *target_name){
    if(!target_name) return 0;
    // new registered users added to the requests_list file.
    FILE *file = fopen(REQUEST_FILE, "a");
    if(!file) return 0;
    int line_len = MAX_NAME_LEN+3;
    char line[line_len];
    sprintf(line,"%s {}",target_name);
    fprintf(file, "%s\n", line);
    fclose(file);
    return 1;
}

int user_request(char buffer[], int prefix_len, int socket, struct register_struct *us){
    char *name_p;
    int buffer_len = strlen(buffer);
    name_p = &buffer[prefix_len];
    if(name_p == NULL) return 0;
    int name_len = buffer_len - prefix_len;
    if(name_len <= 0) return 0;
    int i = 0;
    char target_name[MAX_NAME_LEN];

    while(i < name_len){
        target_name[i] = *name_p;
        name_p++;
        i++;
    }
    target_name[i] = '\0';
    if(!user_name_validation(target_name)) return 0;
    char *sender_name = get_user_name(socket);
    if(sender_name == NULL) return 0;
    if(compare_strings(sender_name, target_name)) return 0; // cannot send request to themselves.
    if(!user_registration_control(target_name)) return 0; // target user must be registered.

    us->name = malloc(strlen(sender_name)*sizeof(char));
    if(!us->name) return 0;
    us->password = malloc(name_len*sizeof(char));
    if(!us->password) return 0;
    strcpy(us->name, sender_name);
    strcpy(us->password, target_name);

    return 1;
}

int user_request_rewrite_remove(char *sender_name, char *target_name, char data[], int line, int count){
    if(!sender_name || !target_name) return 0;
    if(count <= 0) return 0;

    FILE *file = fopen(REQUEST_FILE, "r");
    if(!file) return 0;
    FILE *temp_file = fopen("temp_requests.txt", "w");
    if(!temp_file) return 0;

    int line_len = MAX_NAME_LEN*(MAX_REQUEST+2);
    char temp_line[line_len];
    int counter = 1;
    int i;
    int data_len = strlen(data);
    int sender_len = strlen(sender_name);
    char *point, *temp_point;
    point = strstr(data, sender_name);
    
    if((point + sender_len+2) == (data+data_len)){
        if(*(point-1)==' '){
            *(point-1) = '}';
            *(point) = '\0'; 
        }else{
            *point = '}';
            *(point+1) = '\0'; 
        }
    }else{
        while(point < (data+data_len-1)){
            *point = *(point+sender_len+1);
            point++;
        }
    }
    
    while (fgets(temp_line, sizeof(temp_line), file)) {
        if (counter == line) {
            // Replace the specific line with updated data
            fprintf(temp_file, "%s\n", data);
        } else {
            // Copy the existing line
            fprintf(temp_file,"%s", temp_line);
        }
        counter++;
    }

    fclose(file);
    fclose(temp_file);

    // Replace the original file with the updated temp file
    remove(REQUEST_FILE);
    rename("temp_requests.txt", REQUEST_FILE);
    return 1;

}

int user_request_rewrite_append(char *sender_name, char *target_name, char data[], int line, int count){
    if(!sender_name || !target_name) return 0;

    FILE *file = fopen(REQUEST_FILE, "r");
    if(!file) return 0;
    FILE *temp_file = fopen("temp_requests.txt", "w");
    if(!temp_file) return 0;

    int line_len = MAX_NAME_LEN*(MAX_REQUEST+2);
    char temp_line[line_len];
    int counter = 1;
    int i;
    int data_len = strlen(data);
    if(count > 0){
        data[data_len-2] = ' ';
        for(i = 0; i < strlen(sender_name); i++)
            data[i+data_len-1] = sender_name[i];
        data[i+data_len-1] = '}';
        data[i+data_len] = '\0';
    }else{
        for(i = 0; i < strlen(sender_name); i++)
            data[i+data_len-2] = sender_name[i];
        data[i+data_len-2] = '}';
        data[i+data_len-1] = '\0';
    }

    while (fgets(temp_line, sizeof(temp_line), file)) {
        if (counter == line) {
            // Replace the specific line with updated data
            fprintf(temp_file, "%s\n", data);
        } else {
            // Copy the existing line
            fputs(temp_line, temp_file);
        }
        counter++;
    }

    fclose(file);
    fclose(temp_file);

    // Replace the original file with the updated temp file
    remove(REQUEST_FILE);
    rename("temp_requests.txt", REQUEST_FILE);
    return 1;
}

int user_request_control(char *sender_name, char *target_name, struct request_struct *rs){
    // this function returns the line of target's request list.
    if(!sender_name || !target_name) return 0;
    

    FILE *file = fopen(REQUEST_FILE, "r");
    if(!file) return 0;
    int result = 1;
    int line_len = MAX_NAME_LEN*(MAX_REQUEST+2);
    char temp_line[line_len];
    char temp_target_name [MAX_NAME_LEN];
    char temp_sender_name [MAX_NAME_LEN];
    int i;
    int j;
    int count = 0;
    int line = 0;

    while(fgets(temp_line, line_len, file)){
        sscanf(temp_line, "%s {", temp_target_name);
        line++;
        if(compare_strings(temp_target_name, target_name)){
            i = strlen(temp_target_name)+2;
            j = 0;
            while(temp_line[i] != '}'){
                while(temp_line[i] != ' ' && temp_line[i] != '}'){
                    temp_sender_name[j] = temp_line[i];
                    i++;
                    j++;
                }
                temp_sender_name[j] = '\0';
                
                count++;
                if(count >= MAX_REQUEST){
                    fclose(file);
                    return 0;  // no room for requesting
                }

                if(compare_strings(temp_sender_name, sender_name)){
                    // a request has already been sent
                    result = 0;
                }
                j = 0;
                if(temp_line[i] == ' ') i++;
            }
            break;
        }
    }
    fclose(file);

    rs->data = malloc(strlen(temp_line)+strlen(temp_sender_name)+1);
    if(rs->data == NULL) return 0;
    strcpy(rs->data, temp_line);
    rs->line = line;
    rs->count = count;
    return result;
}

int user_request_append(char *target_name){
    if(!target_name) return 0;
    // new registered users added to the requests_list file.
    FILE *file = fopen(REQUEST_FILE, "a");
    if(!file) return 0;
    int line_len = MAX_NAME_LEN+3;
    char line[line_len];
    sprintf(line,"%s {}",target_name);
    fprintf(file, "%s\n", line);
    fclose(file);
    return 1;
}

int user_register(char buffer[], int prefix_len, struct register_struct *us) {
    char *name_p;
    char *password_p;

    int buffer_len = strlen(buffer);
    name_p = &buffer[prefix_len];
    password_p = strchr(name_p, ' ');
    if(password_p == NULL) return 0;
    int idx = (int)(password_p - name_p);
    if(idx <= 0) return 0;

    int i = 0;
    char name[MAX_NAME_LEN];
    char password[MAX_NAME_LEN];
    int name_len, password_len;
    while(name_p < password_p ){
        if(i >= MAX_NAME_LEN) return 0;
        name[i] = *name_p;
        name_p += 1;
        i++;
    }
    name_len = i;
    name[i] = '\0';

    i = 0;
    password_p += 1;
    while( *password_p != '\0' ) {
        if(i >= MAX_NAME_LEN) return 0;
        password[i] = *password_p;
        password_p += 1;
        i++;
    }
    password[i] = '\0';
    password_len = i;
    if(!user_name_validation(name)) return 0;
    if(!user_name_validation(password)) return 0;
    
    us->name = malloc((name_len + 1) * sizeof(char));
    if(!name) return 0;
    us->password = malloc((password_len + 1) * sizeof(char));
    if(!password) return 0;

    strncpy(us->password , password, password_len);
    strncpy(us->name, name, name_len);
    us->name[name_len] = '\0';
    us->password[password_len] = '\0';
    return 1;
    
}

int user_registration_control(char name[]){
    if(!name) return 0;

    FILE *file = fopen(REGISTER_FILE, "r");
    if(!file) return 0;

    int line_len = MAX_NAME_LEN*3;
    char line[line_len];
    char temp_name[MAX_NAME_LEN];
    while(fgets(line, line_len, file)){
        sscanf(line, "%s ", temp_name);
        if(compare_strings(temp_name, name)){ // the name has already been registered.
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;

}

int user_register_append(char name[], char password[]){
    if(!name || !password) return 0;

    FILE *file = fopen(REGISTER_FILE, "a");
    if(!file) return 0;

    int line_len = MAX_NAME_LEN*3;
    char line[line_len];
    snprintf(line, line_len, "%s %s", name, password);
    fprintf(file, "%s\n", line);
    fclose(file);
    return 1;
}

char * user_online(){
    char *name;
    char *name_list= malloc(MAX_NAME_LEN*(user_count + 2)); 
    char names[MAX_NAME_LEN*(user_count + 1)];
    int count = 0;
    int point = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if(client_sockets[i]){
            name = get_user_name(client_sockets[i]);
            if(name != NULL){
                strcpy(names+point, name);
                point += strlen(name);
                names[point] = ',';
                names[++point] = ' ';
                ++point;
            }
            count++;
        }
    }
    names[point-2] = '\0';
    sprintf(name_list, "[%d] Online List: %s", count, names);
    
    return name_list;
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
    return 1;
}

int prefix_control(char prefix[], char buffer[]){

    int prefix_len = strlen(prefix);
    if(strncmp(buffer, prefix, prefix_len) == 0) return 1;

    return 0;
}

int user_authentication(char name[], char password[], int socket) {
    int result = 0;

    FILE *file = fopen(REGISTER_FILE, "r");
    if(!file) return result;

    int line_len = MAX_NAME_LEN*3;
    char line[line_len];
    char temp_name[MAX_NAME_LEN];
    char temp_password[MAX_NAME_LEN];

    while(fgets(line, line_len, file)){
        sscanf(line, "%s %s", temp_name, temp_password);
        if(compare_strings(temp_name, name)){
            // the name is exist
            if(compare_strings(temp_password, password)){
                result = 1;
            }
            break;
        }
    }

    fclose(file);
    if(result){
        pthread_mutex_lock(&clients_mutex);
        result = add_user(name, socket);
        pthread_mutex_unlock(&clients_mutex);
    }

    return result;
}

int user_exit_authentication(char buffer[], int prefix_len, int socket){
    if((strlen(buffer) - prefix_len) > 0) return 0;

    return remove_user_by_socket(socket);
}

void broadcast_message(char buffer[], int *clientSocket){ 
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
    snprintf(temp_buffer, MAX_HEADER_SIZE, "[%s] %s: %s\r\n", time_stamp, name,  buffer);
    strncpy(buffer, temp_buffer, MAX_HEADER_SIZE);
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
