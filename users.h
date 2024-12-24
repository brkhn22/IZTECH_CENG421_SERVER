#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX_USERS 32
#define MAX_NAME_LEN 50
#define MIN_NAME_LEN 3
#define MAX_REQUEST 50
#define ANONYMOUS "anonymous"
#define SERVER "server"
#define REGISTER_FILE "registered_users.txt"
#define REQUEST_FILE "requests_list.txt"
#define ACCEPT_FILE "accepts_list.txt"


struct user_struct {
    char name[MAX_NAME_LEN]; // name should be unique
    int socket;
} typedef user;

user *user_map;
int user_count;

int compare_strings(char str1[], char str2[]);

void initialize_users();
int user_name_validation(char *name);
int add_user(char name[], int socket);
int remove_user(char name[]);
int remove_user_by_socket(int socket);
int index_of_user(char name[]);
int index_of_user_by_socket(int socket);
int get_user_socket(char name[]);
char* get_user_name(int socket);
