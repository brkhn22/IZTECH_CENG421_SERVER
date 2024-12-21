#ifndef USERS_H
#define USERS_H
#include "users.h"
#endif

void initialize_users(){
    user_count = 0;
}

int add_user(char name[], int socket){
    if (!user_name_validation(name)) return 0;
    if (index_of_user(name) >= 0) return 0;
    if(user_count == 0){
        user_map = malloc(sizeof(struct user_struct));
        if(user_map == NULL)
            return 0;
        strcpy(user_map[0].name, name);
        user_map[0].socket = socket;
    }else{
        user_map = realloc(user_map, sizeof(struct user_struct)*(user_count + 1));
        if(user_map == NULL)
            return 0;
        strcpy(user_map[user_count].name, name);
        user_map[user_count].socket = socket;
    }
    user_count += 1;
    return 1;
}

int remove_user(char name[]){
    int idx = index_of_user(name);
    if(idx < 0) return 0;
    if(idx == user_count-1)
        user_map = realloc(user_map, sizeof(struct user_struct)*(user_count - 1));
    else{
        for (int i = idx; i < user_count - 1; i++) 
            user_map[i] = user_map[i + 1];
        user_map = realloc(user_map, sizeof(struct user_struct)*(user_count - 1));
    }
    user_count -= 1;

    if (user_map == NULL && user_count > 0) {
        perror("Memory reallocation failed");
        exit(0);
    }

    return 1;

}

int remove_user_by_socket(int socket){
    int idx = index_of_user_by_socket(socket);
    if(idx < 0) return 0;
    if(idx == user_count-1)
        user_map = realloc(user_map, sizeof(struct user_struct)*(user_count - 1));
    else{
        for (int i = idx; i < user_count - 1; i++) 
            user_map[i] = user_map[i + 1];
        user_map = realloc(user_map, sizeof(struct user_struct)*(user_count - 1));
    }
    user_count -= 1;

    if (user_map == NULL && user_count > 0) {
        perror("Memory reallocation failed");
        exit(0);
    }

    return 1;

}

int index_of_user(char name[]){
    int i;
    if (!name) return -1;
    if (user_count <= 0) return -1;
    for(i = 0; i < user_count; i++){
        if(compare_strings(name, user_map[i].name))
            return i;
    }
    return -1;
}

int index_of_user_by_socket(int socket){
    int idx = -1;
    int i;
    if(user_count > 0){
        for(i = 0; i < user_count; i++){
            if(user_map[i].socket == socket){
                idx = i;
                break;
            }
        }
    }
    return idx;
}

int get_user_socket(char name[]){
    int idx = index_of_user(name);
    if(idx < 0) return -1;
    return user_map[idx].socket;
}

char* get_user_name(int socket){
    int idx = index_of_user_by_socket(socket);
    if(idx < 0) return NULL;
    return user_map[idx].name;
}

int user_name_validation(char *name){
    int i;
    int len;
    int result = 1;
    if(!name) return 0;
    len = strlen(name);
    if(len <= MIN_NAME_LEN || len > (MAX_NAME_LEN-1)) return 0;
    for(i = 0; i < len; i++){
        if(!((name[i] >= 'A' && name[i] <= 'Z') ||
        (name[i] >= 'a' && name[i] <= 'z') ||
        (name[i] >= '0' && name[i] <= '9') ||
         name[i] == '_' || name[i] == '#' || name[i] == '.')){
            result = 0;
            break;
         }
    }
    return result;
}


int compare_strings(char str1[], char str2[]){
    int i;
    int str1_len;
    int str2_len;
    if(!str1 || !str2) return 0;

    str1_len = strlen(str1);
    str2_len = strlen(str2);
    if(str1_len != str2_len) return 0;

    for(i = 0; i < str1_len; i++){
        if(tolower(str1[i]) != tolower(str2[i]))
            return 0; 
    }
    return 1;
}