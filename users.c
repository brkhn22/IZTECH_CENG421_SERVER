#include "users.h"

void initialize_users(){
    user_count = 0;
}

int add_user(char name[], int socket){
    if (index_of_user(name) > -1) return 0;
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
    int idx = -1;
    int i;
    int j;
    int name_len = strlen(name);
    int temp_len;
    int result = 0;
    if(user_count > 0){
        for(i = 0; i < user_count && !result; i++){
            temp_len = strlen(user_map[i].name);
            if(name_len == temp_len){
                result = 1;
                idx = i;
                for(j = 0; j < name_len; j++){
                    if(tolower(name[j]) != tolower(user_map[i].name[j])){
                        result = 0;
                        idx = -1;
                    }
                }
            }
        }
    }
    return idx;
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