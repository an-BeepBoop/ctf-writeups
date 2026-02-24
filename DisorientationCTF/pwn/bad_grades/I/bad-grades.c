#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

#define NUM_STUDENTS 10000

//You may assume each value here are initialised to -1.
int local_cache[NUM_STUDENTS];

/**
* You may assume the validity of UID had been checked by 
* the caller of this function.
*/
int load(int uid){
    if(local_cache[uid] == -1){
        return load_from_old_server(uid);
    }else{
        return local_cache[uid];
    }
}

/**
* You may assume the validity of UID and grades had been checked by 
* the caller of this function.
*/
void store(int uid, int grades){
    store_to_old_server(uid, grades);
    local_cache[uid] = grades;
}