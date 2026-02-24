#include <string.h>
#include <stdio.h>
#define TRUE 1
#define FALSE 0

volatile int ZOOWEE_DOLLARS = 0;

void give_balance(char *ptr, int len) {
    char correct_username[] = "ZOOWEE";
    const int correct_username_len = strlen(correct_username);
    char my_copy[20];
    int ADMIN_ALLOWED = FALSE;
    // length check ensures strcpy is safe
    if (len > 20) {
        printf("Username too long to be valid\n");
        return;
    }
    strcpy(my_copy, ptr);
    if (memcmp(my_copy, correct_username, correct_username_len) == 0) {
        if (ADMIN_ALLOWED) {
            printf("ADMIN mode enabled. Logged in as %s\n", correct_username);
            printf("You have %d dollars in your bank account\n", ZOOWEE_DOLLARS);
        }
        else {
            printf("ADMIN mode disabled. Logged in as %s\n", correct_username);
        }
    }
    else {
        printf("BAD LOGIN DETAILS\n");
    }
}