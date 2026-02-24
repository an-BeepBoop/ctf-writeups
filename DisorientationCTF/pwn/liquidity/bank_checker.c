#include <stdio.h>
#include <string.h>

#define TRUE 1
#define FALSE 0

int ZOOWEE_DOLLARS = 123;

void check_bank_account() {
    // update ZOOWEE_DOLLARS todo
}

int main() {
    check_bank_account();
    char user[10];
    int ADMIN_ALLOWED = FALSE;
    // disable this in prod
    printf("Please enter username\n");
    gets(user);
    if (strcmp(user, "ZOOWEE") == 0) {
        if (ADMIN_ALLOWED) {
            printf("ADMIN mode enabled. Logged in as ZOOWEE\n");
            printf("You have %d dollars in your bank account\n", ZOOWEE_DOLLARS);
        }
        else {
            printf("ADMIN mode disabled. Logged in as ZOOWEE\n");
        }
    }
    else {
        printf("BAD LOGIN DETAILS\n");
    }
}