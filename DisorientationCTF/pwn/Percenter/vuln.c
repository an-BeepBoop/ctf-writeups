#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debuglib.h"

char* banner = "\n"
    "▄▄▄▄  ▗▞▀▚▖ ▄▄▄ ▗▄▄▖▗▄▄▄▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖▗▄▄▖ \n"
    "█   █ ▐▛▀▀▘█   ▐▌   ▐▌   ▐▛▚▖▐▌  █  ▐▌   ▐▌ ▐▌\n"
    "█▄▄▄▀ ▝▚▄▄▖█   ▐▌   ▐▛▀▀▘▐▌ ▝▜▌  █  ▐▛▀▀▘▐▛▀▚▖\n"
    "█              ▝▚▄▄▖▐▙▄▄▖▐▌  ▐▌  █  ▐▙▄▄▖▐▌ ▐▌\n"
    "▀      Debugging Service v0.1.4               \n"
    "- - - - - - - - - - - - - - - - - - - - - - - \n"
    " For remotely tracking device battery levels  \n"
    "----------------------------------------------\n";

typedef struct {
    int isAdmin;
} admin_t;

void adminShell() {
    system("/bin/sh");
}

int checkIsAdmin() {
#ifdef DISALLOW_ADMIN
    return 0;
#else
    return authenticateAdmin();
#endif
}

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);
    puts(banner);

    char input[32];
    admin_t* admin = malloc(sizeof(admin_t));
    admin->isAdmin = checkIsAdmin();

    puts("Enter your name (this will be added to debug logs).");
    fgets(input, sizeof(input), stdin);
    puts("Name set to:");
    printf(input);

    if (admin->isAdmin) {
        puts("Logged in as admin.");
        adminShell();
    }

    puts("---------------------");
    puts("Enter device ID to connect to:");
    scanf("%s", input);
    if (connectDevice(input)) {
        startDebugSession();
    }
    else {
        puts("Device not found...");
    }

    return 0;
}
