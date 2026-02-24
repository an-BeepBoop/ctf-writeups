#include <stdio.h>
#include <stdlib.h>

const char* config_filepath = "config.txt";

const char* open_message =
    "---------tROPhy-collection---------\n"
    "eTrophy v0.0.5 (32 bit)\n"
    "\n"
    "Changelog:\n"
    "- Fixed typo in welcome message\n"
    "- Fixed issue that allowed bad actors to get /bin/sh";

const char* options_message =
    "\n\nOptions:\n"
    "  1: Display trophies\n"
    "  2: Update name\n"
    "  3: Exit\n";

void get_name(char* dest) {
    FILE* conf = fopen(config_filepath, "r");

    if (conf == NULL) {
        puts("Unable to open config file.");
        exit(1);
    }

    fgets(dest, 32, conf);
}

void print_trophies() {
    char name[32];
    get_name(name);

    printf("Trophies currently in %s\'s collection:\n", name);
    system("find trophies -type f -printf \"%f: \" -exec cat {} \\;");
}

void update_name() {
    char buf[32];
    puts("New name (up to 32 chars):");

    gets(buf);

    FILE* conf = fopen(config_filepath, "w");

    if (conf == NULL) {
        puts("Unable to open config file.");
        exit(1);
    }

    fprintf(conf, "%s", buf);
    fclose(conf);
}

int main() {
    setbuf(stdout, NULL);
    puts(open_message);

    while (1) {
        puts(options_message);
        printf("> ");
        fflush(stdout);

        char choice = getchar();
        while (getchar() != '\n');

        switch (choice) {
            case '1':
                print_trophies();
                break;
            case '2':
                update_name();
                break;
            case '3':
                puts("Bye!");
                return 0;
            default:
                puts("Invalid option.");
                break;
        }
    }


    return 0;
}
