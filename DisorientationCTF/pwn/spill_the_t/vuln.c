#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>

const char* welcome_msg =
    ">>===========================================================<<\n"
    "|| ___              _    _       _    _                _____ ||\n"
    "||(  _`\\         _ (_ ) (_ )    ( )_ ( )              (_   _)||\n"
    "||| (_(_) _ _   (_) | |  | |    | ,_)| |__     __       | |  ||\n"
    "||`\\__ \\ ( '_`\\ | | | |  | |    | |  |  _ `\\ /'__`\\     | |  ||\n"
    "||( )_) || (_) )| | | |  | |    | |_ | | | |(  ___/     | |  ||\n"
    "||`\\____)| ,__/'(_)(___)(___)   `\\__)(_) (_)`\\____)     (_)  ||\n"
    "||       | |                                                 ||\n"
    "||       (_)                                                 ||\n"
    ">>===========================================================<<\n"
    "                  For all your gossiping needs                 \n";

const char* options_msg =
    "Options:\n"
    "  1: Exit\n"
    "  2: Hear tea\n"
    "  3: Spill tea\n"
    "  4: Update tea\n"
    "  5: Remove tea\n"
    "> ";

typedef struct tea {
    unsigned int active;
    struct tea* next;
    char* tea;

} tea_t;

tea_t* spilled_tea = NULL;


void exit_tea() {
    puts("Thx for the scoop");
    exit(0);
}

void hear_tea() {
    puts("Tea gathered so far:");
    tea_t* tea = spilled_tea;
    for (size_t i = 0; tea != NULL; i++) {
        if (tea->active) printf("(Tea #%u) Did you know... %s!\n", i, tea->tea);
        tea = tea->next;
    }
    puts("");
}

void spill_tea() {
    puts("Spill the tea gang: (max 47 chars)");
    tea_t* goss = malloc(sizeof(tea_t));
    if (spilled_tea == NULL) {
        spilled_tea = goss;
    }
    else {
        tea_t* tea = spilled_tea;
        while (tea->next != NULL) tea = tea->next;
        tea->next = goss;
    }

    goss->tea = malloc(48);
    fgets(goss->tea, 48, stdin);
    goss->tea[strcspn(goss->tea, "\n")] = '\0';
    goss->active = 1;
    goss->next = NULL;

    puts("k got it");
}

void update_tea() {
    if (spilled_tea == NULL) {
        puts("No tea to update :(");
        return;
    }

    printf("Oh wait rly what changed?\nTea index: ");
    unsigned int idx;
    int success = scanf("%u", &idx);
    getchar();
    if (success == 0) {
        puts("Please enter an unsigned integer.");
        return;
    }

    tea_t* tea = spilled_tea;
    for (; idx > 0; idx--) {
        if (tea->next == NULL) {
            puts("Invalid index.");
            return;
        }
        tea = tea->next;
    }

    puts("Ok spill the new tea plz:");
    fgets(tea->tea, 48, stdin);
    tea->tea[strcspn(tea->tea, "\n")] = '\0';
    //for (int i = strcspn(tea->tea, "\n"); i < 48; i++) {
    //    tea->tea[i] = '\0';
    //}
    puts("dude that is wild");
}

void remove_tea() {
    if (spilled_tea == NULL) {
        puts("No tea to remove :(");
        return;
    }

    printf("ight which one was cap?\nTea index: ");
    unsigned int idx;
    int success = scanf("%u", &idx);
    getchar();
    if (success == 0) {
        puts("Please enter an unsigned integer.");
        return;
    }

    tea_t* tea = spilled_tea;
    for (; idx > 0; idx--) {
        if (tea->next == NULL) {
            puts("Invalid index.");
            return;
        }
        tea = tea->next;
    }

    // Apparently I need to do this in C. Should have just used java ts pmo so much rn i fr cannot be bothered testing
    tea->active = 0;
    free(tea->tea);
    free(tea);

    puts("yeah that was lowkey untrue");
}

void disable_buffering() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

int main(int argc, char* argv[]) {
    disable_buffering();
    puts(welcome_msg);

    while (1) {
        printf(options_msg);

        char choice = getchar();
        while(getchar() != '\n');

        switch (choice) {
            case '1':
                exit_tea();
                break;
            case '2':
                hear_tea();
                break;
            case '3':
                spill_tea();
                break;
            case '4':
                update_tea();
                break;
            case '5':
                remove_tea();
                break;
            default:
                puts("Invalid option.");
                break;
        }
    }

    return 0;
}

void print_flag() {
    FILE *flag = fopen("flag.txt", "r");
    char buf[64];
    while (fgets(buf, sizeof(buf), flag)) {
        printf("%s", buf);
    }
    fclose(flag);
}
