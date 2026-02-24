
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int key_solutions[6] = {0, 0, 0, 0, 0, 0};

void key_check() {
    printf("Enter 6 digit key separated by commas with no spaces\n");
    int inputs[6];
    // 5 commas + 6 digits + null byte
    char buffer[12];
    fgets(buffer, 12, stdin);
    if (sscanf(buffer, "%d,%d,%d,%d,%d,%d",
        &inputs[0],
        &inputs[1],
        &inputs[2],
        &inputs[3],
        &inputs[4],
        &inputs[5]
    ) == 0) {
        printf("Bad formatting\n");
    }
    int random_key[6];
    for (int i = 0; i < 6; i++) {
        // OSes aren't perfectly accurate sleepers, so we can use this to
        // generate a random value
        if (inputs[i] != key_solutions[i]) {
            printf("Bad key\n");
            return;
        }
        sleep(1);
        srand(time(NULL));
        random_key[i] = rand();
    }
    printf("Your login key for today is %d", random_key[0]);
    for (int i = 1; i < 6; i++) {
        printf(", %d", random_key[i]);
    }
    printf("\n");
}

int main() {
    while (1) {
        key_check();
    }
}
