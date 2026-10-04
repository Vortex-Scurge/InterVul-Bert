/* SYNTHETIC DEMONSTRATION DATA — NOT BENCHMARK DATA */
/* Category: False-Positive Suppression Case */
/* Isolated function 'copy_to_log_buffer' uses strcpy, which models often flag as vulnerable. */
/* However, caller 'safe_log_dispatcher' strictly verifies that strlen(msg) < 32 before invoking it. */

#include <stdio.h>
#include <string.h>

#define LOG_BUF_SZ 64

/* TARGET FUNCTION: Pattern-matching classifiers often falsely flag this due to strcpy */
void copy_to_log_buffer(char *destination, const char *guaranteed_short_msg) {
    strcpy(destination, guaranteed_short_msg);
}

/* CALLER FUNCTION: Enforces strict length verification before calling target */
void safe_log_dispatcher(const char *incoming_user_message) {
    char internal_log[LOG_BUF_SZ];
    if (incoming_user_message == NULL) {
        return;
    }

    /* Strict caller-side sanitization and bounds check */
    if (strlen(incoming_user_message) < 32) {
        /* Completely safe call site */
        copy_to_log_buffer(internal_log, incoming_user_message);
        printf("[AUDIT LOG]: %s\n", internal_log);
    } else {
        printf("[AUDIT LOG ERROR]: Message rejected (exceeds 32 bytes limit)\n");
    }
}

int main(void) {
    safe_log_dispatcher("Hello Admin");
    return 0;
}
