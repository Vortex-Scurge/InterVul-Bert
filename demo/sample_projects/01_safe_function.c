/* SYNTHETIC DEMONSTRATION DATA — NOT BENCHMARK DATA */
/* Category: Safe Function */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUFFER 128

int safe_string_copy(const char *source, char *destination, size_t dest_size) {
    if (source == NULL || destination == NULL || dest_size == 0) {
        return -1;
    }
    size_t src_len = strnlen(source, dest_size);
    if (src_len >= dest_size) {
        return -1; /* Truncation prevented */
    }
    memcpy(destination, source, src_len);
    destination[src_len] = '\0';
    return 0;
}

int main(void) {
    char dest[MAX_BUFFER];
    const char *msg = "Authorized safe configuration";
    if (safe_string_copy(msg, dest, sizeof(dest)) == 0) {
        printf("Safe copy succeeded: %s\n", dest);
    }
    return 0;
}
