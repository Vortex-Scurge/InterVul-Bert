/* SYNTHETIC DEMONSTRATION DATA — NOT BENCHMARK DATA */
/* Category: Vulnerability Requiring Caller Context */
/* The target function 'store_user_record' appears benign or assumes preconditions, */
/* but caller 'handle_network_packet' passes raw, unbounded network input without validation. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* TARGET FUNCTION: Appears to be an internal trust-boundary record store */
void store_user_record(char *record_dest, const char *raw_data) {
    /* Assumes caller sanitized input size, but lacks defensive bounds check */
    strcpy(record_dest, raw_data);
}

/* CALLER FUNCTION: Ingests untrusted external packet without length checking */
void handle_network_packet(int socket_fd) {
    char packet_payload[2048];
    char internal_storage[64];

    /* Simulates reading from network socket */
    int bytes_read = read_socket(socket_fd, packet_payload, sizeof(packet_payload) - 1);
    if (bytes_read > 0) {
        packet_payload[bytes_read] = '\0';
        /* Vulnerability exists because caller forwards large payload to small storage */
        store_user_record(internal_storage, packet_payload);
    }
}
