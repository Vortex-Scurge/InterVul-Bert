/* SYNTHETIC DEMONSTRATION DATA — NOT BENCHMARK DATA */
/* Category: Multi-Function Vulnerability Chain */
/* Chain: */
/*   Source: process_request() */
/*     ↓ */
/*   Function A: normalize_header() */
/*     ↓ */
/*   Function B: parse_query_parameters() */
/*     ↓ */
/*   Target: execute_query() */
/*     ↓ */
/*   Function C: db_native_execute() */
/*     ↓ */
/*   Sink: system() */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* DOWNSTREAM SINK FUNCTION (CALLEE C) */
void db_native_execute(const char *raw_sql_statement) {
    /* Dangerous execution sink */
    system(raw_sql_statement);
}

/* TARGET FUNCTION */
void execute_query(char *query_buffer) {
    /* Delegates without escaping to downstream native executor */
    db_native_execute(query_buffer);
}

/* INTERMEDIATE FUNCTION B */
void parse_query_parameters(char *raw_params) {
    char sql_buf[1024];
    /* Flawed parameter concatenation */
    sprintf(sql_buf, "SELECT * FROM users WHERE name = '%s'", raw_params);
    execute_query(sql_buf);
}

/* INTERMEDIATE FUNCTION A */
void normalize_header(char *header_data) {
    /* Superficial transformation that does NOT sanitize SQL metacharacters */
    for (int i = 0; header_data[i] != '\0'; i++) {
        if (header_data[i] == '\r') header_data[i] = ' ';
    }
    parse_query_parameters(header_data);
}

/* UNTRUSTED SOURCE ENTRYPOINT */
void process_request(void) {
    char untrusted_input[512];
    /* Ingests untrusted external input */
    fgets(untrusted_input, sizeof(untrusted_input), stdin);
    normalize_header(untrusted_input);
}

int main(void) {
    process_request();
    return 0;
}
