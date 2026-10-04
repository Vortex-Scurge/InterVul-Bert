/* SYNTHETIC DEMONSTRATION DATA — NOT BENCHMARK DATA */
/* Category: Purely Safe Mathematical / String Utility */

#include <stdio.h>
#include <stdlib.h>

int compute_checksum(const int *data, size_t length) {
    int sum = 0;
    for (size_t i = 0; i < length; i++) {
        sum += data[i];
    }
    return sum;
}

int calculate_statistics(const int *values, size_t count) {
    if (values == NULL || count == 0) {
        return 0;
    }
    return compute_checksum(values, count);
}

int main(void) {
    int sample_data[4] = {10, 20, 30, 40};
    int res = calculate_statistics(sample_data, 4);
    printf("Result: %d\n", res);
    return 0;
}
