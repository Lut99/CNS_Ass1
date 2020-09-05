/* BENCHMARK.c
 *   by Lut99
 *
 * Created:
 *   05/09/2020, 17:17:42
 * Last edited:
 *   05/09/2020, 17:34:14
 * Auto updated?
 *   Yes
 *
 * Description:
 *   A simple program that benchmarks the number of MD5-hashes can be
 *   computed on this machine using C's crypt-library.
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <crypt.h>
#include <sys/time.h>


/***** CONSTANTS *****/

/* The number of hashes that are used to compute the score. */
#define N_HASHES 50000
/* The length of the randomly-generated password (excluding null-termination). */
#define PASSWORD_LENGTH 32


int main() {
    printf("\n*** BENCHMARK ***\n\n");

    printf("Generating random passwords..."); fflush(stdout);
    char passwords[N_HASHES * (PASSWORD_LENGTH + 1)];
    for (int i = 0; i < N_HASHES; i++) {
        for (int j = 0; j < PASSWORD_LENGTH; j++) {
            int r = (rand() % 62);
            char c;
            if (r < 26) { c = 'a' + (char) r; }
            else if (r < 52) { c = 'A' + (char) (r - 26); }
            else { c = '0' + (char) (r - 52); }
            passwords[i * (PASSWORD_LENGTH + 1) + j] = c;
        }
        passwords[i * (PASSWORD_LENGTH + 1) + PASSWORD_LENGTH] = '\0';
    }
    printf(" Done\n");

    printf("Benchmarking hashes..."); fflush(stdout);
    struct timeval start_ms, end_ms;
    gettimeofday(&start_ms, NULL);
    for (unsigned long i = 0; i < N_HASHES; i++) {
        char* password = passwords + (i * (PASSWORD_LENGTH + 1));
        char* hash = crypt(password, "$1$E7$");
        (void) hash;
    }
    gettimeofday(&end_ms, NULL);
    float duration = ((end_ms.tv_sec - start_ms.tv_sec) * 1000000 + (end_ms.tv_usec - start_ms.tv_usec)) / 1000000.0;
    printf(" Done (%fs)\n\n", duration);

    printf("> This machine is capable of %f hash/s on a single thread. <\n\n",
           N_HASHES / duration);
}
