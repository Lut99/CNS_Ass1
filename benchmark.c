/* BENCHMARK.c
 *   by Lut99
 *
 * Created:
 *   05/09/2020, 17:17:42
 * Last edited:
 *   05/09/2020, 22:54:08
 * Auto updated?
 *   Yes
 *
 * Description:
 *   A simple program that benchmarks the number of MD5-hashes can be
 *   computed on this machine using C's crypt-library.
**/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <crypt.h>
#include <pthread.h>
#include <sched.h>
#include <sys/time.h>


/***** CONSTANTS *****/

/* The number of hashes that are used to compute the score. */
#define N_HASHES 50000
/* The length of the randomly-generated password (excluding null-termination). */
#define PASSWORD_LENGTH 32



/***** STRUCTS *****/

/* ThreadData struct, which stores the data we carry back and forth from a thread. */
typedef struct TREADDATA {
    pthread_t data;
    int tid;
    char* passwords;
    float duration;
} ThreadData;



/***** HELPER FUNCTIONS *****/

/* Returns the number of active cores that this process has access to. Credits go to Damien Zammit (https://stackoverflow.com/a/62867839). */
int nprocs()
{
  cpu_set_t cs;
  CPU_ZERO(&cs);
  sched_getaffinity(0, sizeof(cs), &cs);
  return CPU_COUNT(&cs);
}




/***** THREAD FUNCTION *****/
void* thread_benchmark(void* data) {
    ThreadData* tdata = (ThreadData*) data;

    // Simply run the benchmark
    struct timeval start_ms, end_ms;
    gettimeofday(&start_ms, NULL);
    struct crypt_data cdata;
    cdata.initialized = 0;
    for (unsigned long i = 0; i < N_HASHES; i++) {
        char* password = tdata->passwords + (i * (PASSWORD_LENGTH + 1));
        char* hash = crypt_r(password, "$1$E7$", &cdata);
        (void) hash;
    }
    gettimeofday(&end_ms, NULL);
    tdata->duration = ((end_ms.tv_sec - start_ms.tv_sec) * 1000000 + (end_ms.tv_usec - start_ms.tv_usec)) / 1000000.0;

    // Done
    return NULL;
}



/***** MAIN FUNCTION *****/
int main() {
    printf("\n*** BENCHMARK ***\n\n");

    int n_threads = nprocs();
    printf("Benchmarking %d threads.\n\n", n_threads);

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
    // Create the threads
    ThreadData threads[n_threads];
    for (int i = 0; i < n_threads; i++) {
        threads[i].tid = i;
        threads[i].passwords = passwords;
        pthread_create(&threads[i].data, NULL, thread_benchmark, (void*) &threads[i]);
    }
    // Wait until they're here again
    float total_duration = 0;
    for (int i = 0; i < n_threads; i++) {
        pthread_join(threads[i].data, NULL);
        total_duration += threads[i].duration;
    }
    gettimeofday(&end_ms, NULL);
    printf(" Done (~%fs)\n\n", total_duration / n_threads);

    printf("> This machine is capable of %f hashes/s on average over %d threads. <\n",
           N_HASHES / (total_duration / n_threads), n_threads);
    printf("> Total score: %f hashes/s.\n\n", (N_HASHES * n_threads) / (((end_ms.tv_sec - start_ms.tv_sec) * 1000000 + (end_ms.tv_usec - start_ms.tv_usec)) / 1000000.0));
}
