/* GUESSWORD.c
 *   by HACKER_HANDLE
 *
 * Created:
 *   02/09/2020, 20:34:28
 * Last edited:
 *   05/09/2020, 17:39:05
 * Auto updated?
 *   Yes
 *
 * Description:
 *   This file contains the code needed for Assignment 1 of the course
 *   Computer & Network Security. Specifically, it contains a program that,
 *   given a list of dictionaries, can use those to try and guess the
 *   passwords stored in Linux user & shadow files.
**/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <crypt.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <sys/time.h>


/***** CONSTANTS *****/

/* Determines the maximum number of passwords stored in memory. */
#define MAX_PASSWORDS 10000000
/* Determines the maximum length of a single password (including null-termination). */
#define MAX_PASSWORD_LENGTH 64
/* Determines the maximum number of salts loaded in memory at a time. */
#define MAX_SALTS 128
/* Determines the maximum number of characters a salt can exist of (including null-termination). */
#define MAX_SALT_LENGTH 7
/* Determines the maximum number of characters a hash can exist of (including null-termination). */
#define MAX_HASH_LENGTH 23
/* Determines the maximum number of users loaded in memory. */
#define MAX_USERS 10000
/* Determines the maximum number of characters allowed in a username (including null-termination). */
#define MAX_USERNAME_LENGTH 7
/* Determines the chunk size for reading a file. */
#define CHUNK_SIZE 512
/* The path of the Dictionary file. */
#define DICTIONARY_PATH "dictionary.txt"



/***** ENUMS *****/

/* The ParseState-enum determines what part of the User struct we're trying to parse right now. */
typedef enum PARSESTATE {
    username,
    salt,
    hash
} ParseState;



/***** OBJECTS *****/

/* The Array-struct, which contains a pointer to the a list of char arrays. */
typedef struct ARRAY {
    // The data pointed to by this Array
    void* data;
    // The number of elements stored in this Array
    long size;
    // The maximum numbers allowed to be stored in this Array
    long max_size;
    // The number of bytes that each element is long
    int pitch_size;
} Array;

/* Creates a new Array struct. */
Array* Array_create(int max_size, int max_elem_length) {
    // Allocate it and set the variables
    Array* array = malloc(sizeof(Array) + max_size * max_elem_length);
    array->data = (void*) (((char*) array) + sizeof(Array));
    array->size = 0;
    array->pitch_size = max_elem_length;
    array->max_size = max_size;

    // Return it
    return array;
}
/* Deallocates an Array struct. */
void Array_destroy(Array* ptr) {
    free(ptr);
}

/* Returns an element stored in the Array (as char*). */
#define GET_CHAR(ARR, Y) \
    (((char*) (ARR)->data) + (Y) * (ARR)->pitch_size)
/* Returns an element stored in the Array (as User*). */
#define GET_USER(ARR, Y) \
    ((User*) (((char*) (ARR)->data) + (Y) * (ARR)->pitch_size))



/* The User-struct, which contains information on a user (his username, the hash & the matching salt). */
typedef struct USER {
    char username[MAX_USERNAME_LENGTH];
    char hash[MAX_HASH_LENGTH];
    int salt_id;
    int guessed;
} User;



/* The ThreadData-struct, which is used to move the relevant data to the threads. */
typedef struct THREADDATA {
    // The pthread-relevant thread ID.
    pthread_t tdata;
    // The human-relevant thread ID.
    int tid;
    // Reference to the list of all passwords.
    Array* passwords;
    // Reference to the list of all users.
    Array* users;
    // Reference to the salt used.
    char* salt;
    // The size of the salt used.
    int salt_len;
    // The start of our assigned range of passwords.
    unsigned long start;
    // The end of our assigned range of passwords.
    unsigned long stop;
    #ifdef DEBUG
    /* Lists the time that the Thread took to compute it's share of threads. */
    float elapsed;
    #endif
} ThreadData;



/***** HELPER FUNCTIONS *****/

/* Reads the given file as if it was a dictionary, and returns a Passwords struct with array size 'sizeof(char) * MAX_PASSWORDS * (MAX_PASSWORD_LENGTH + 1)'. Returns NULL if some error occurred. */
int read_passwords(Array* passwords, FILE* dictionary_h) {
    // Reset the size of the passwords struct
    passwords->size = 0;

    // Loop and read the file
    char buffer[MAX_PASSWORD_LENGTH];
    int index = 0;
    #ifdef DEBUG
    long line = 0;
    #endif
    while(fgets(buffer, MAX_PASSWORD_LENGTH, dictionary_h) != NULL) {
        // Loop through the buffer to add
        for (int i = 0; i < MAX_PASSWORD_LENGTH; i++) {
            char c = buffer[i];
            if (c == '\n' || c == '\0') {
                // Finish the current password with an '\0'
                GET_CHAR(passwords, passwords->size)[index] = '\0';
                // Only go the the next passwords if there is something here
                if (index > 0) {
                    passwords->size++;
                }
                // Reset the index, increment line, then go the next buffer
                index = 0;
                #ifdef DEBUG
                if (c == '\n') { line++; }
                #endif
                break;
            } else {
                if (passwords->size == MAX_PASSWORDS) {
                    // Password count overflow
                    #ifdef DEBUG
                    fprintf(stderr, "[WARNING] Encountered too many passwords starting from line %lu; stopping early.\n",
                            line);
                    #endif
                    // Still return the OK code, as it is still usable
                    return 0;
                } else if (index == MAX_PASSWORD_LENGTH - 1) {
                    // String overflow
                    #ifdef DEBUG
                    fprintf(stderr, "[WARNING] Password on line %ld is too long; splitting after %d characters.\n",
                            line, MAX_PASSWORD_LENGTH - 1);
                    #endif
                    // Move to the next field to dump the rest
                    passwords->size++;
                    index = 0;
                }
                // Simply add it
                GET_CHAR(passwords, passwords->size)[index++] = c;
            }
        }
    }

    // Check if anything illegal occured
    if (passwords->size < MAX_PASSWORDS && !feof(dictionary_h)) {
        // Stopped prematurly; we errored somehow
        fprintf(stderr, "[ERROR] Could not read from dictionary file: %s\n", strerror(errno));
        return errno;
    }
    
    // If everything checks out, return the OK-code
    return 0;
}

/* Reads a shadow file to memory. Returns a list of User objects that describes each user in the file, and a list of all unique salts used. Return '1' if successful or '0' otherwise. */
int read_shadow(char* salt_s, Array* users, FILE* shadow_h) {
    // Create buffers to store stuff in
    char line_buffer[CHUNK_SIZE];

    // Loop through the file and read line-by-line
    int salt_done = 0;
    #ifdef DEBUG
    long line = 0;
    #endif
    while (users->size < MAX_USERS && fgets(line_buffer, CHUNK_SIZE, shadow_h) != NULL) {
        // Loop through the line buffer to parse each line
        int skip = 0;
        long index = 0;
        int dollar_count = 0;
        ParseState state = username;
        for (int i = 0; !skip && i < CHUNK_SIZE; i++) {
            char c = line_buffer[i];
            // Switch to the correct state
            switch(state) {
                case username:
                    if (c == ':') {
                        // If index == 0, do nothing as we don't want empty lines
                        if (index == 0) {
                            #ifdef DEBUG
                            fprintf(stderr, "[WARNING] Encountered empty username on line %ld; skipping.\n", line);
                            #endif
                            skip = 1;
                            break;
                        }
                        // Move to the next state, after finalizing the username
                        GET_USER(users, users->size)->username[index] = '\0';
                        index = 0;
                        state = salt;
                    } else if (c == '\n' || c == '\0') {
                        // Too early for this to happen
                        #ifdef DEBUG
                        fprintf(stderr, "[WARNING] Encountered unterminated username on line %ld; skipping.\n", line);
                        #endif
                        skip = 1;
                    } else {
                        // Otherwise, add to the username (if not overflowing)
                        if (index == MAX_USERNAME_LENGTH - 1) {
                            #ifdef DEBUG
                            fprintf(stderr, "[WARNING] Overflow in username on line %ld; skipping.\n", line);
                            #endif
                            skip = 1;
                        } else {
                            GET_USER(users, users->size)->username[index++] = c;
                        }
                    }
                    break;

                case salt:
                    if (c == '\n' || c == '\0') {
                        // Too early for this to happen
                        #ifdef DEBUG
                        fprintf(stderr, "[WARNING] Encountered unterminated salt on line %ld; skipping.\n", line);
                        #endif
                        skip = 1;
                    } else {
                        // Otherwise, add to the username (if not overflowing)
                        if (index == MAX_SALT_LENGTH - 1) {
                            #ifdef DEBUG
                            fprintf(stderr, "[WARNING] Overflow in salt on line %ld; skipping.\n", line);
                            #endif
                            skip = 1;
                            break;
                        } else if (!salt_done) {
                            salt_s[index++] = c;
                        }

                        // If we have encountered three dollars, then it's time to move to the next phase
                        if (c == '$' && ++dollar_count == 3) {
                            if (!salt_done) {
                                salt_s[index] = '\0';
                                salt_done = 1;
                            }
                            index = 0;
                            state = hash;
                        }
                    }
                    break;

                case hash:
                    if (c == ':' || c == '\n' || c == '\0') {
                        // Check if the hash is weirdly sized
                        if (index == 0) {
                            #ifdef DEBUG
                            fprintf(stderr, "[WARNING] Encountered empty hash on line %ld; skipping.\n", line);
                            #endif
                            skip = 1;
                            break;
                        } else if (index != 22) {
                            // Show a warning in the log, as this is unexpected (but we accept the hash nonetheless)
                            #ifdef DEBUG
                            fprintf(stderr, "[WARNING] Encountered hash with unexpected size %ld on line %ld (expected size 22).\n",
                                    index, line);
                            #endif
                        }

                        // Finish the hash && advance users, as that part is done now
                        GET_USER(users, users->size)->hash[index] = '\0';
                        GET_USER(users, users->size)->guessed = 0;
                        users->size++;

                        // Skip to avoid reading the rest of the line
                        skip = 1;
                    } else {
                        // Simply add to the hash of the user (if not overflowing)
                        if (index == MAX_HASH_LENGTH - 1) {
                            #ifdef DEBUG
                            fprintf(stderr, "[WARNING] Overflow in hash on line %ld; skipping.\n", line);
                            #endif
                            skip = 1;
                        } else {
                            GET_USER(users, users->size)->hash[index++] = c;
                        }
                    }
                    break;
            }
        }
        #ifdef DEBUG
        // Don't forget to increment the line
        line++;
        #endif
    }

    // Check if anything illegal occured
    if (users->size < MAX_USERS && !feof(shadow_h)) {
        // Stopped prematurly; we errored somehow
        fprintf(stderr, "[ERROR] Could not read from shadow file: %s\n", strerror(errno));
        return errno;
    }

    // We're done here
    return 0;
}

/* Returns the number of active cores that this process has access to. Credits go to Damien Zammit (https://stackoverflow.com/a/62867839). */
int nprocs()
{
  cpu_set_t cs;
  CPU_ZERO(&cs);
  sched_getaffinity(0, sizeof(cs), &cs);
  return CPU_COUNT(&cs);
}

/* Returns 1 if both of the given strings are equal, or 0 otherwise. */
int streq(char* str1, char* str2) {
    for (int i = 0; ; i++) {
        if (str1[i] != str2[i]) { return 0; }
        if (str1[i] == '\0') { return 1; }
    }
}



/***** THREAD MAINS *****/

/* The default Thread main. Will first compute its share of hashes, after which it shall compare those to the users available. */
void* thread_main(void* data) {
    ThreadData* tdata = (ThreadData*) data;

    // Get some shortcuts to stuff in tdata
    Array* passwords = tdata->passwords;
    char* salt = tdata->salt;
    int salt_len = tdata->salt_len;
    int start = tdata->start;
    int stop = tdata->stop;

    // Start with our time measurement
    #ifdef DEBUG
    struct timeval start_clock, stop_clock;
    gettimeofday(&start_clock, NULL);
    #endif
    
    // Go through our range to compute the hashes & compare them once computed
    for (unsigned long p = start; p <= stop; p++) {
        // Acquire the correct password
        // Compute the hash
        char* result = crypt(GET_CHAR(passwords, p), salt);
        // Remove the salt bit from the result
        char* hash = result + salt_len;
        // // Compare it with the hash we know each user has
        // for (long i = 0; i < tdata->users->size; i++) {
        //     User* user = GET_USER(tdata->users, i);
        //     if (!user->guessed && streq(hash, user->hash)) {
        //         // We have this user, so print the result
        //         fprintf(stdout, "%s:%s\n",user->username, password);
        //         fflush(stdout);
        //         // Mark that we guessed it
        //         user->guessed = 1;
        //     }
        // }
    }

    #ifdef DEBUG
    gettimeofday(&stop_clock, NULL);
    tdata->elapsed = ((stop_clock.tv_sec - start_clock.tv_sec) * 1000000 + (stop_clock.tv_usec - start_clock.tv_usec)) / 1000000.0;
    #endif

    return NULL;
}



/***** MAIN *****/
int main(int argc, const char** argv) {
    /***** Initialize by parsing command line args and opening handles. *****/
    // Read the CL-args
    // const char* passwd_path;
    const char* shadow_path;
    const char* dictionary_path = DICTIONARY_PATH;
    if (argc < 3 || argc > 4) {
        printf("Usage: %s passwd_path shadow_path [dictionary_path]\n", argv[0]);
        exit(0);
    } else {
        // Actually ifnore the passwd for now, as I think everything we need to know is in the shadow file.
        // passwd_path = argv[1];
        shadow_path = argv[2];
        if (argc == 4) {
            dictionary_path = argv[3];
        }
    }

    // Check if the files exist by already acquiring FILE handles
    FILE* shadow_h = fopen(shadow_path, "r");
    if (shadow_h == NULL) {
        fprintf(stderr, "[ERROR] Could not open file '%s': %s\n", shadow_path, strerror(errno));
        return errno;
    }
    // Also get a handle for the hardcoded dictionary.txt
    FILE* dictionary_h = fopen(dictionary_path, "r");
    if (dictionary_h == NULL) {
        fclose(shadow_h);
        fprintf(stderr, "[ERROR] Could not open file '%s': %s\n", dictionary_path, strerror(errno));
        return errno;
    }



    /***** Then, read the dictionary file with all the passwords. *****/
    Array* passwords = Array_create(MAX_PASSWORDS, sizeof(char) * MAX_PASSWORD_LENGTH);
    int result = read_passwords(passwords, dictionary_h);
    fclose(dictionary_h);
    if (result != 0) {
        fclose(shadow_h);
        Array_destroy(passwords);
        return result;
    }
    #ifdef DEBUG
    fprintf(stderr, "[INFO] Loaded %ld passwords.\n", passwords->size);
    #endif



    /***** Next, extract a list of users and unique salts from the shadow file. *****/
    // First, declare an Array to store the salts in and one for the Users
    char salt[MAX_SALT_LENGTH];
    Array* users = Array_create(MAX_USERS, sizeof(User));
    
    // Now, call a function to do the work for us >:)
    result = read_shadow(salt, users, shadow_h);
    if (result != 0) {
        // Something bad happened; cleanup and return
        fclose(shadow_h);
        Array_destroy(passwords);
        Array_destroy(users);
        return result;
    }
    #ifdef DEBUG
    fprintf(stderr, "[INFO] Using salt string '%s'.\n", salt);
    fprintf(stderr, "[INFO] Loaded %ld users.\n", users->size);
    #endif



    /***** Then, we spawn threads which will handle the rest. *****/
    // Get the number of HW threads available on this machine
    int n_threads = 8;//nprocs();
    if (n_threads > passwords->size) { n_threads = passwords->size; }
    #ifdef DEBUG
    fprintf(stderr, "[INFO] Using %d threads.\n\n", n_threads);
    #endif
    
    // Spawn n_threads threads
    ThreadData threads[n_threads];
    for (int i = 0; i < n_threads; i++) {
        // First, we populate the ThreadData struct
        threads[i].tid = i;
        threads[i].passwords = passwords;
        threads[i].salt = salt;
        threads[i].salt_len = strlen(salt);
        threads[i].users = users;
        threads[i].start = i * (passwords->size / n_threads);
        threads[i].stop = i < n_threads - 1 ? (i + 1) * (passwords->size / n_threads) - 1 : passwords->size - 1;

        // Spawn the thread
        pthread_create(&threads[i].tdata, NULL, thread_main, (void*) &threads[i]);
    }

    // Simply wait until they are done
    #ifdef DEBUG
    float total_hps = 0;
    #endif
    for (int i = 0; i < n_threads; i++) {
        pthread_join(threads[i].tdata, NULL);
        #ifdef DEBUG
        float hashes_per_second = ((threads[i].stop + 1) - threads[i].start) / threads[i].elapsed;
        if (i == 0) { fprintf(stderr, "\n"); }
        fprintf(stderr, "[INFO] Thread %d computed %lu hashes in %fs = %f hashes/s.\n",
                threads[i].tid, (threads[i].stop + 1) - threads[i].start, threads[i].elapsed,
                hashes_per_second);
        total_hps += hashes_per_second;
        #endif
    }
    #ifdef DEBUG
    fprintf(stderr, "[INFO] Average thread speed = %f hashes/s.\n", total_hps / (float) n_threads);
    #endif

    // Check the validity of all threads


    
    /***** Finally, clean up. *****/
    // Close the files
    fclose(shadow_h);

    // Deallocate the heap memory
    Array_destroy(passwords);
    Array_destroy(users);

    /* Done! */
    return 0;
}
