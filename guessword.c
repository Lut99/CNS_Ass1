/* GUESSWORD.c
 *   by DukeD1rtfarm3r
 *
 * Created:
 *   02/09/2020, 20:34:28
 * Last edited:
 *   08/09/2020, 17:01:49
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
#include <sys/time.h>


/***** CONSTANTS *****/

/* If given, enables all sorts of extra prints useful for debugging. */
// #define DEBUG
/* Determines the maximum number of plain passwords stored in memory. */
#define MAX_PLAIN_PASSWORDS 50000
/* Determines the maximum number of mutated passwords stored in memory. */
#define MAX_MUTATED_PASSWORDS 100000000
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
/* The maximum length of a line in the shadow file. */
#define MAX_LINE_LENGTH 64
/* The total length for two passwords to be considered when combined. */
#define LONG_PASSWORD_LENGTH 24
/* The path of the Dictionary file. */
#define DICTIONARY_PATH "dictionary.txt"
/* The path of the LongDictionary file. */
#define LONG_DICTIONARY_PATH "long_dictionary.txt"

/* Maps a month number (0-11) to the appropriate number of days in that month. */
int month_map[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
/* All the special characters we consider for mutation 4. */
#define SPECIAL_CHARS ".?!,;:'\"|@#$%%^&*()-_+="



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
    // Reference to the list of all plain passwords.
    Array* plain_passwords;
    // Reference to the list of all mutated passwords.
    Array* mutated_passwords;
    // Reference to the list of all users.
    Array* users;
    // Reference to the salt used.
    char* salt;
    // The size of the salt used.
    int salt_len;
    #ifdef DEBUG
    /* Lists the time that the Thread took to compute it's share of threads. */
    float elapsed;
    /* Counts the number of hashes processed by this thread. */
    unsigned long n_hashes;
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
                if (passwords->size == MAX_PLAIN_PASSWORDS) {
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
    if (passwords->size < MAX_PLAIN_PASSWORDS && !feof(dictionary_h)) {
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
    char line_buffer[MAX_LINE_LENGTH];

    // Loop through the file and read line-by-line
    int salt_done = 0;
    #ifdef DEBUG
    long line = 0;
    #endif
    while (users->size < MAX_USERS && fgets(line_buffer, MAX_LINE_LENGTH, shadow_h) != NULL) {
        // Loop through the line buffer to parse each line
        int skip = 0;
        long index = 0;
        int dollar_count = 0;
        ParseState state = username;
        for (int i = 0; !skip && i < MAX_LINE_LENGTH; i++) {
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

/* Maps a given letter to an often-used mutation of that letter. */
char* mutate_letter(char* c) {
    switch(c[0]) {
        case 'a': return "/-\\\"/\\";
        // case 'b': return "a";
        case 'c': return "<";
        case 'd': return "|)";
        case 'e': return "3";
        // case 'f': return "a";
        case 'g': return "&";
        // case 'h': return "a";
        case 'i': return "!";
        case 'j': return "]";
        case 'k': return "|(";
        // case 'l': return "a";
        case 'm': return "/V\\";
        case 'n': return "[\\]";
        case 'o': return "0\"()\"°";
        case 'p': return "|>";
        // case 'q': return "a";
        // case 'r': return "a";
        case 's': return "$";
        case 't': return "7";
        case 'u': return "|_|";
        case 'v': return "`'";
        case 'w': return "\\|/";
        // case 'x': return "a";
        case 'y': return "`/";
        // case 'z': return "a";
        default:
            return c;
    }
}

/* Mutates a given list of plain passwords to obtain those confirming to the identified patterns. Returns 0 on success or anything else if something went wrong. */
int mutate_passwords(Array* mutated, Array* plain) {
    char letter_buffer[2];
    letter_buffer[1] = '\0';
    for (int p = 0; p < plain->size; p++) {
        char* password = GET_CHAR(plain, p);

        /* Mutation 1: Create a mutated password which has a single letter capitalized for each letter in the password. */
        {
            for (int i = 0; ; i++) {
                // Stop if we reached \0 or it's not a lowercase char
                if (password[i] == '\0' || password[i] < 'a' || password[i] > 'z') { break; }

                // Copy the string
                strcpy(GET_CHAR(mutated, mutated->size), password);
                // Mutate by capitalizing
                GET_CHAR(mutated, mutated->size)[i] -= 'a' - 'A';
                // Increment mutated's size
                mutated->size++;
            }
            // Also add an ALL-caps version to the deal
            for (int i = 0; ; i++) {
                char c = password[i];
                if (c >= 'a' && c <= 'z') { c -= 'a' - 'A'; }
                GET_CHAR(mutated, mutated->size)[i] = c;
                if (c == '\0') { break; }
            }
            mutated->size++;
        }

        /* Mutation 2: Create a mutated password which has a single letter changed with a much-occuring replacement. */
        for (int i = 0; ; i++) {
            // Stop if we reached \0
            if (password[i] == '\0') { break; }

            // Get the mutation for this letter
            letter_buffer[0] = password[i];
            char* mutation = mutate_letter(letter_buffer);
            // If the mutation is the letter, nothing changed so we avoid duplicates
            if (mutation[0] == password[i]) { continue; }

            // Now loop to find the different possible mutations
            for (int j = 0; ; j++) {
                // Skip when we're not at the end of such a mutation
                if (mutation[j] != '\"' && mutation[j] != '\0') { continue; }
                
                // With the mutation, copy the password letter-for-letter by insert the mutation when we arrive at i
                char* result = GET_CHAR(mutated, mutated->size++);
                int result_i = 0;
                for (int k = 0; ; k++) {
                    if (i == k) {
                        // Copy the current mutation there, until either the quote or the null-char has been reached
                        for (int l = 0; ; l++) {
                            if (mutation[l] == '\"' || mutation[l] == '\0') { break; }
                            result[result_i++] = mutation[l];
                        }
                    } else {
                        // Simply copy the char
                        result[result_i++] = password[k];
                    }
                    // Stop after the \0
                    if (password[k] == '\0') { break; }
                }

                // Stop when we reached '\0' in the mutation
                if (mutation[j] == '\0') { break; }
                // Otherwise, move mutation to the next one
                mutation += j + 1;
            }
        }

        /* Mutation 3: Create a mutated password which has a two letters changed with a much-occuring replacement. */
        for (int i = 0; ; i++) {
            // Stop if we reached \0
            if (password[i] == '\0') { break; }

            // Get the mutation for this letter
            letter_buffer[0] = password[i];
            char* mutation_1 = mutate_letter(letter_buffer);
            // If the mutation is the letter, nothing changed so we avoid duplicates
            if (mutation_1[0] == password[i]) { continue; }

            // Loop for the different permutations
            for (int j = 0; ; j++) {
                // Skip when we're not at the end of such a mutation
                if (mutation_1[j] != '\"' && mutation_1[j] != '\0') { continue; }

                // Find another of the letters to permutate
                for (int k = 0; ; k++) {
                    if (password[k] == '\0') { break; }
                    else if (k == i) { continue; }

                    // Get the mutation for this letter
                    letter_buffer[0] = password[k];
                    char* mutation_2 = mutate_letter(letter_buffer);
                    // If the mutation is the letter, this is already covered by mutation 2, so skip
                    if (mutation_2[0] == password[k]) { continue; }

                    // Loop for every of those different permutations
                    for (int l = 0; ; l++) {
                        // Skip when we're not at the end of such a mutation
                        if (mutation_2[l] != '\"' && mutation_2[l] != '\0') { continue; }

                        // Loop through password to copy it, inserting each of the permutations where necessary
                        char* result = GET_CHAR(mutated, mutated->size++);
                        int result_i = 0;
                        for (int m = 0; ; m++) {
                            if (i == m) {
                                // Copy the first mutation there, until either the quote or the null-char has been reached
                                for (int n = 0; ; n++) {
                                    if (mutation_1[n] == '\"' || mutation_1[n] == '\0') { break; }
                                    result[result_i++] = mutation_1[n];
                                }
                            } else if (k == m) {
                                // Copy the second mutation there, until either the quote or the null-char has been reached
                                for (int n = 0; ; n++) {
                                    if (mutation_2[n] == '\"' || mutation_2[n] == '\0') { break; }
                                    result[result_i++] = mutation_2[n];
                                }
                            } else {
                                // Simply copy the char
                                result[result_i++] = password[m];
                            }
                            // Stop after the \0
                            if (password[m] == '\0') { break; }
                        }

                        // Stop when we reached '\0' in the mutation
                        if (mutation_2[l] == '\0') { break; }
                        // Otherwise, move mutation to the next one
                        mutation_2 += l + 1;
                    }
                }

                // Stop when we reached '\0' in the mutation
                if (mutation_1[j] == '\0') { break; }
                // Otherwise, move mutation to the next one
                mutation_1 += j + 1;
            }
        }

        /* Mutation 4: Create a version where we copy the password and then paste 'xor' or 'zorz' behind it. */
        {
            // Copy the password (twise)
            char* result_xor = GET_CHAR(mutated, mutated->size++);
            char* result_zorz = GET_CHAR(mutated, mutated->size++);
            strcpy(result_xor, password);
            strcpy(result_zorz, password);

            // Find the last character (applies to both, easily enough)
            int last = 0;
            for (; ; last++) {
                if (password[last] == '\0') { break; }
            }

            // Insert 'xor'
            result_xor[last]     = 'x';
            result_xor[last + 1] = 'o';
            result_xor[last + 2] = 'r';
            result_xor[last + 3] = '\0';

            // Insert 'zorz'
            result_zorz[last]     = 'z';
            result_zorz[last + 1] = 'o';
            result_zorz[last + 2] = 'r';
            result_zorz[last + 3] = 'z';
            result_zorz[last + 4] = '\0';
        }

        // /* Mutation 5: Add each of the special characters after the word. */
        for (int i = 0; ; i++) {
            char specialchar = SPECIAL_CHARS[i];
            if (specialchar == '\0') { break; }

            // Copy the password to the area
            char* result = GET_CHAR(mutated, mutated->size++);
            strcpy(result, password);

            // Find the last one
            for (int j = 0; ; j++) {
                if (result[j] == '\0') {
                    // Insert the special character instead
                    result[j] = specialchar;
                    result[j + 1] = '\0';
                    break;
                }
            }
        }

        /* Mutation 6: Add all years in the range 1950-1990 after the password, either full or abbreviated. */
        for (int year = 1960; year <= 2000; year++) {
            // Copy the password to the buffer - twice
            char* result = GET_CHAR(mutated, mutated->size++);
            char* result_abbr = GET_CHAR(mutated, mutated->size++);
            strcpy(result, password);
            strcpy(result_abbr, password);

            // Find the last position (will be the same for both)
            int last = 0;
            for (; ; last++) {
                if (result[last] == '\0') { break; }
            }

            // Append the year - long style
            int tyear = year;
            result[last]     = '0' + (tyear / 1000); tyear = tyear % 1000;
            result[last + 1] = '0' + (tyear / 100 ); tyear = tyear % 100;
            result[last + 2] = '0' + (tyear / 10  ); tyear = tyear % 10;
            result[last + 3] = '0' + tyear;
            result[last + 4] = '\0';

            // Append the year - short style
            tyear = (year % 1000) % 100;
            result_abbr[last]     = '0' + (tyear / 10); tyear = tyear % 10;
            result_abbr[last + 1] = '0' + tyear;
            result_abbr[last + 2] = '\0';
        }
    }

    /* Mutation 7: Add a set of all birthdays between now and 1950-1990. */
    for (int year = 1960; year <= 2020; year++) {
        for (int month = 0; month < 12; month++) {
            // Get the correct number of days for this month, correct for leap years
            int day_limit = month_map[month];
            if (month == 1 && year % 4 == 0 && year != 2020) { day_limit = 29; }
            // Loop through those days as well
            for (int day = 0; day < day_limit; day++) {
                // Insert this combination in all sorts of fashions
                sprintf(GET_CHAR(mutated, mutated->size++), "%02d%02d%d", day, month, year);
                sprintf(GET_CHAR(mutated, mutated->size++), "%02d%02d%d", month, day, year);
                sprintf(GET_CHAR(mutated, mutated->size++), "%d%d%d", day, month, year);
                sprintf(GET_CHAR(mutated, mutated->size++), "%d%d%d", month, day, year);
                
            }
        }
    }

    /* Mutation 8: Add a set of all 5-number combinations. */
    for (int a = 0; a < 10; a++) {
        for (int b = 0; b < 10; b++) {
            for (int c = 0; c < 10; c++) {
                for (int d = 0; d < 10; d++) {
                    for (int e = 0; e < 10; e++) {
                        sprintf(GET_CHAR(mutated, mutated->size++), "%d%d%d%d%d", a, b, c, d, e);
                    }
                }
            }
        }
    }

    /* Mutation 9: Add a set of all 6-number combinations. */
    for (int a = 0; a < 10; a++) {
        for (int b = 0; b < 10; b++) {
            for (int c = 0; c < 10; c++) {
                for (int d = 0; d < 10; d++) {
                    for (int e = 0; e < 10; e++) {
                        for (int f = 0; f < 10; f++) {
                            sprintf(GET_CHAR(mutated, mutated->size++), "%d%d%d%d%d%d", a, b, c, d, e, f);
                        }
                    }
                }
            }
        }
    }

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
    Array* plain = tdata->plain_passwords;
    Array* mutated = tdata->mutated_passwords;
    char* salt = tdata->salt;
    int salt_len = tdata->salt_len;
    int n_threads = nprocs();
    struct crypt_data cdata;
    cdata.initialized = 0;

    // Start with our time measurement
    #ifdef DEBUG
    struct timeval start_clock, stop_clock;
    gettimeofday(&start_clock, NULL);
    #endif

    /***** PHASE 1: PLAIN PASSWORDS *****/
    // Compute the start and stop index for the plain passwords
    long pstart = tdata->tid * (plain->size / n_threads);
    long pstop = tdata->tid < n_threads - 1 ? (tdata->tid + 1) * (plain->size / n_threads) - 1 : plain->size - 1;
    
    // Go through our range to compute the hashes & compare them once computed
    for (long p = pstart; p <= pstop; p++) {
        // Compute the hash
        char* result = crypt_r(GET_CHAR(plain, p), salt, &cdata);
        // Remove the salt bit from the result
        char* hash = result + salt_len;

        // Compare it with the hash we know each user has
        for (long i = 0; i < tdata->users->size; i++) {
            User* user = GET_USER(tdata->users, i);
            if (!user->guessed && streq(hash, user->hash)) {
                // We have this user, so print the result
                fprintf(stdout, "%s:%s\n", user->username, GET_CHAR(plain, p));
                fflush(stdout);
                // Mark that we guessed it
                user->guessed = 1;
            }
        }

        #ifdef DEBUG
        // Keep track of what we done
        ++tdata->n_hashes;
        #endif
    }

    /***** PHASE 2: MUTATED PASSWORDS *****/
    // Compute the start and stop index for the mutated passwords
    long mstart = tdata->tid * (mutated->size / n_threads);
    long mstop = tdata->tid < n_threads - 1 ? (tdata->tid + 1) * (mutated->size / n_threads) - 1 : mutated->size - 1;

    // Go through our range to compute the hashes & compare them once computed
    for (long p = mstart; p <= mstop; p++) {
        // Compute the hash
        char* result = crypt_r(GET_CHAR(mutated, p), salt, &cdata);
        // Remove the salt bit from the result
        char* hash = result + salt_len;

        // Compare it with the hash we know each user has
        for (long i = 0; i < tdata->users->size; i++) {
            User* user = GET_USER(tdata->users, i);
            if (!user->guessed && streq(hash, user->hash)) {
                // We have this user, so print the result
                fprintf(stdout, "%s:%s\n", user->username, GET_CHAR(mutated, p));
                fflush(stdout);
                // Mark that we guessed it
                user->guessed = 1;
            }
        }

        #ifdef DEBUG
        // Keep track of what we done
        ++tdata->n_hashes;
        #endif
    }

    /***** PHASE 3: COMBINING LONG PASSWORDS *****/
    // Loop through the plain passwords again to identify two long ones
    char buffer[MAX_PASSWORD_LENGTH * 2];
    for (long p1 = pstart; p1 <= pstop; p1++) {
        char* password1 = GET_CHAR(plain, p1);
        for (long p2 = 0; p2 < plain->size; p2++) {
            char* password2 = GET_CHAR(plain, p2);

            // If the combined lengths do not equal our target length, ignore them
            if (p1 == p2 || strlen(password1) + strlen(password2) != LONG_PASSWORD_LENGTH) { continue; }

            // Otherwise, merge them in a single string
            int buffer_i = 0;
            for (int i = 0; ; i++) {
                if (password1[i] == '\0') { break; }
                buffer[buffer_i++] = password1[i];
            }
            for (int i = 0; ; i++) {
                buffer[buffer_i++] = password2[i];
                if (password2[i] == '\0') { break; }
            }

            // Compute the hash of our new password
            char* result = crypt_r(buffer, salt, &cdata);
            char* hash = result + salt_len;

            // Compare it with the hash we know each user has
            for (long i = 0; i < tdata->users->size; i++) {
                User* user = GET_USER(tdata->users, i);
                if (!user->guessed && streq(hash, user->hash)) {
                    // We have this user, so print the result
                    fprintf(stdout, "%s:%s\n", user->username, buffer);
                    fflush(stdout);
                    // Mark that we guessed it
                    user->guessed = 1;
                }
            }

            #ifdef DEBUG
            // Keep track of what we done
            ++tdata->n_hashes;
            #endif
        }
    }

    // Note  the stopping time
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
        shadow_path = argv[2];
        if (argc >= 4) {
            dictionary_path = argv[3];
        }
    }

    #ifdef DEBUG
    // Print a neat intro thing
    fprintf(stderr, "\n*** GUESSWORD ***\n\n");
    fprintf(stderr, "Using:\n");
    fprintf(stderr, " - Path to shadow file                : '%s'\n", shadow_path);
    fprintf(stderr, " - Path to dictionary file            : '%s'\n", dictionary_path);
    fprintf(stderr, "\n");
    #endif

    // Check if the files exist by already acquiring FILE handles
    FILE* shadow_h = fopen(shadow_path, "r");
    if (shadow_h == NULL) {
        fprintf(stderr, "[ERROR] Could not open file '%s': %s\n", shadow_path, strerror(errno));
        return errno;
    }
    // Also get a handle for the dictionary & long words dictionary
    FILE* dictionary_h = fopen(dictionary_path, "r");
    if (dictionary_h == NULL) {
        fclose(shadow_h);
        fprintf(stderr, "[ERROR] Could not open file '%s': %s\n", dictionary_path, strerror(errno));
        return errno;
    }



    /***** Then, read the dictionary file with all the (plain) passwords. *****/
    // Create the array struct & populate it
    Array* plain_passwords = Array_create(MAX_PLAIN_PASSWORDS, sizeof(char) * MAX_PASSWORD_LENGTH);
    int result = read_passwords(plain_passwords, dictionary_h);
    fclose(dictionary_h);

    // Check if we were successful
    if (result != 0) {
        fclose(shadow_h);
        Array_destroy(plain_passwords);
        return result;
    }
    #ifdef DEBUG
    fprintf(stderr, "[INFO] Loaded %ld plain passwords.\n", plain_passwords->size);
    #endif



    /***** With the base passwords loaded, we want to mutate them to obtain better ones. *****/
    Array* mutated_passwords = Array_create(MAX_MUTATED_PASSWORDS, sizeof(char) * MAX_PASSWORD_LENGTH);
    result = mutate_passwords(mutated_passwords, plain_passwords);
    if (result != 0) {
        fclose(shadow_h);
        Array_destroy(plain_passwords);
        Array_destroy(mutated_passwords);
        return result;
    }
    #ifdef DEBUG
    fprintf(stderr, "[INFO] Generated %ld mutated passwords.\n", mutated_passwords->size);
    #endif



    /***** Extract a list of users and unique salts from the shadow file. *****/
    // First, declare an Array to store the salts in and one for the Users
    char salt[MAX_SALT_LENGTH];
    Array* users = Array_create(MAX_USERS, sizeof(User));
    
    // Now, call a function to do the work for us >:)
    result = read_shadow(salt, users, shadow_h);
    if (result != 0) {
        // Something bad happened; cleanup and return
        fclose(shadow_h);
        Array_destroy(plain_passwords);
        Array_destroy(mutated_passwords);
        Array_destroy(users);
        return result;
    }
    #ifdef DEBUG
    fprintf(stderr, "[INFO] Using salt string '%s'.\n", salt);
    fprintf(stderr, "[INFO] Loaded %ld users.\n", users->size);
    #endif



    /***** Then, we spawn threads which will handle the rest. *****/
    // Get the number of HW threads available on this machine
    int n_threads = nprocs();
    if (n_threads > plain_passwords->size) { n_threads = plain_passwords->size; }
    #ifdef DEBUG
    fprintf(stderr, "[INFO] Using %d threads.\n\n", n_threads);
    #endif
    
    // Spawn n_threads threads
    ThreadData threads[n_threads];
    for (int i = 0; i < n_threads; i++) {
        // First, we populate the ThreadData struct
        threads[i].tid = i;
        threads[i].plain_passwords = plain_passwords;
        threads[i].mutated_passwords = mutated_passwords;
        threads[i].salt = salt;
        threads[i].salt_len = strlen(salt);
        threads[i].users = users;

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
        float hashes_per_second = (threads[i].n_hashes) / threads[i].elapsed;
        if (i == 0) { fprintf(stderr, "\n"); }
        fprintf(stderr, "[INFO] Thread %d computed %lu hashes in %fs = %f hashes/s.\n",
                threads[i].tid, threads[i].n_hashes, threads[i].elapsed,
                hashes_per_second);
        total_hps += hashes_per_second;
        #endif
    }
    #ifdef DEBUG
    fprintf(stderr, "[INFO] Average thread speed = %f hashes/s.\n", total_hps / (float) n_threads);
    #endif


    
    /***** Finally, clean up. *****/
    // Close the files
    fclose(shadow_h);

    // Deallocate the heap memory
    Array_destroy(plain_passwords);
    Array_destroy(mutated_passwords);
    Array_destroy(users);

    /* Done! */
    return 0;
}
