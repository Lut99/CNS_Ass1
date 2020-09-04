/* GUESSWORD.c
 *   by HACKER_HANDLE
 *
 * Created:
 *   02/09/2020, 20:34:28
 * Last edited:
 *   04/09/2020, 18:30:55
 * Auto updated?
 *   Yes
 *
 * Description:
 *   This file contains the code needed for Assignment 1 of the course
 *   Computer & Network Security. Specifically, it contains a program that,
 *   given a list of dictionaries, can use those to try and guess the
 *   passwords stored in Linux user & shadow files.
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <crypt.h>


/***** MACROS *****/

/* Allows the user to get an character array from a multidimensional array in an Array-struct. */
#define GET_CHAR(ARR, Y) \
    ((ARR)->data + (Y) * ((ARR)->max_size + 1))



/***** CONSTANTS *****/

/* Determines the maximum number of passwords stored in memory. */
#define MAX_PASSWORDS 10000000
/* Determines the maximum length of a single password (including null-termination). */
#define MAX_PASSWORD_LENGTH 64
/* Determines the maximum number of salts loaded in memory at a time. */
#define MAX_SALTS 128
/* Determines the maximum number of characters a salt can exist of (including null-termination). */
#define MAX_SALT_LENGTH 3
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
    hash,
    done
} ParseState;



/***** STRUCTS *****/

/* The Array-struct, which contains a pointer to the a list of char arrays. */
typedef struct ARRAY {
    char* data;
    int size;
    int max_size;
} Array;

/* The User-struct, which contains information on a user (his username, the hash & the matching salt). */
typedef struct USER {
    char* username;
    char* hash;
    int salt_id;
} User;



/***** HELPER FUNCTIONS *****/

/* Reads the given file as if it was a dictionary, and returns a Passwords struct with array size 'sizeof(char) * MAX_PASSWORDS * (MAX_PASSWORD_LENGTH + 1)'. Returns NULL if some error occurred. */
Array* read_passwords(FILE* dictionary) {
    // Allocate & preparet hte passwords struct
    Array* passwords = malloc(sizeof(Array) + sizeof(char) * MAX_PASSWORDS * MAX_PASSWORD_LENGTH);
    passwords->data = ((char*) passwords) + sizeof(Array);
    passwords->size = 0;
    passwords->max_size = MAX_PASSWORDS;

    // Loop and read the file
    for (;passwords->size < MAX_PASSWORDS && fgets(GET_PWD(passwords, passwords->size++), MAX_PASSWORD_LENGTH, dictionary) != NULL;) {}

    // Check if anything illegal occured
    if (passwords->size < MAX_PASSWORDS && !feof(dictionary)) {
        // Stopped prematurly; we errored somehow
        free(passwords);
        fprintf(stderr, "[ERROR] Could not read from file '" DICTIONARY_PATH "': %s\n", strerror(errno));
        return NULL;
    } else if (passwords->size == MAX_PASSWORDS) {
        // We stopped because of an overflow; reinstate the correct size and continue with the first MAX_PASSWORDS passwords
        #ifdef DEBUG
        fprintf(stderr, "[WARNING] Reading too many passwords from '" DICTIONARY_PATH "', stopping early.\n");
        #endif
        passwords->size--;
    } else if (passwords->size > MAX_PASSWORDS) {
        // Sanity check; shouldn't happen
        free(passwords);
        fprintf(stderr, "[ERROR] Got too many passwords from '" DICTIONARY_PATH "'.\n");
        return NULL;
    }
    
    // Trim newlines
    for (int i = 0; i < passwords->size; i++) {
        for (int j = 0; j < MAX_PASSWORD_LENGTH; j++) {
            char c = GET_CHAR(passwords, i)[j];
            if (c == '\n') {
                GET_CHAR(passwords, i)[j] = '\0';
                break;
            }
        }
    }
    
    // If everything checks out, return the passwords
    return passwords;
}

/* Reads a shadow file to memory. Returns a list of User objects that describes each user in the file, and a list of all unique salts used. Return '1' if successful or '0' otherwise. */
int read_shadow(Array* salts, Array* users, FILE* handle) {
    // Let's loop through the handle
    char buffer[CHUNK_SIZE];
    int line = 0;
    

    // while (fgets(buffer, CHUNK_SIZE, handle) != NULL) {
    //     // Loop through the buffer to extract useful information
    //     ParseState state = username;
    //     int stop = 0;
    //     int target_i = 0;
    //     int dollar_count = 0;
    //     for (int i = 0; stop == 0 && i < CHUNK_SIZE; i++) {
    //         char c = buffer[i];
    //         switch(state) {
    //             case username:
    //                 if (c == '\n' || c == '\0') {
    //                     // We didn't finish the username; skip this user
    //                     #ifdef DEBUG
    //                     fprintf(stderr, "[WARNING] Encountered user with only a username on line %d; skipping\n", line);
    //                     #endif
                        
    //                     if (c == '\n') { line++; }
    //                     stop = 1;
    //                 } else if (c == ':') {
    //                     // Add null-termination to the username, then move to the next state
    //                     ((User*) users->data[users->size])->username[target_i] = '\0';
    //                     target_i = 0;
    //                     state = salt;
    //                 } else {
    //                     // Add to the username
    //                     ((User*) users->data[users->size])->username[target_i++] = c;
    //                 }
    //                 break;
    //             case salt:
    //                 if (c == '\n' || c == '\0') {
    //                     // We didn't finish the salt; skip this user
    //                     #ifdef DEBUG
    //                     fprintf(stderr, "[WARNING] Encountered user with only a username and a salt on line %d; skipping\n", line);
    //                     #endif
    //                     if (c == '\n') { line++; }
    //                     stop = 1;
    //                 } else if (c == '$') {
    //                     // Add it to the salt
    //                     GET_CHAR(salts, salts->size)[target_i++] = c;
    //                     if (dollar_count++ == 2) {
    //                         // Finish it with a '\0', and then move to the next state
    //                         GET_CHAR(salts, salts->size)[target_i] = '\0';
    //                         target_i = 0;
    //                         state = hash;
    //                     }
    //                 } else {
    //                     // Add to the salt
    //                     GET_CHAR(salts, salts->size)[target_i++] = c;
    //                 }
    //                 break;
    //             case hash:
    //                 if (c == ':' || c == '\n' || c == '\0') {
    //                     // Make sure the hash has enough characters
    //                     if (target_i != 22) {
    //                         #ifdef DEBUG
    //                         fprintf(stderr, "[WARNING] Encountered hash with incorrect size on line %d; skipping\n", line);
    //                         #endif
    //                     }
    //                     if (c == '\n') { line++; }
    //                 }
    //         }
    //     }
    // }
    // if (salts->size < salts->max_size && users->size < users->max_size && !feof(handle)) {
    //     // Stopped prematurly; we errored somehow
    //     fprintf(stderr, "[ERROR] Could not read from file '" DICTIONARY_PATH "': %s\n", strerror(errno));
    //     return 0;
    // }

    return 0;
}



/***** MAIN *****/
int main(int argc, const char** argv) {
    /***** Initialize by parsing command line args and opening handles. *****/
    // Read the CL-args
    // const char* passwd_path;
    const char* shadow_path;
    if (argc != 3) {
        printf("Usage: %s passwd_path shadow_path\n", argv[0]);
        exit(0);
    } else {
        // Actually ifnore the passwd for now, as I think everything we need to know is in the shadow file.
        // passwd_path = argv[1];
        shadow_path = argv[2];
    }

    // Check if the files exist by already acquiring FILE handles
    FILE* shadow_h = fopen(shadow_path, "r");
    if (shadow_h == NULL) {
        fprintf(stderr, "[ERROR] Could not open file '%s': %s\n", shadow_path, strerror(errno));
        return errno;
    }
    // Also get a handle for the hardcoded dictionary.txt
    FILE* dictionary = fopen(DICTIONARY_PATH, "r");
    if (dictionary == NULL) {
        fclose(shadow_h);
        fprintf(stderr, "[ERROR] Could not open file '%s': %s\n", DICTIONARY_PATH, strerror(errno));
        return errno;
    }



    /***** Next, extract a list of users and unique salts from the shadow file. *****/
    // First, declare an Array to store the salts in
    Array* salts = malloc(sizeof(Array) + sizeof(char) * MAX_SALTS * (MAX_SALT_LENGTH + 1));
    salts->data = ((char*) salts) + sizeof(Array);
    salts->size = 0;
    salts->max_size = MAX_SALTS;

    // Then, another Array to declare the Users
    Array* users = malloc(sizeof(Array) + sizeof(User) * MAX_USERS);
    users->data = ((char*) users) + sizeof(Array);
    users->size = 0;
    users->max_size = MAX_USERS;
    
    // Now, call a function to do the work for us >:)
    read_shadow(salts, users, shadow_h);



    /***** Then, read the dictionary file with all the passwords. *****/
    Array* passwords = read_passwords(dictionary);
    fclose(dictionary);
    if (passwords == NULL) {
        fclose(shadow_h);
        return errno;
    }
    #ifdef DEBUG
    fprintf(stderr, "[INFO] Loaded %d passwords.\n", passwords->size);
    #endif



    /***** Then, we spawn threads which will first compute their share of hashes, and
     ***** then start comparing those to the hashes we have for all users. *****/
    // Get the number of HW threads available on this machine


    
    /***** Finally, wait until all threads are finished and clean up. *****/
    // Close the files
    fclose(shadow_h);

    // Deallocate
    free(passwords);

    /* Done! */
    return 0;


    // /***** Next, start reading the passwd file *****/
    // // Create a User object to store each parsed user
    // User* user = malloc(sizeof(User));
    // user->username = malloc(sizeof(char) * CHUNK_SIZE);
    // user->hash = malloc(sizeof(char) * CHUNK_SIZE);
    // user->salt = malloc(sizeof(char) * CHUNK_SIZE);
    // // Get users as long as there are any
    // int line = 0;
    // while (1) {
    //     int result = get_user(user, line, shadow_h);
    //     if (result == 0) { break; }
    //     else if (result == -1) {
    //         // Something bad happened, so let's quit
    //         fclose(shadow_h);
    //         free(user->username);
    //         free(user->hash);
    //         free(user->salt);
    //         free(user);
    //         free(passwords);
    //         exit(errno);
    //     }
        
    //     #ifdef DEBUG
    //     fprintf(stderr, "[INFO] Considering user '%s'...\n", user->username);
    //     #endif

    //     // Try to hash each password on this user until we find one
    //     for (int i = 0; i < passwords->size; i++) {
    //         #ifdef DEBUG
    //         fprintf(stderr, "[INFO]    Computing hash %d/%d\r", i + 1, passwords->size);
    //         #endif

    //         char* pwd = GET_PWD(passwords, i);
    //         char* result = crypt(pwd, user->salt);

    //         // Fetch the key-part from the result & check if it's correct
    //         char* guess = result + user->salt_len;
    //         if (strcmp(guess, user->salt) == 0) {
    //             fprintf(stdout, "%s:%s\n", user->username, pwd);
    //             fflush(stdout);
    //             break;
    //         }
    //     #ifdef DEBUG
    //     fprintf(stderr, "\n");
    //     #endif
        
    //     // Don't forget to increment the line number
    //     line++;
    // }
}
