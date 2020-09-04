/* GUESSWORD.c
 *   by HACKER_HANDLE
 *
 * Created:
 *   02/09/2020, 20:34:28
 * Last edited:
 *   9/4/2020, 2:39:21 PM
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

/* Allows the user to index the one-dimensional array in a Passwords-struct as if it were 2-dimension. */
#define INDEX(PWDS, Y, X) \
    ((PWDS)->data[(Y) * (MAX_PASSWORD_LENGTH + 1) + (X)])
/* Allows the user to get a char* from a single password in a Passwords-struct. */
#define GET_PWD(PWDS, Y) \
    ((PWDS)->data + (Y) * (MAX_PASSWORD_LENGTH + 1))



/***** CONSTANTS *****/

/* Determines the maximum number of passwords stored in memory. */
#define MAX_PASSWORDS 10000000
/* Determines the maximum length of a single password. */
#define MAX_PASSWORD_LENGTH 128
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

/* The Passwords-struct, which contains a pointer to the list of passwords and the number of passwords. */
typedef struct PASSWORDS {
    char* data;
    int size;
} Passwords;

/* The User-struct, which contains information on a user (his username, the hash & the matching salt). */
typedef struct USER {
    char* username;
    char* hash;
    char* salt;
    int salt_len;
} User;



/***** HELPER FUNCTIONS *****/

/* Reads the given file as if it was a dictionary, and returns a dictionary with size 'sizeof(char) * MAX_PASSWORDS * (MAX_PASSWORD_LENGTH + 1)'. Returns NULL if some error occurred. */
Passwords* read_passwords(FILE* dictionary) {
    Passwords* passwords = malloc(sizeof(Passwords) + sizeof(char) * MAX_PASSWORDS * (MAX_PASSWORD_LENGTH + 1));
    passwords->data = ((char*) passwords) + sizeof(Passwords);
    passwords->size = 0;
    int password_i = 0;
    char buff[CHUNK_SIZE];

    // Loop and read the file
    int stop = 0;
    int line = 0;
    while (!stop && fgets(buff, sizeof(buff), dictionary) != NULL) {
        for (int i = 0; i < CHUNK_SIZE; i++) {
            char c = buff[i];
            if (c == '\n') {
                line++;
                
                // Move to the next password after finishing this one with '\0'
                INDEX(passwords, passwords->size, password_i) = '\0';
                passwords->size++;
                password_i = 0;
                break;
            } else if (c != '\0') {
                // Make sure we're not overflowing
                if (passwords->size == MAX_PASSWORDS) {
                    // Number of passwords overflows
                    fprintf(stderr, "[WARNING] Reading too many passwords from '" DICTIONARY_PATH "', stopping early.\n");
                    stop = 1;
                    break;
                } else if (password_i == MAX_PASSWORD_LENGTH - 1) {
                    // Length of one password overflows
                    fprintf(stderr, "[WARNING] Password on line %d is too long, splitting after reading %d characters.\n", line, MAX_PASSWORD_LENGTH);
                    INDEX(passwords, passwords->size, password_i) = '\0';
                    passwords->size++;
                    password_i = 0;
                    break;
                } else {
                    // Otherwise, write that character to the buffer
                    INDEX(passwords, passwords->size, password_i++) = c;
                }
            }
        }
    }

    // If we didn't hit EOF, something must have gone wrong
    if (!stop && !feof(dictionary)) {
        free(passwords);
        fprintf(stderr, "[ERROR] Could not read from file '" DICTIONARY_PATH "': %s\n", strerror(errno));
        return NULL;
    }

    // Otherwise, return the passwords
    return passwords;
}

/* Reads a single line from a given shadow file, and then parses that to the given User object. Returns 1 if it was successful, 0 if EOF was reached and -1 if an error occured. */
int get_user(User* user, int line, FILE* handle) {
    // Try to read whatever is left in the buffer
    char buffer[CHUNK_SIZE];
    if (fgets(buffer, sizeof(buffer), handle) == NULL) {
        if (feof(handle)) {
            return 0;
        } else {
            fprintf(stderr, "[ERROR] Could not read from shadow file: %s\n", strerror(errno));
            return -1;
        }
    }

    // Reset the user's fields to be empty strings so we can check if there is something
    user->username[0] = '\0';
    user->salt[0] = '\0';
    user->salt_len = 0;
    user->hash[0] = '\0';
    
    // If succesful, we attempt to parse this
    int index = 0;
    ParseState state = username;
    int n_dollars = 0;
    for (int i = 0; state != done && i < CHUNK_SIZE; i++) {
        char c = buffer[i];
        switch(state) {
            case username:
                if (c == ':') {
                    user->username[index] = '\0';
                    state = salt;
                    index = 0;
                } else {
                    user->username[index++] = c;
                }
                break;
            case salt:
                if (c == '$') {
                    n_dollars++;
                    if (n_dollars == 3) {
                        user->salt[index] = '$';
                        user->salt[index + 1] = '\0';
                        state = hash;
                        index = 0;
                        break;
                    }
                }
                user->salt[index++] = c;
                user->salt_len++;
                break;
            case hash:
                if (c == ':') {
                    user->hash[index] = '\0';
                    state = done;
                } else {
                    user->hash[index++] = c;
                }
                break;
            case done:
                // Nothing, just skip
                break;
        }
    }

    // Check if any of them have been written to
    if (user->username[0] == '\0') {
        fprintf(stderr, "[ERROR] Missing username on line %d in shadow file.\n", line);
        return -1;
    } else if (user->salt[0] == '\0') {
        fprintf(stderr, "[ERROR] Missing salt on line %d in shadow file.\n", line);
        return -1;
    } else if (user->hash[0] == '\0') {
        fprintf(stderr, "[ERROR] Missing hash on line %d in shadow file.\n", line);
        return -1;
    } else if (state != done) {
        fprintf(stderr, "[ERROR] Missing closing ':' after hash on line %d in shadow file.\n", line);
        return -1;
    }

    // If we made it until here, it checks out - so return
    return 1;

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



    /***** Then, read the dictionary file with all the passwords. *****/
    Passwords* passwords = read_passwords(dictionary);
    fclose(dictionary);
    if (passwords == NULL) {
        fclose(shadow_h);
        return errno;
    }
    #ifdef DEBUG
    fprintf(stderr, "[INFO] Loaded %d passwords.\n", passwords->size);
    #endif



    /***** Next, extract a list of users and unique salts from the shadow file. *****/
    // We will call a function for this



    /***** Then, we spawn threads which will first compute their share of hashes, and
     ***** then start comparing those to the hashes we have for all users. *****/
    // Get the number of HW threads available on this machine


    
    /***** Finally, wait until all threads are finished and clean up. *****/
    // Close the files
    fclose(shadow_h);

    // Deallocate
    free(user->username);
    free(user->hash);
    free(user->salt);
    free(user);
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
