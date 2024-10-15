#ifndef _COMMANDS_H_
#define _COMMANDS_H_ 


#include "includes.h"
EXTERN_C_START;


// Status codes
typedef enum {
    SS_STATUS_SUCCESS = 0,                      // Operation was successful
    SS_STATUS_USER_ALREADY_EXISTS = 1,          // User already exists
    SS_STATUS_INVALID_USERNAME = 2,             // Username is invalid
    SS_STATUS_INVALID_PASSWORD = 3,             // Password is invalid
    SS_STATUS_USER_NOT_FOUND = 4,               // User not found
    SS_STATUS_LOGIN_FAILED = 5,                 // Login failed due to incorrect password
    SS_STATUS_NOT_LOGGED_IN = 6,                // No user is currently logged in
    SS_STATUS_FILE_NOT_FOUND = 7,               // Specified file not found
    SS_STATUS_MEMORY_ALLOCATION_FAILED = 8,     // Memory allocation failed
    SS_STATUS_HASH_FAILED = 9,                  // Hashing failed
    SS_STATUS_UNKNOWN_ERROR = 10                // An unknown error occurred
} SafeStorageStatus;


// Macro definitions for username and password requirements
#define USERNAME_MIN_LENGTH 5
#define USERNAME_MAX_LENGTH 10
#define PASSWORD_MIN_LENGTH 5


// Special character set for password validation
#define SPECIAL_CHARACTERS "!@#$%^&*"


/*
 * @brief       This command will be called at the beginning to initialize support for the safe storage lib.
 *              Here you can create global data, find %APPDIR%, and allocate/ create any resources you consider necessary
 *              to function correctly. It is guaranteed that this command will be called before any other commands.
 */
NTSTATUS WINAPI
SafeStorageInit(
    VOID
);


/*
 * @brief       This command will be called at the end to perform cleanup.
 *              Here you can deallocate global data and any other resources you have used.
 *
 */
VOID WINAPI
SafeStorageDeinit(
    VOID
);


/*
 * @brief       Handles the "register" command.
 *
 *
 * @details     This command is available only if no user is currently logged in.
 *              If a user is logged in, this command will return an error status.
 *
 *              If there is already a user with the name from the "Username" string,
 *              the command will return an error status.
 *
 *              If the user is successfully registered, a subdirectory
 *              %APPDIR%\\Users\\<Username> will be created. A unique identifier (e.g. a pair (username, password)) will be
 *              saved in a separate file %APPDIR%\\users.txt.
 *              The password will not be saved in plain text (see the @note section below).
 *              If the "Users" subdirectory does not exist in %APPDIR%, it must be created before creating the <Username> directory.
 *              %APPDIR%
 *                 |- Users
 *                     |- <Username>
 *
 *
 * @param[in]   Username        - A string representing the username.
 *
 * @param[in]   UsernameLength  - The length of the "Username" string,
 *                                not including the NULL terminator.
 *
 * @param[in]   Password        - A string representing the user's password.
 *
 * @param[in]   PasswordLength  - The length of the "Password" string,
 *                                not including the NULL terminator.
 *
 *
 * @note        Some limits are imposed on the strings:
 *                      - Username string: must contain only English alphabet letters (a-zA-Z);
 *                                         must contain a minimum of 5 characters and a maximum of 10;
 *                      - Password string: must be at least 5 characters long;
 *                                         must contain at least one digit;
 *                                         must contain at least one lowercase letter and one uppercase letter;
 *                                         must contain at least one special symbol (!@#$%^&);
 *              The password will not be saved in plain text (how you store the password is up to you):
 *                      - suggestions: MD5, SHA256
 *                      - see https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--creating-an-md-5-hash-from-file-content
 *              Don't forget to sanitize the parameters.
 */
NTSTATUS WINAPI
SafeStorageHandleRegister(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
);


/*
 * @brief       Handles the "login" command.
 *
 *
 * @details     This command is available only if no user is currently logged in.
 *              If a user is logged in, this command will return an error status.
 *
 *              It will attempt to log in the specified user.
 *              It checks %APPDIR%\\users.txt and performs the necessary password validations.
 *
 *              If the user does not exist or the password is incorrect, an error status will be returned.
 *              If a match is found, the respective user will be "logged in", and the store and retrieve commands
 *              will become available.
 *
 *
 * @param[in]   Username        - A string representing the username.
 *
 * @param[in]   UsernameLength  - The length of the "Username" string,
 *                                not including the NULL terminator.
 *
 * @param[in]   Password        - A string representing the user's password.
 *
 * @param[in]   PasswordLength  - The length of the "Password" string,
 *                                not including the NULL terminator.
 *
 *
 * @note        Don't forget to sanitize the parameters!
 *
 */
NTSTATUS WINAPI
SafeStorageHandleLogin(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
);


/*
 * @brief       Handles the "logout" command.
 *
 *
 * @details     This command is available only if a user is currently logged in.
 *              If NO user is logged in, this command will return an error status.
 *
 *              After the execution of this command, no user will be logged in, and the register and login commands will become available again.
 *              The store and retrieve commands will no longer be available.
 */
NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
);


/*
 * @brief       Handles the "store" command.
 *
 *
 * @details     This command is available only if a user is currently logged in.
 *              If NO user is logged in, this command will return an error status.
 *
 *              Copies the contents of the file provided by the SourceFilePath parameter to
 *                  %APPDIR%\\Users\\<current_logged_in_user>\\<SubmissionName>.
 *
 *              If no file exists with the name SourceFilePath, the function will return an error.
 *
 *              If a file already exists at %APPDIR%\\Users\\<current_logged_in_user>\\<SubmissionName>, it will be overwritten.
 *
 *
 * @param[in]   SubmissionName          - A string representing the submission name.
 *
 * @param[in]   SubmissionNameLength    - The length of the "SubmissionName" string,
 *                                        not including the NULL terminator.
 *
 * @param[in]   SourceFilePath          - A string representing the absolute path,
 *                                        where the file to be uploaded is located.
 *
 * @param[in]   SourceFilePathLength    - The length of the "SourceFile" string,
 *                                        not including the NULL terminator.
 *
 *
 * @note        Don't forget to sanitize the parameters!
 *              For maximum points and to optimize the transfer, the file should be read and written in 4KB chunks using a thread pool.
 *              See https://learn.microsoft.com/en-us/windows/win32/procthread/using-the-thread-pool-functions.
 *              Alternatively, you can implement your own thread pool.
 *
 */
NTSTATUS WINAPI
SafeStorageHandleStore(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* SourceFilePath,
    uint16_t SourceFilePathLength
);


/*
 * @brief       Handles the "retrieve" command.
 *
 *
 * @details     This command is available only if a user is currently logged in.
 *              If NO user is logged in, this command will return an error status.
 *
 *              Copies the contents of the file %APPDIR%\\Users\\<current_logged_in_user>\\<SubmissionName> to DestinationFilePath.
 *
 *              If no source file exists, the function will return an error.
 *
 *              If a file already exists at DestinationFilePath, it will be overwritten.
 *
 *
 * @param[in]   SubmissionName              - A string representing the submission name.
 *
 * @param[in]   SubmissionNameLength        - The length of the "SubmissionName" string,
 *                                            not including the NULL terminator.
 *
 * @param[in]   DestinationFilePath         - A string representing the absolute path,
 *                                            where the submission will be copied.
 *
 * @param[in]   DestinationFilePathLength   - The length of the "DestinationFilePath" string,
 *                                            not including the NULL terminator.
 *
 * @note        Don't forget to sanitize the parameters!
 *              For maximum points and to optimize the transfer, the file should be read and written in 4KB chunks using a thread pool.
 *              See https://learn.microsoft.com/en-us/windows/win32/procthread/using-the-thread-pool-functions.
 *              Alternatively, you can implement your own thread pool.
 *
 */
NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* DestinationFilePath,
    uint16_t DestinationFilePathLength
);


EXTERN_C_END;
#endif  //_COMMANDS_H_
