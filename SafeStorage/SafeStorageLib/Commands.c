#include "Commands.h"
#include <stdbool.h>
#include <strsafe.h>
#include <errno.h>

#define MAX_USERNAME_LENGTH 10

// Function declarations

/**
 * @brief       Validates the username based on specified criteria.
 *
 * @param       username       The username to validate.
 * @param       usernameLength The length of the username.
 * @return      TRUE if the username is valid; otherwise, FALSE.
 */
bool isValidUsername(_In_reads_ (usernameLength) const char* username, _In_ uint16_t usernameLength) {
    // Check length
    if (usernameLength < 5 || usernameLength > 10) {
        return false;
    }

    // Check if all characters are alphabetic
    for (uint16_t i = 0; i < usernameLength; i++) {
        if (!isalpha(username[i])) {
            return false;
        }
    }

    return true;
}


/**
 * @brief       Validates the password based on specified criteria.
 *
 * @param       password        The password to validate.
 * @param       passwordLength  The length of the password.
 * @return      TRUE if the password is valid; otherwise, FALSE.
 */
bool isValidPassword(_In_reads_ (passwordLength) const char* password, _In_ uint16_t passwordLength)
{
    // Check length
    if (passwordLength < 5) {
        return false;
    }

    // Variables for checking password requirements
    bool hasDigit = false;
    bool hasLower = false;
    bool hasUpper = false;
    bool hasSpecial = false;

    // Check content of the password
    for (uint16_t i = 0; i < passwordLength; i++) {
        if (isdigit(password[i])) {
            hasDigit = true;
        }

        else if (islower(password[i])) {
            hasLower = true;
        }

        else if (isupper(password[i])) {
            hasUpper = true;
        }

        else if (strchr("!@#$%^&", password[i])) {
            hasSpecial = true;
        }
    }

    // Password meets all requirements
    return hasDigit && hasLower && hasUpper && hasSpecial;
}


/**
 * @brief       Stores the user's credentials (username and hashed password) in the users.txt file.
 *
 * @param       username        The username to be stored.
 * @param       hashedPassword  The hashed password to be stored.
 * @return      TRUE if the credentials are stored successfully; otherwise, FALSE.
 */
bool StoreUserCredentials(_In_z_ const char* username, _In_reads_bytes_(HASH_LENGTH) const char* password) {
    char AppDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, AppDir);

    // Construct the path to the users.txt file
    char usersFilePath[MAX_PATH];
    sprintf_s(usersFilePath, MAX_PATH, "%s\\users.txt", AppDir);

    // Open users.txt for appending
    FILE* file = fopen(usersFilePath, "a");
    if (file == NULL) {
        printf("Error opening file for writing: %s\n", strerror(errno));
        return false;
    }
    
    // Write username and hashed password
    fprintf(file, "%s %s\n", username, password);

    fclose(file);
    return true;
}

/**
 * @brief       Checks if a user is already registered by checking the users.txt file.
 *
 * @param       username        The username to be checked.
 * @return      TRUE if the user is already registerd; otherwise, FALSE.
 */
bool UserAlreadyRegistered(_In_ const char* username) {
    char AppDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, AppDir);

    // Construct the path to the users.txt file.
    char usersFilePath[MAX_PATH];
    sprintf_s(usersFilePath, MAX_PATH, "%s\\users.txt", AppDir);

    // Open users.txt file for reading.
    FILE* file = fopen(usersFilePath, "r");
    if (file == NULL) {
        // Handle error
        return false;   // user not registered if the file does not exist.
    }
    
    char line[MAX_USERNAME_LENGTH + 1]; // Buffer to hold each line of the file
    // Read lines and check for the username
    while (fgets(line, sizeof(line), file)) {
        // Remove newline character from the line if present
        line[strcspn(line, "\n")] = 0;

        // Compare the line with provided username
        if (strcmp(line, username) == 0) {
            fclose(file);
            return true;    // User is registered
        }
    }

    fclose(file);
    return false;   // User found, already registered
}


NTSTATUS WINAPI
SafeStorageInit(
    VOID
)
{
    /* The function is not implemented. It is your responsibility. */
    /* Here you can create any global objects you consider necessary. */

    return STATUS_SUCCESS;
}


VOID WINAPI
SafeStorageDeinit(
    VOID
)
{
    /* The function is not implemented. It is your responsibility. */
    /* Here you can clean up any global objects you have created earlier. */

    return;
}


NTSTATUS WINAPI
SafeStorageHandleRegister(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    char AppDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, AppDir);

    // Validate username
    if (!isValidUsername(Username, UsernameLength)) {
        printf("Invalid Username\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Validate password
    if (!isValidPassword(Password, PasswordLength)) {
        printf("Invalid Password\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Check if the username already exists in users.txt
    if (UserAlreadyRegistered(Username)) {
        printf("User already exists\n");
        return STATUS_USER_EXISTS;
    }

    // Create user directory
    char userDirectory[MAX_PATH];
    sprintf(userDirectory, "%s\\users\\%s", AppDir, Username);

    // Check if parent directory exists
    char usersDir[MAX_PATH];
    sprintf(usersDir, "%s\\users", AppDir);
    if (!CreateDirectoryA(usersDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        printf("Error creating users directory: %s\n", strerror(errno));
        return SS_STATUS_MEMORY_ALLOCATION_FAILED;
    }

    if (!CreateDirectoryA(userDirectory, NULL)) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_ALREADY_EXISTS) {
            printf("Directory already exists\n");
        }
        else {
            printf("Error creating directory: %s\n", strerror(dwError));
        }
        return SS_STATUS_MEMORY_ALLOCATION_FAILED;
    }

    // Hash the password
    /*char hashedPassword[HASH_LENGTH];
    if (!HashPassword(Password, PasswordLength, hashedPassword)) {
        return STATUS_HASH_FAILED;
    }*/

    // Store the username and hashed password in users.txt
    if (!StoreUserCredentials(Username, Password)) {
        printf("Failed to store user credentials\n");
        return SS_STATUS_MEMORY_ALLOCATION_FAILED;
    }

    return SS_STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleLogin(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(Username);
    UNREFERENCED_PARAMETER(UsernameLength);
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(PasswordLength);

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    /* The function is not implemented. It is your responsibility. */

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleStore(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* SourceFilePath,
    uint16_t SourceFilePathLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(SubmissionName);
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(SourceFilePath);
    UNREFERENCED_PARAMETER(SourceFilePathLength);

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* DestinationFilePath,
    uint16_t DestinationFilePathLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(SubmissionName);
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(DestinationFilePath);
    UNREFERENCED_PARAMETER(DestinationFilePathLength);

    return STATUS_NOT_IMPLEMENTED;
}
