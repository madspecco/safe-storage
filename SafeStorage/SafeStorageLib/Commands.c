#include "Commands.h"
#include <stdbool.h>


// Function declarations

/**
 * @brief       Validates the username based on specified criteria.
 *
 * @param       username       The username to validate.
 * @param       usernameLength The length of the username.
 * @return      TRUE if the username is valid; otherwise, FALSE.
 */
bool isValidUsername(_In_reads_(usernameLength) const char* username, _In_ uint16_t usernameLength) {
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
bool isValidPassword(_In_reads_(passwordLength) const char* password, _In_ uint16_t passwordLength)
{
    // Prevent warnings/errors until implementation
    UNREFERENCED_PARAMETER(password);
    UNREFERENCED_PARAMETER(passwordLength);

    // Implement later
    return true;  // Temporary return value
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
        return STATUS_INVALID_PARAMETER;
    }

    // Validate password
    if (!isValidPassword(Password, PasswordLength)) {
        return STATUS_INVALID_PARAMETER;
    }

    // Check if the username already exists in users.txt
    //if (UserAlreadyRegistered(Username)) {
    //    return STATUS_USER_EXISTS;
    //}

    // Create user directory
    //char userDirectory[MAX_PATH];
    //sprintf(userDirectory, "%s\\users\\%s", AppDir, Username);
    //if (!CreateDirectoryA(userDirectory, NULL)) {
    //    return STATUS_CANNOT_CREATE_DIRECTORY;
    //}

    // Hash the password
    /*char hashedPassword[HASH_LENGTH];
    if (!HashPassword(Password, PasswordLength, hashedPassword)) {
        return STATUS_HASH_FAILED;
    }*/

    // Store the username and hashed password in users.txt
    //if (!StoreUserCredentials(Username, hashedPassword)) {
    //    return STATUS_CANNOT_WRITE_FILE;
    //}

    return STATUS_SUCCESS;
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
