#include "Commands.h"
#include <stdbool.h>
#include <strsafe.h>
#include <errno.h>


// Global static variables
static bool g_IsUserLoggedIn = false;
static char g_LoggedInUsername[USERNAME_MAX_LENGTH + 1] = { 0 };


// Function declarations
/**
 * @brief       Converts a binary hash to a hexadecimal string.
 *
 * @param       hash            The binary hash.
 * @param       hashLength      The length of the hash (HASH_LENGTH).
 * @param       hexString       The output buffer for the hexadecimal string (must be 2 * HASH_LENGTH + 1 bytes).
 */
void ConvertHashToHexString(_In_reads_bytes_(hashLength) const char* hash, _In_ uint16_t hashLength, _Out_writes_(2 * hashLength + 1) char* hexString) {
    for (uint16_t i = 0; i < hashLength; i++) {
        sprintf_s(hexString + (i * 2), 3, "%02x", (unsigned char)hash[i]);
    }
    hexString[2 * hashLength] = '\0';   // Null-terminate the string
}


/**
 * @brief       Validates the username based on specified criteria.
 *
 * @param       username       The username to validate.
 * @param       usernameLength The length of the username.
 * @return      TRUE if the username is valid; otherwise, FALSE.
 */
bool isValidUsername(_In_reads_ (usernameLength) const char* username, _In_ uint16_t usernameLength) {
    // Check length
    if (usernameLength < USERNAME_MIN_LENGTH || usernameLength > USERNAME_MAX_LENGTH) {
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
    if (passwordLength < PASSWORD_MIN_LENGTH) {
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
 * @brief       Hashes the password using the SHA-256 algorithm.
 *
 * @param       password        The password to be hashed.
 * @param       passwordLength  The length of the password.
 * @param       hashedPassword  A buffer to store the resulting hashed password (must be HASH_LENGTH bytes).
 * @return      TRUE if the hashing succeeds; otherwise, FALSE.
 */
bool HashPassword(_In_reads_bytes_(passwordLength) const char* password, _In_ uint16_t passwordLength, _Out_writes_bytes_all_(HASH_LENGTH) char* hashedPassword) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashLength = HASH_LENGTH;
    NTSTATUS status;
    bool result = false;

    // Clear the output buffer to avoid uninitialized usage
    memset(hashedPassword, 0, HASH_LENGTH);

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    // Create hash object
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    // Hash the data
    status = BCryptHashData(hHash, (PUCHAR)password, passwordLength, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    // Get the hash
    status = BCryptFinishHash(hHash, (PUCHAR)hashedPassword, hashLength, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    result = true;

cleanup:
    // Clean up resources
    if (hHash) {
        BCryptDestroyHash(hHash);
    }

    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return result;
}



/**
 * @brief       Stores the user's credentials (username and hashed password) in the users.txt file.
 *
 * @param       username        The username to be stored.
 * @param       hashedPassword  The hashed password to be stored.
 * @return      TRUE if the credentials are stored successfully; otherwise, FALSE.
 */
bool StoreUserCredentials(_In_z_ const char* username, _In_reads_bytes_(HASH_LENGTH) const char* hashedPassword) {
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

    // Convert the binary hash to a hexadecimal string
    char hexHashedPassword[2 * HASH_LENGTH + 1];
    ConvertHashToHexString(hashedPassword, HASH_LENGTH, hexHashedPassword);
    
    // Write username and hashed password
    fprintf(file, "%s:%s\n", username, hexHashedPassword);

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
    
    char line[USERNAME_MAX_LENGTH + 1]; // Buffer to hold each line of the file
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
    /* Here you can create any global objects you consider necessary. */
    g_IsUserLoggedIn = false;   // Initialize the variable
    memset(g_LoggedInUsername, 0, sizeof(g_LoggedInUsername));  // Clear the username
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
    char hashedPassword[HASH_LENGTH];
    if (!HashPassword(Password, PasswordLength, hashedPassword)) {
        return SS_STATUS_HASH_FAILED;
    }

    // Store the username and hashed password in users.txt
    if (!StoreUserCredentials(Username, hashedPassword)) {
        printf("Failed to store user credentials\n");
        return SS_STATUS_MEMORY_ALLOCATION_FAILED;
    }

    return SS_STATUS_SUCCESS;
}


bool IsUserLoggedIn(void) {
    return g_IsUserLoggedIn;
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

    // Hash the provided password to compare with the stored hash
    char hashedPassword[HASH_LENGTH];
    if (!HashPassword(Password, PasswordLength, hashedPassword)) {
        printf("Failed to hash password\n");
        return SS_STATUS_HASH_FAILED;
    }

    // Retrieve stored hashed password for the username
    char storedHashedPassword[HASH_LENGTH];
    if (!RetrieveUserCredentials(Username, storedHashedPassword)) {
        printf("User not found\n");
        return SS_STATUS_USER_NOT_FOUND;
    }

    // Compare the hashed passwords
    if (strcmp(hashedPassword, storedHashedPassword) != 0) {
        printf("Incorrect password\n");
        return SS_STATUS_INVALID_PASSWORD;
    }

    // Login successful
    g_IsUserLoggedIn = true; // Set logged in state to true
    strncpy(g_LoggedInUsername, Username, USERNAME_MAX_LENGTH); // Store the username


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
