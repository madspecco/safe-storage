﻿#include "Commands.h"
#include <stdbool.h>
#include <strsafe.h>
#include <errno.h>
#include <windows.h>
#include <AclAPI.h>


// Global static variables
static bool g_IsUserLoggedIn = false;
static char g_LoggedInUsername[USERNAME_MAX_LENGTH + 1] = { 0 };
static char g_AppDirectory[MAX_PATH] = { 0 };



// Function declarations
/**
 * @brief Initializes the global application directory variable.
 *
 * @return TRUE if initialization is successful; otherwise, FALSE.
 */
bool InitializeAppDirectory() {
    // Get the current directory
    if (GetCurrentDirectoryA(MAX_PATH, g_AppDirectory) == 0) {
        printf("Error initializing application directory: %s\n", strerror(errno));
        return false;
    }
    return true;
}


/**
 * @brief Extracts the filename from a full file path.
 *
 * @param filePath The full file path.
 * @return A pointer to the filename within the file path.
 */
const char* ExtractFileName(const char* filePath) {
    const char* lastSlash = strrchr(filePath, '\\'); // Look for the last backslash
    return (lastSlash != NULL) ? lastSlash + 1 : filePath; // Return the part after the slash
}

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
bool HashPassword(_In_reads_bytes_(passwordLength) const char* password, _In_ uint16_t passwordLength, _Out_writes_bytes_all_(HASH_HEX_LENGTH) char* hashedPassword) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE binaryHash[HASH_LENGTH] = { 0 };
    DWORD hashLength = HASH_LENGTH;
    NTSTATUS status;
    bool result = false;

    // Clear the output buffer to avoid uninitialized usage
    memset(hashedPassword, 0, HASH_HEX_LENGTH);

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

    // Get the binary hash
    status = BCryptFinishHash(hHash, binaryHash, hashLength, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    // Convert the binary hash to a hex string
    for (DWORD i = 0; i < hashLength; i++) {
        sprintf_s(&hashedPassword[i * 2], 3, "%02x", binaryHash[i]);
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
bool StoreUserCredentials(_In_z_ const char* username, _In_reads_bytes_(HASH_HEX_LENGTH) const char* hashedPassword) {
    // Construct the path to the users.txt file
    char usersFilePath[MAX_PATH];
    sprintf_s(usersFilePath, MAX_PATH, "%s\\users.txt", g_AppDirectory);

    // Open users.txt for appending
    FILE* file = fopen(usersFilePath, "a");
    if (file == NULL) {
        printf("Error opening file for writing: %s\n", strerror(errno));
        return false;
    }

    // Write username and hashed password as hex
    fprintf(file, "%s:%s\n", username, hashedPassword);

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
    // Construct the path to the users.txt file.
    char usersFilePath[MAX_PATH];
    sprintf_s(usersFilePath, MAX_PATH, "%s\\users.txt", g_AppDirectory);

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

    /* Initialize the global application directory */
    if (GetCurrentDirectoryA(MAX_PATH, g_AppDirectory) == 0) {
        printf("Failed to initialize the application directory.\n");
        return STATUS_UNSUCCESSFUL;
    }
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
    sprintf(userDirectory, "%s\\users\\%s", g_AppDirectory, Username);

    // Check if parent directory exists
    char usersDir[MAX_PATH];
    sprintf(usersDir, "%s\\users", g_AppDirectory);
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
    char hashedPassword[HASH_HEX_LENGTH] = { 0 };
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


bool RetrieveUserCredentials(_In_ const char* Username, _Out_writes_z_(HASH_LENGTH * 2 + 1) char* OutHashedPassword) {
    // Construct the path to users.txt
    char filePath[MAX_PATH];
    if (sprintf_s(filePath, MAX_PATH, "%s\\users.txt", g_AppDirectory) < 0) {
        printf("Failed to construct file path\n");
        OutHashedPassword[0] = '\0'; // Ensure it's always null-terminated
        return false;
    }

    FILE* file = fopen(filePath, "r");
    if (file == NULL) {
        printf("Failed to open users.txt\n");
        OutHashedPassword[0] = '\0'; // Ensure it's always null-terminated
        return false;
    }

    // Increase buffer size to accommodate 64 characters of hash + 1 for null terminator
    char line[USERNAME_MAX_LENGTH + HASH_LENGTH * 2 + 2]; // 2 extra for ':' and '\0'
    char storedUsername[USERNAME_MAX_LENGTH + 1] = { 0 };
    char storedHashedPassword[HASH_LENGTH * 2 + 1] = { 0 }; // 64 hex chars + 1 null terminator

    // Initialize output to ensure it's valid
    OutHashedPassword[0] = '\0';

    // Read each line and parse for username and hash
    while (fgets(line, sizeof(line), file) != NULL) {
        // Remove any trailing newline character
        line[strcspn(line, "\r\n")] = '\0';

        // Parse line as "username:hashed_password"
        if (sscanf_s(line, "%10[^:]:%64s", storedUsername, (unsigned)_countof(storedUsername), storedHashedPassword, (unsigned)_countof(storedHashedPassword)) == 2) {
            if (strcmp(Username, storedUsername) == 0) {
                // Safely copy the hashed password
                strncpy_s(OutHashedPassword, HASH_LENGTH * 2 + 1, storedHashedPassword, HASH_LENGTH * 2);

                // Ensure null termination
                OutHashedPassword[HASH_LENGTH * 2] = '\0';

                fclose(file);
                return true;
            }
        }
        else {
            printf("Line parsing failed or incorrect format: %s\n", line);
        }
    }

    fclose(file);
    printf("User not found\n");
    return false;  // User not found
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

    // Check if a user is already logged in
    if (g_IsUserLoggedIn) {
        printf("You are already logged in as %s. Please log out first.\n", g_LoggedInUsername);
        return SS_STATUS_ALREADY_LOGGED_IN;
    }


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
    char hashedPassword[HASH_LENGTH * 2 + 1] = { 0 };
    if (!HashPassword(Password, PasswordLength, hashedPassword)) {
        printf("Failed to hash password\n");
        return SS_STATUS_HASH_FAILED;
    }

    // Retrieve stored hashed password for the username
    char storedHashedPassword[HASH_HEX_LENGTH] = { 0 };
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
    printf("Welcome, %s!\n", Username);

    return SS_STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    // Check if a user is logged in
    if (!g_IsUserLoggedIn) {
        printf("No user is logged in.\n");
        return SS_STATUS_NOT_LOGGED_IN;
    }

    // Log the user out
    printf("Goodbye, %s!\n", g_LoggedInUsername);
    g_IsUserLoggedIn = false; // Set logged-in state to false
    memset(g_LoggedInUsername, 0, USERNAME_MAX_LENGTH); // Clear the stored username

    return SS_STATUS_SUCCESS;
}


void SetWritePermissions(LPCSTR filePath) {
    DWORD result;
    PACL pOldDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESSA ea;

    // Get current security descriptor
    result = GetNamedSecurityInfoA(
        filePath,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        &pOldDACL,
        NULL,
        &pSD
    );

    if (result != ERROR_SUCCESS) {
        printf("Failed to get security info: %lu\n", result);
        return;
    }

    // Initialize EXPLICIT_ACCESS structure
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESSA));
    ea.grfAccessPermissions = FILE_GENERIC_WRITE;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = "CURRENT_USER";

    // Set new DACL
    PACL pNewDACL = NULL;
    result = SetEntriesInAclA(1, &ea, pOldDACL, &pNewDACL);
    if (result == ERROR_SUCCESS) {
        result = SetNamedSecurityInfoA(
            (LPSTR)filePath,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            NULL,
            NULL,
            pNewDACL,
            NULL
        );

        if (result != ERROR_SUCCESS) {
            printf("Failed to set security info: %lu\n", result);
        }
    }
    else {
        printf("Failed to modify DACL: %lu\n", result);
    }

    if (pSD) LocalFree((HLOCAL)pSD);
    if (pNewDACL) LocalFree((HLOCAL)pNewDACL);
}


NTSTATUS WINAPI
SafeStorageHandleStore(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* SourceFilePath,
    uint16_t SourceFilePathLength
)
{
    // Check if a user is logged in
    if (!g_IsUserLoggedIn) {
        printf("No user is logged in.\n");
        return SS_STATUS_NOT_LOGGED_IN;
    }

    // Validate SubmissionName
    if (SubmissionName == NULL || SubmissionNameLength == 0 || SubmissionNameLength > MAX_SUBMISSION_NAME_LENGTH) {
        printf("Invalid submission name.\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Validate SourceFilePath
    if (SourceFilePath == NULL || SourceFilePathLength == 0 || SourceFilePathLength > MAX_FILE_PATH_LENGTH) {
        printf("Invalid source file path.\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Construct the destination path for the submission
    char destinationPath[MAX_PATH];
    int result = snprintf(
        destinationPath,
        sizeof(destinationPath),
        "%s\\users\\%s\\%.*s",
        g_AppDirectory,
        g_LoggedInUsername,
        SubmissionNameLength,
        SubmissionName
    );

    // Check for truncation or formatting errors
    if (result < 0 || result >= (int)sizeof(destinationPath)) {
        printf("Failed to construct the destination path.\n");
        return STATUS_BUFFER_OVERFLOW;
    }


    // Ensure the user's directory exists
    if (CreateDirectoryA(destinationPath, NULL) == 0 && GetLastError() != ERROR_ALREADY_EXISTS) {
        printf("Failed to create the directory for the submission: %lu\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }


    //Copy the source file to the destination
    const char* sourceFileName = ExtractFileName(SourceFilePath);

    // Buffer to hold the final destination path
    char fullDestinationPath[MAX_PATH];

    // Safely construct the full destination path
    if (FAILED(StringCchPrintfA(fullDestinationPath, MAX_PATH, "%s\\%s", destinationPath, sourceFileName))) {
        printf("Failed to construct the full destination path.\n");
        return STATUS_UNSUCCESSFUL;
    }

    if (!CopyFileA(SourceFilePath, fullDestinationPath, FALSE)) {
        printf("Failed to copy the file to the destination: %lu\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }


    printf("File successfully stored at: %s\n", destinationPath);
    return STATUS_SUCCESS;


    ///* The function is not implemented. It is your responsibility. */
    ///* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    ///* This is just to prevent a compilation warning that the parameter is unused. */

    //UNREFERENCED_PARAMETER(SubmissionName);
    //UNREFERENCED_PARAMETER(SubmissionNameLength);
    //UNREFERENCED_PARAMETER(SourceFilePath);
    //UNREFERENCED_PARAMETER(SourceFilePathLength);

    //return STATUS_NOT_IMPLEMENTED;
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
