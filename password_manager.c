#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>

// Constants for file names and cryptographic parameters
#define MASTER_PASS_FILE "master.pass"  // File for storing the hashed master password and salt
#define PASSWORD_FILE "passwords.enc"  // File for storing encrypted account passwords
#define SALT_SIZE 16                   // Size of the salt (in bytes) for password hashing
#define KEY_SIZE 32                    // AES-256 requires a 256-bit (32-byte) encryption key
#define IV_SIZE 16                     // Initialization vector (IV) size for AES
#define BUFFER_SIZE 1024               // General buffer size for strings and data

// Function prototypes for each major operation
void set_master_password();               // Sets the master password for the first time
int verify_master_password();             // Verifies the entered master password
void save_password(const char *account, const char *password); // Encrypts and stores an account password
void retrieve_passwords();                // Decrypts and displays all stored passwords
void generate_password(char *output, int length); // Generates a random, secure password
void encrypt_data(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, FILE *out_file);
int decrypt_data(FILE *file, unsigned char *key, unsigned char *iv);

// Main function: Provides a menu for interacting with the password manager
int main() {
    int choice;

    printf("Password Manager\n");
    printf("================\n");

    // If the master password file does not exist, prompt the user to set a new master password
    if (access(MASTER_PASS_FILE, F_OK) != 0) {
        printf("No master password found. Set a new one.\n");
        set_master_password();
    }

    // Verify the master password before allowing access
    if (!verify_master_password()) {
        printf("Authentication failed. Exiting.\n");
        return 1;
    }

    // Display menu until the user chooses to exit
    while (1) {
        printf("\nOptions:\n");
        printf("1. Save a password\n");
        printf("2. Retrieve passwords\n");
        printf("3. Generate a password\n");
        printf("4. Exit\n");
        printf("Choose an option: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: { // Save a new password
                char account[BUFFER_SIZE], password[BUFFER_SIZE];
                printf("Enter account name: ");
                scanf("%s", account);
                printf("Enter password: ");
                scanf("%s", password);
                save_password(account, password);
                break;
            }
            case 2: // Retrieve all stored passwords
                retrieve_passwords();
                break;
            case 3: { // Generate a random password
                int length;
                char generated_password[BUFFER_SIZE];
                printf("Enter password length: ");
                scanf("%d", &length);
                generate_password(generated_password, length);
                printf("Generated password: %s\n", generated_password);
                break;
            }
            case 4: // Exit the program
                printf("Exiting.\n");
                return 0;
            default: // Handle invalid menu choices
                printf("Invalid choice. Try again.\n");
        }
    }
}

// Function to set a new master password and save its hash and salt
void set_master_password() {
    char master_pass[BUFFER_SIZE];
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    FILE *file;

    // Prompt the user to enter a master password
    printf("Set a master password: ");
    scanf("%s", master_pass);

    // Generate a random salt for the password hash
    if (!RAND_bytes(salt, SALT_SIZE)) {
        fprintf(stderr, "Error generating salt.\n");
        exit(1);
    }

    // Derive a key from the master password and salt using PBKDF2
    if (!PKCS5_PBKDF2_HMAC(master_pass, strlen(master_pass), salt, SALT_SIZE, 10000, EVP_sha256(), KEY_SIZE, key)) {
        fprintf(stderr, "Error generating key.\n");
        exit(1);
    }

    // Save the salt and derived key to the master password file
    file = fopen(MASTER_PASS_FILE, "wb");
    if (!file) {
        fprintf(stderr, "Error creating master password file.\n");
        exit(1);
    }
    fwrite(salt, 1, SALT_SIZE, file);
    fwrite(key, 1, KEY_SIZE, file);
    fclose(file);

    printf("Master password set successfully.\n");
}

// Function to verify the entered master password by comparing hashes
int verify_master_password() {
    char master_pass[BUFFER_SIZE];
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE], stored_key[KEY_SIZE];
    FILE *file;

    // Prompt the user to enter the master password
    printf("Enter master password: ");
    scanf("%s", master_pass);

    // Read the salt and stored key from the master password file
    file = fopen(MASTER_PASS_FILE, "rb");
    if (!file) {
        fprintf(stderr, "Error opening master password file.\n");
        return 0;
    }
    fread(salt, 1, SALT_SIZE, file);
    fread(stored_key, 1, KEY_SIZE, file);
    fclose(file);

    // Derive a key from the entered password and stored salt
    if (!PKCS5_PBKDF2_HMAC(master_pass, strlen(master_pass), salt, SALT_SIZE, 10000, EVP_sha256(), KEY_SIZE, key)) {
        fprintf(stderr, "Error generating key.\n");
        return 0;
    }

    // Compare the derived key with the stored key
    return memcmp(key, stored_key, KEY_SIZE) == 0;
}

// Function to save an account password securely
void save_password(const char *account, const char *password) {
    unsigned char key[KEY_SIZE], iv[IV_SIZE];
    FILE *file;

    // Retrieve the master key from the master password file
    file = fopen(MASTER_PASS_FILE, "rb");
    if (!file) {
        fprintf(stderr, "Error opening master password file.\n");
        return;
    }
    fread(key, 1, KEY_SIZE, file);
    fclose(file);

    // Generate a random IV for encryption
    if (!RAND_bytes(iv, IV_SIZE)) {
        fprintf(stderr, "Error generating IV.\n");
        exit(1);
    }

    // Open the password file in append mode to add a new entry
    file = fopen(PASSWORD_FILE, "ab");
    if (!file) {
        fprintf(stderr, "Error opening password file.\n");
        return;
    }

    // Save the account name and encrypt the password
    fprintf(file, "%s\n", account);
    fwrite(iv, 1, IV_SIZE, file);
    encrypt_data((unsigned char *)password, strlen(password), key, iv, file);
    fclose(file);

    printf("Password saved successfully.\n");
}

// Function to retrieve and decrypt all stored passwords
void retrieve_passwords() {
    unsigned char key[KEY_SIZE];
    FILE *file;

    // Retrieve the master key from the master password file
    file = fopen(MASTER_PASS_FILE, "rb");
    if (!file) {
        fprintf(stderr, "Error opening master password file.\n");
        return;
    }
    fread(key, 1, KEY_SIZE, file);
    fclose(file);

    // Open the password file to read encrypted data
    file = fopen(PASSWORD_FILE, "rb");
    if (!file) {
        printf("No saved passwords.\n");
        return;
    }

    char account[BUFFER_SIZE];
    unsigned char iv[IV_SIZE];

    // Read and decrypt each entry in the password file
    while (fscanf(file, "%s\n", account) != EOF) {
        if (fread(iv, 1, IV_SIZE, file) != IV_SIZE) {
            fprintf(stderr, "Error reading IV from file.\n");
            break;
        }

        printf("Account: %s\n", account);
        printf("Password: ");
        if (!decrypt_data(file, key, iv)) {
            fprintf(stderr, "Error decrypting password.\n");
            break;
        }
        printf("\n");
    }

    fclose(file);
}

// Function to generate a random secure password
void generate_password(char *output, int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    for (int i = 0; i < length; i++) {
        output[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    output[length] = '\0';
}

// Function to encrypt data using AES-256-CBC
void encrypt_data(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, FILE *out_file) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char ciphertext[BUFFER_SIZE];
    int len, ciphertext_len;

    // Initialize encryption operation
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    // Write the ciphertext length and data to the file
    fwrite(&ciphertext_len, sizeof(int), 1, out_file);
    fwrite(ciphertext, 1, ciphertext_len, out_file);

    EVP_CIPHER_CTX_free(ctx);
}

// Function to decrypt data using AES-256-CBC
int decrypt_data(FILE *file, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char ciphertext[BUFFER_SIZE], plaintext[BUFFER_SIZE];
    int len, plaintext_len, ciphertext_len;

    // Read the ciphertext length and data from the file
    if (fread(&ciphertext_len, sizeof(int), 1, file) != 1) {
        fprintf(stderr, "Error reading ciphertext length.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (ciphertext_len > BUFFER_SIZE) {
        fprintf(stderr, "Ciphertext length exceeds buffer size.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (fread(ciphertext, 1, ciphertext_len, file) != ciphertext_len) {
        fprintf(stderr, "Error reading ciphertext.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Perform the decryption operation
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        fprintf(stderr, "Decryption error.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';

    // Display the plaintext password
    printf("%s", plaintext);

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}
