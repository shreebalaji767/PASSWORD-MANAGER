#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <bcrypt.h>
#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define VAULT_FILE "vault.dat"
#define BACKUP_FILE "vault_backup.dat"

#define MAGIC "CPMV002"
#define MAGIC_SIZE 7

#define SALT_SIZE 16
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define KEY_SIZE 32

#define PBKDF2_ITERATIONS 600000ULL

#define MAX_RECORDS 1000
#define TITLE_SIZE 512
#define USERNAME_SIZE 512
#define PASSWORD_SIZE 512
#define WEBSITE_SIZE 512
#define NOTES_SIZE 2048

typedef struct
{
    char title[TITLE_SIZE];
    char username[USERNAME_SIZE];
    char password[PASSWORD_SIZE];
    char website[WEBSITE_SIZE];
    char notes[NOTES_SIZE];
} PasswordRecord;

typedef struct
{
    uint32_t count;
    PasswordRecord records[MAX_RECORDS];
} VaultData;

static void secure_zero(void *ptr, size_t size)
{
    if (ptr != NULL && size > 0)
    {
        SecureZeroMemory(ptr, size);
    }
}

static void fatal_error(const char *message)
{
    fprintf(stderr, "\n============================================\n");
    fprintf(stderr, "FATAL ERROR\n");
    fprintf(stderr, "============================================\n");
    fprintf(stderr, "%s\n", message);
    fprintf(stderr, "============================================\n");
    fprintf(stderr, "Press ENTER to close...");
    getchar();
    exit(EXIT_FAILURE);
}

static void wait_enter(void)
{
    printf("\nPress ENTER to continue...");
    getchar();
}

static void clear_screen(void)
{
    system("cls");
}

static void trim_newline(char *s)
{
    if (s == NULL)
        return;

    s[strcspn(s, "\r\n")] = '\0';
}

static void copy_string(char *dest, size_t dest_size, const char *src)
{
    if (dest == NULL || dest_size == 0)
        return;

    if (src == NULL)
    {
        dest[0] = '\0';
        return;
    }

    snprintf(dest, dest_size, "%s", src);
}

static void read_line(const char *prompt, char *buffer, size_t size)
{
    if (buffer == NULL || size == 0)
        return;

    printf("%s", prompt);
    fflush(stdout);

    if (fgets(buffer, (int)size, stdin) == NULL)
    {
        buffer[0] = '\0';
        clearerr(stdin);
        return;
    }

    trim_newline(buffer);
}

static void read_password(const char *prompt, char *buffer, size_t size)
{
    size_t pos = 0;

    if (buffer == NULL || size == 0)
        return;

    printf("%s", prompt);
    fflush(stdout);

    while (1)
    {
        int ch = _getch();

        if (ch == '\r' || ch == '\n')
        {
            break;
        }

        if (ch == 8)
        {
            if (pos > 0)
            {
                pos--;
                printf("\b \b");
            }
            continue;
        }

        if (ch == 0 || ch == 224)
        {
            _getch();
            continue;
        }

        if (ch >= 32 && ch <= 126)
        {
            if (pos < size - 1)
            {
                buffer[pos++] = (char)ch;
                putchar('*');
            }
        }
    }

    buffer[pos] = '\0';
    putchar('\n');
}

static int random_bytes(unsigned char *buffer, ULONG size)
{
    NTSTATUS status;

    status = BCryptGenRandom(
        NULL,
        buffer,
        size,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    return BCRYPT_SUCCESS(status);
}

static int derive_key(
    const char *password,
    const unsigned char *salt,
    unsigned char *key
)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(
        &alg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );

    if (!BCRYPT_SUCCESS(status))
        return 0;

    status = BCryptDeriveKeyPBKDF2(
        alg,
        (PUCHAR)password,
        (ULONG)strlen(password),
        (PUCHAR)salt,
        SALT_SIZE,
        PBKDF2_ITERATIONS,
        key,
        KEY_SIZE,
        0
    );

    BCryptCloseAlgorithmProvider(alg, 0);

    return BCRYPT_SUCCESS(status);
}

static int aes_gcm_encrypt(
    const unsigned char *plaintext,
    ULONG plaintext_size,
    const unsigned char *key,
    const unsigned char *nonce,
    unsigned char *ciphertext,
    unsigned char *tag
)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key_handle = NULL;

    NTSTATUS status;
    DWORD object_size = 0;
    DWORD result = 0;

    unsigned char *key_object = NULL;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;

    status = BCryptOpenAlgorithmProvider(
        &alg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );

    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    status = BCryptGetProperty(
        alg,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&object_size,
        sizeof(object_size),
        &result,
        0
    );

    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    key_object = (unsigned char *)malloc(object_size);

    if (key_object == NULL)
        goto cleanup;

    status = BCryptSetProperty(
        alg,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0
    );

    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    status = BCryptGenerateSymmetricKey(
        alg,
        &key_handle,
        key_object,
        object_size,
        (PUCHAR)key,
        KEY_SIZE,
        0
    );

    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);

    auth_info.pbNonce = (PUCHAR)nonce;
    auth_info.cbNonce = NONCE_SIZE;

    auth_info.pbTag = tag;
    auth_info.cbTag = TAG_SIZE;

    status = BCryptEncrypt(
        key_handle,
        (PUCHAR)plaintext,
        plaintext_size,
        &auth_info,
        NULL,
        0,
        ciphertext,
        plaintext_size,
        &result,
        0
    );

    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    secure_zero(key_object, object_size);
    free(key_object);

    return 1;

cleanup:

    if (key_handle != NULL)
        BCryptDestroyKey(key_handle);

    if (alg != NULL)
        BCryptCloseAlgorithmProvider(alg, 0);

    if (key_object != NULL)
    {
        secure_zero(key_object, object_size);
        free(key_object);
    }

    return 0;
}

static int aes_gcm_decrypt(
    const unsigned char *ciphertext,
    ULONG ciphertext_size,
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *tag,
    unsigned char *plaintext
)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key_handle = NULL;

    NTSTATUS status;
    DWORD object_size = 0;
    DWORD result = 0;

    unsigned char *key_object = NULL;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;

    status = BCryptOpenAlgorithmProvider(
        &alg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );

    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    status = BCryptGetProperty(
        alg,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&object_size,
        sizeof(object_size),
        &result,
        0
    );

    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    key_object = (unsigned char *)malloc(object_size);

    if (key_object == NULL)
        goto cleanup;

    status = BCryptSetProperty(
        alg,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0
    );

    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    status = BCryptGenerateSymmetricKey(
        alg,
        &key_handle,
        key_object,
        object_size,
        (PUCHAR)key,
        KEY_SIZE,
        0
    );

    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);

    auth_info.pbNonce = (PUCHAR)nonce;
    auth_info.cbNonce = NONCE_SIZE;

    auth_info.pbTag = (PUCHAR)tag;
    auth_info.cbTag = TAG_SIZE;

    status = BCryptDecrypt(
        key_handle,
        (PUCHAR)ciphertext,
        ciphertext_size,
        &auth_info,
        NULL,
        0,
        plaintext,
        ciphertext_size,
        &result,
        0
    );

    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    secure_zero(key_object, object_size);
    free(key_object);

    return 1;

cleanup:

    if (key_handle != NULL)
        BCryptDestroyKey(key_handle);

    if (alg != NULL)
        BCryptCloseAlgorithmProvider(alg, 0);

    if (key_object != NULL)
    {
        secure_zero(key_object, object_size);
        free(key_object);
    }

    return 0;
}

static int save_vault(
    const VaultData *vault,
    const char *master_password
)
{
    FILE *file = NULL;

    unsigned char salt[SALT_SIZE];
    unsigned char nonce[NONCE_SIZE];
    unsigned char tag[TAG_SIZE];
    unsigned char key[KEY_SIZE];

    unsigned char *ciphertext = NULL;

    uint32_t plaintext_size = (uint32_t)sizeof(VaultData);

    if (!random_bytes(salt, SALT_SIZE))
        return 0;

    if (!random_bytes(nonce, NONCE_SIZE))
        return 0;

    if (!derive_key(master_password, salt, key))
    {
        secure_zero(key, sizeof(key));
        return 0;
    }

    ciphertext = (unsigned char *)malloc(plaintext_size);

    if (ciphertext == NULL)
    {
        secure_zero(key, sizeof(key));
        return 0;
    }

    if (!aes_gcm_encrypt(
            (const unsigned char *)vault,
            plaintext_size,
            key,
            nonce,
            ciphertext,
            tag))
    {
        secure_zero(key, sizeof(key));
        secure_zero(ciphertext, plaintext_size);
        free(ciphertext);
        return 0;
    }

    file = fopen(VAULT_FILE, "wb");

    if (file == NULL)
    {
        secure_zero(key, sizeof(key));
        secure_zero(ciphertext, plaintext_size);
        free(ciphertext);
        return 0;
    }

    fwrite(MAGIC, 1, MAGIC_SIZE, file);
    fwrite(&plaintext_size, sizeof(plaintext_size), 1, file);
    fwrite(salt, 1, SALT_SIZE, file);
    fwrite(nonce, 1, NONCE_SIZE, file);
    fwrite(tag, 1, TAG_SIZE, file);
    fwrite(ciphertext, 1, plaintext_size, file);

    fclose(file);

    secure_zero(key, sizeof(key));
    secure_zero(ciphertext, plaintext_size);
    free(ciphertext);

    return 1;
}

static int load_vault(
    VaultData *vault,
    const char *master_password
)
{
    FILE *file = NULL;

    char magic[MAGIC_SIZE];
    uint32_t plaintext_size = 0;

    unsigned char salt[SALT_SIZE];
    unsigned char nonce[NONCE_SIZE];
    unsigned char tag[TAG_SIZE];
    unsigned char key[KEY_SIZE];

    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;

    file = fopen(VAULT_FILE, "rb");

    if (file == NULL)
        return 0;

    if (fread(magic, 1, MAGIC_SIZE, file) != MAGIC_SIZE)
        goto fail;

    if (memcmp(magic, MAGIC, MAGIC_SIZE) != 0)
        goto fail;

    if (fread(&plaintext_size, sizeof(plaintext_size), 1, file) != 1)
        goto fail;

    if (plaintext_size != sizeof(VaultData))
        goto fail;

    if (fread(salt, 1, SALT_SIZE, file) != SALT_SIZE)
        goto fail;

    if (fread(nonce, 1, NONCE_SIZE, file) != NONCE_SIZE)
        goto fail;

    if (fread(tag, 1, TAG_SIZE, file) != TAG_SIZE)
        goto fail;

    ciphertext = (unsigned char *)malloc(plaintext_size);
    plaintext = (unsigned char *)malloc(plaintext_size);

    if (ciphertext == NULL || plaintext == NULL)
        goto fail;

    if (fread(ciphertext, 1, plaintext_size, file) != plaintext_size)
        goto fail;

    fclose(file);
    file = NULL;

    if (!derive_key(master_password, salt, key))
        goto fail;

    if (!aes_gcm_decrypt(
            ciphertext,
            plaintext_size,
            key,
            nonce,
            tag,
            plaintext))
    {
        secure_zero(key, sizeof(key));
        goto fail;
    }

    memcpy(vault, plaintext, sizeof(VaultData));

    if (vault->count > MAX_RECORDS)
    {
        secure_zero(key, sizeof(key));
        goto fail;
    }

    secure_zero(key, sizeof(key));
    secure_zero(ciphertext, plaintext_size);
    secure_zero(plaintext, plaintext_size);

    free(ciphertext);
    free(plaintext);

    return 1;

fail:

    if (file != NULL)
        fclose(file);

    if (ciphertext != NULL)
    {
        secure_zero(ciphertext, plaintext_size);
        free(ciphertext);
    }

    if (plaintext != NULL)
    {
        secure_zero(plaintext, plaintext_size);
        free(plaintext);
    }

    return 0;
}

static int file_exists(const char *filename)
{
    DWORD attributes = GetFileAttributesA(filename);

    return attributes != INVALID_FILE_ATTRIBUTES &&
           !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

static void generate_password(char *output, size_t size)
{
    const char *lower =
        "abcdefghijklmnopqrstuvwxyz";

    const char *upper =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    const char *digits =
        "0123456789";

    const char *symbols =
        "!@#$%^&*()-_=+[]{}";

    char pool[256] = "";

    size_t pool_len;
    size_t i;

    if (size == 0)
        return;

    strncat(pool, lower, sizeof(pool) - strlen(pool) - 1);
    strncat(pool, upper, sizeof(pool) - strlen(pool) - 1);
    strncat(pool, digits, sizeof(pool) - strlen(pool) - 1);
    strncat(pool, symbols, sizeof(pool) - strlen(pool) - 1);

    pool_len = strlen(pool);

    if (size < 5)
    {
        output[0] = '\0';
        return;
    }

    for (i = 0; i < size - 1; i++)
    {
        unsigned char random_byte;

        if (!random_bytes(&random_byte, 1))
        {
            output[0] = '\0';
            return;
        }

        output[i] = pool[random_byte % pool_len];
    }

    output[size - 1] = '\0';
}

static void list_passwords(const VaultData *vault)
{
    uint32_t i;

    clear_screen();

    printf("============================================\n");
    printf("             SAVED PASSWORDS\n");
    printf("============================================\n\n");

    if (vault->count == 0)
    {
        printf("No passwords saved.\n");
        wait_enter();
        return;
    }

    for (i = 0; i < vault->count; i++)
    {
        printf(
            "%3u. %s\n",
            (unsigned)(i + 1),
            vault->records[i].title
        );

        printf(
            "     Username : %s\n",
            vault->records[i].username
        );

        printf(
            "     Website  : %s\n\n",
            vault->records[i].website
        );
    }

    wait_enter();
}

static int select_record(const VaultData *vault)
{
    char input[32];
    long number;

    if (vault->count == 0)
    {
        printf("\nNo records available.\n");
        return -1;
    }

    read_line("\nEnter record number: ", input, sizeof(input));

    number = strtol(input, NULL, 10);

    if (number < 1 || number > (long)vault->count)
    {
        printf("Invalid record number.\n");
        return -1;
    }

    return (int)(number - 1);
}

static void add_password(VaultData *vault)
{
    PasswordRecord *r;

    clear_screen();

    printf("============================================\n");
    printf("              ADD PASSWORD\n");
    printf("============================================\n\n");

    if (vault->count >= MAX_RECORDS)
    {
        printf("Vault is full.\n");
        wait_enter();
        return;
    }

    r = &vault->records[vault->count];

    memset(r, 0, sizeof(*r));

    read_line("Title    : ", r->title, sizeof(r->title));
    read_line("Username : ", r->username, sizeof(r->username));
    read_password("Password : ", r->password, sizeof(r->password));
    read_line("Website  : ", r->website, sizeof(r->website));
    read_line("Notes    : ", r->notes, sizeof(r->notes));

    vault->count++;

    printf("\nPassword added.\n");

    wait_enter();
}

static void view_password(const VaultData *vault)
{
    int index;

    clear_screen();

    printf("============================================\n");
    printf("              VIEW PASSWORD\n");
    printf("============================================\n");

    index = select_record(vault);

    if (index < 0)
    {
        wait_enter();
        return;
    }

    printf("\nTitle    : %s\n", vault->records[index].title);
    printf("Username : %s\n", vault->records[index].username);
    printf("Password : %s\n", vault->records[index].password);
    printf("Website  : %s\n", vault->records[index].website);
    printf("Notes    : %s\n", vault->records[index].notes);

    wait_enter();
}

static void edit_password(VaultData *vault)
{
    int index;
    char temp[NOTES_SIZE];

    clear_screen();

    printf("============================================\n");
    printf("              EDIT PASSWORD\n");
    printf("============================================\n");

    index = select_record(vault);

    if (index < 0)
    {
        wait_enter();
        return;
    }

    PasswordRecord *r = &vault->records[index];

    printf("\nPress ENTER to keep the current value.\n\n");

    read_line("Title: ", temp, sizeof(temp));

    if (temp[0] != '\0')
        copy_string(r->title, sizeof(r->title), temp);

    read_line("Username: ", temp, sizeof(temp));

    if (temp[0] != '\0')
        copy_string(r->username, sizeof(r->username), temp);

    read_password("Password: ", temp, sizeof(temp));

    if (temp[0] != '\0')
        copy_string(r->password, sizeof(r->password), temp);

    read_line("Website: ", temp, sizeof(temp));

    if (temp[0] != '\0')
        copy_string(r->website, sizeof(r->website), temp);

    read_line("Notes: ", temp, sizeof(temp));

    if (temp[0] != '\0')
        copy_string(r->notes, sizeof(r->notes), temp);

    secure_zero(temp, sizeof(temp));

    printf("\nPassword updated.\n");

    wait_enter();
}

static void delete_password(VaultData *vault)
{
    int index;
    uint32_t i;

    clear_screen();

    printf("============================================\n");
    printf("             DELETE PASSWORD\n");
    printf("============================================\n");

    index = select_record(vault);

    if (index < 0)
    {
        wait_enter();
        return;
    }

    printf(
        "\nDelete \"%s\"? (Y/N): ",
        vault->records[index].title
    );

    {
        int ch = _getch();

        printf("%c\n", ch);

        if (ch != 'y' && ch != 'Y')
        {
            printf("Delete cancelled.\n");
            wait_enter();
            return;
        }
    }

    for (i = (uint32_t)index;
         i + 1 < vault->count;
         i++)
    {
        memcpy(
            &vault->records[i],
            &vault->records[i + 1],
            sizeof(PasswordRecord)
        );
    }

    secure_zero(
        &vault->records[vault->count - 1],
        sizeof(PasswordRecord)
    );

    vault->count--;

    printf("Password deleted.\n");

    wait_enter();
}

static void search_passwords(const VaultData *vault)
{
    char search[256];
    uint32_t i;
    int found = 0;

    clear_screen();

    printf("============================================\n");
    printf("             SEARCH PASSWORDS\n");
    printf("============================================\n\n");

    read_line("Search: ", search, sizeof(search));

    if (search[0] == '\0')
    {
        return;
    }

    for (i = 0; i < vault->count; i++)
    {
        const PasswordRecord *r = &vault->records[i];

        if (strstr(r->title, search) != NULL ||
            strstr(r->username, search) != NULL ||
            strstr(r->website, search) != NULL)
        {
            printf("\n[%u] %s\n",
                   (unsigned)(i + 1),
                   r->title);

            printf("    Username: %s\n", r->username);
            printf("    Website : %s\n", r->website);

            found = 1;
        }
    }

    if (!found)
        printf("\nNo matching records.\n");

    wait_enter();
}

static void password_generator(void)
{
    char length_text[32];
    char password[128];
    long length;

    clear_screen();

    printf("============================================\n");
    printf("             PASSWORD GENERATOR\n");
    printf("============================================\n\n");

    read_line("Length (8-64): ",
              length_text,
              sizeof(length_text));

    length = strtol(length_text, NULL, 10);

    if (length < 8 || length > 64)
    {
        printf("Invalid length.\n");
        wait_enter();
        return;
    }

    generate_password(
        password,
        (size_t)length + 1
    );

    if (password[0] == '\0')
    {
        printf("Password generation failed.\n");
        wait_enter();
        return;
    }

    printf("\nGenerated password:\n\n");
    printf("%s\n", password);

    wait_enter();

    secure_zero(password, sizeof(password));
}

static int copy_to_clipboard(const char *text)
{
    HGLOBAL memory;
    SIZE_T bytes;
    wchar_t *wide_text;
    int required;

    if (text == NULL)
        return 0;

    if (!OpenClipboard(NULL))
        return 0;

    if (!EmptyClipboard())
    {
        CloseClipboard();
        return 0;
    }

    required = MultiByteToWideChar(
        CP_UTF8,
        0,
        text,
        -1,
        NULL,
        0
    );

    if (required <= 0)
    {
        CloseClipboard();
        return 0;
    }

    bytes = (SIZE_T)required * sizeof(wchar_t);

    memory = GlobalAlloc(GMEM_MOVEABLE, bytes);

    if (memory == NULL)
    {
        CloseClipboard();
        return 0;
    }

    wide_text = (wchar_t *)GlobalLock(memory);

    if (wide_text == NULL)
    {
        GlobalFree(memory);
        CloseClipboard();
        return 0;
    }

    MultiByteToWideChar(
        CP_UTF8,
        0,
        text,
        -1,
        wide_text,
        required
    );

    GlobalUnlock(memory);

    if (SetClipboardData(CF_UNICODETEXT, memory) == NULL)
    {
        GlobalFree(memory);
        CloseClipboard();
        return 0;
    }

    CloseClipboard();

    return 1;
}

static void copy_password(const VaultData *vault)
{
    int index;

    clear_screen();

    printf("============================================\n");
    printf("             COPY PASSWORD\n");
    printf("============================================\n");

    index = select_record(vault);

    if (index < 0)
    {
        wait_enter();
        return;
    }

    if (copy_to_clipboard(vault->records[index].password))
    {
        printf("\nPassword copied to Windows clipboard.\n");
        printf("IMPORTANT: Clipboard contents can be accessed by other programs.\n");
    }
    else
    {
        printf("\nCould not access clipboard.\n");
    }

    wait_enter();
}

static void backup_vault(void)
{
    if (!file_exists(VAULT_FILE))
    {
        printf("\nNo vault exists.\n");
        wait_enter();
        return;
    }

    if (CopyFileA(
            VAULT_FILE,
            BACKUP_FILE,
            FALSE))
    {
        printf("\nEncrypted vault backup created:\n");
        printf("%s\n", BACKUP_FILE);
    }
    else
    {
        printf(
            "\nBackup failed. Windows error: %lu\n",
            (unsigned long)GetLastError()
        );
    }

    wait_enter();
}

static void restore_vault(void)
{
    if (!file_exists(BACKUP_FILE))
    {
        printf("\nBackup file does not exist.\n");
        wait_enter();
        return;
    }

    printf(
        "\nThis will replace the current vault file.\n"
        "Continue? (Y/N): "
    );

    {
        int ch = _getch();

        printf("%c\n", ch);

        if (ch != 'y' && ch != 'Y')
        {
            printf("Restore cancelled.\n");
            wait_enter();
            return;
        }
    }

    if (CopyFileA(
            BACKUP_FILE,
            VAULT_FILE,
            FALSE))
    {
        printf("\nVault restored.\n");
        printf("Lock/exit and reopen the program to use the restored vault.\n");
    }
    else
    {
        printf(
            "\nRestore failed. Windows error: %lu\n",
            (unsigned long)GetLastError()
        );
    }

    wait_enter();
}

static int change_master_password(
    VaultData *vault,
    char *master_password,
    size_t master_password_size
)
{
    char current[512];
    char new_password[512];
    char confirm[512];

    clear_screen();

    printf("============================================\n");
    printf("           CHANGE MASTER PASSWORD\n");
    printf("============================================\n\n");

    read_password(
        "Current master password: ",
        current,
        sizeof(current)
    );

    if (strcmp(current, master_password) != 0)
    {
        secure_zero(current, sizeof(current));
        printf("\nIncorrect master password.\n");
        wait_enter();
        return 0;
    }

    read_password(
        "New master password: ",
        new_password,
        sizeof(new_password)
    );

    if (strlen(new_password) < 12)
    {
        secure_zero(current, sizeof(current));
        secure_zero(new_password, sizeof(new_password));

        printf("\nNew password must contain at least 12 characters.\n");
        wait_enter();
        return 0;
    }

    read_password(
        "Confirm new password: ",
        confirm,
        sizeof(confirm)
    );

    if (strcmp(new_password, confirm) != 0)
    {
        secure_zero(current, sizeof(current));
        secure_zero(new_password, sizeof(new_password));
        secure_zero(confirm, sizeof(confirm));

        printf("\nPasswords do not match.\n");
        wait_enter();
        return 0;
    }

    if (!save_vault(vault, new_password))
    {
        secure_zero(current, sizeof(current));
        secure_zero(new_password, sizeof(new_password));
        secure_zero(confirm, sizeof(confirm));

        printf("\nCould not save vault with new password.\n");
        wait_enter();
        return 0;
    }

    copy_string(
        master_password,
        master_password_size,
        new_password
    );

    secure_zero(current, sizeof(current));
    secure_zero(new_password, sizeof(new_password));
    secure_zero(confirm, sizeof(confirm));

    printf("\nMaster password changed successfully.\n");

    wait_enter();

    return 1;
}

static void show_menu(const VaultData *vault)
{
    printf("\n============================================\n");
    printf("             C PASSWORD MANAGER\n");
    printf("============================================\n");
    printf("Encrypted Windows C Password Vault\n");
    printf("--------------------------------------------\n");
    printf("Records: %u\n", (unsigned)vault->count);
    printf("--------------------------------------------\n");
    printf("1.  Add Password\n");
    printf("2.  List Passwords\n");
    printf("3.  Search Passwords\n");
    printf("4.  View Password\n");
    printf("5.  Edit Password\n");
    printf("6.  Delete Password\n");
    printf("7.  Generate Password\n");
    printf("8.  Copy Password\n");
    printf("9.  Backup Vault\n");
    printf("10. Restore Vault\n");
    printf("11. Change Master Password\n");
    printf("12. Lock / Exit\n");
    printf("============================================\n");
}

int main(void)
{
    VaultData *vault = NULL;

    char master_password[512];
    char input[32];

    int choice;
    int attempts;

    SetConsoleTitleA("C Password Manager");

    printf("============================================\n");
    printf("        C PASSWORD MANAGER STARTING\n");
    printf("============================================\n");
    printf("Windows CNG / AES-256-GCM / PBKDF2-SHA256\n");
    printf("\n");

    vault = (VaultData *)calloc(1, sizeof(VaultData));

    if (vault == NULL)
        fatal_error("Could not allocate vault memory.");

    memset(master_password, 0, sizeof(master_password));

    if (!file_exists(VAULT_FILE))
    {
        printf("No vault found.\n");
        printf("Creating a new encrypted vault.\n\n");

        read_password(
            "Create master password: ",
            master_password,
            sizeof(master_password)
        );

        if (strlen(master_password) < 12)
        {
            secure_zero(master_password, sizeof(master_password));
            free(vault);

            fatal_error(
                "Master password must contain at least 12 characters."
            );
        }

        memset(vault, 0, sizeof(*vault));

        if (!save_vault(vault, master_password))
        {
            secure_zero(master_password, sizeof(master_password));
            secure_zero(vault, sizeof(*vault));
            free(vault);

            fatal_error("Could not create encrypted vault.");
        }

        printf("\nEncrypted vault created successfully.\n");
        wait_enter();
    }
    else
    {
        int loaded = 0;

        for (attempts = 1; attempts <= 3; attempts++)
        {
            clear_screen();

            printf("============================================\n");
            printf("              UNLOCK VAULT\n");
            printf("============================================\n\n");

            printf(
                "Attempt %d of 3\n\n",
                attempts
            );

            read_password(
                "Master password: ",
                master_password,
                sizeof(master_password)
            );

            if (load_vault(vault, master_password))
            {
                loaded = 1;
                break;
            }

            secure_zero(
                master_password,
                sizeof(master_password)
            );

            printf("\nIncorrect password or damaged vault.\n");

            if (attempts < 3)
                wait_enter();
        }

        if (!loaded)
        {
            secure_zero(master_password, sizeof(master_password));
            secure_zero(vault, sizeof(*vault));
            free(vault);

            fatal_error(
                "Unable to unlock vault after 3 attempts."
            );
        }

        printf("\nVault unlocked successfully.\n");
        wait_enter();
    }

    while (1)
    {
        clear_screen();

        show_menu(vault);

        read_line(
            "\nSelect option: ",
            input,
            sizeof(input)
        );

        choice = atoi(input);

        switch (choice)
        {
            case 1:
                add_password(vault);

                if (!save_vault(vault, master_password))
                    fatal_error("Could not save vault.");

                break;

            case 2:
                list_passwords(vault);
                break;

            case 3:
                search_passwords(vault);
                break;

            case 4:
                view_password(vault);
                break;

            case 5:
                edit_password(vault);

                if (!save_vault(vault, master_password))
                    fatal_error("Could not save vault.");

                break;

            case 6:
                delete_password(vault);

                if (!save_vault(vault, master_password))
                    fatal_error("Could not save vault.");

                break;

            case 7:
                password_generator();
                break;

            case 8:
                copy_password(vault);
                break;

            case 9:
                backup_vault();
                break;

            case 10:
                restore_vault();
                break;

            case 11:
                change_master_password(
                    vault,
                    master_password,
                    sizeof(master_password)
                );
                break;

            case 12:
                clear_screen();

                printf("Locking password vault...\n");

                secure_zero(
                    master_password,
                    sizeof(master_password)
                );

                secure_zero(
                    vault,
                    sizeof(*vault)
                );

                free(vault);

                printf("Vault locked.\n");
                return 0;

            default:
                printf("\nInvalid option.\n");
                wait_enter();
                break;
        }
    }

    return 0;
}