# C Password Manager

A native Windows password manager written entirely in **C** using **MinGW/GCC** and the **Windows Cryptography API: Next Generation (CNG)**.

The application provides an encrypted local password vault that can be used from the Windows command line.

---

## Features

* 🔐 Master password protection
* 🔒 AES-256-GCM authenticated encryption
* 🧂 Cryptographically secure random salt
* 🔢 Cryptographically secure random nonce
* 🧮 PBKDF2-HMAC-SHA256 key derivation
* 🔁 600,000 PBKDF2 iterations
* ➕ Add password records
* 📋 List saved records
* 🔎 Search records
* 👁️ View password details
* ✏️ Edit records
* 🗑️ Delete records
* 🎲 Secure password generator
* 📋 Copy passwords to Windows clipboard
* 💾 Encrypted vault backup
* ♻️ Vault restore
* 🔑 Change master password
* 🔒 Lock and exit
* 🧹 Sensitive data is cleared from memory where appropriate
* 🪟 Native Windows executable
* 🚫 No database required
* 🚫 No internet connection required
* 🚫 No cloud account required

---

# Technology

The project is written in:

**C**

Compiler:

**GCC / MinGW-w64**

Recommended environment:

**MSYS2 UCRT64**

Windows cryptography:

**Windows CNG / BCrypt**

Libraries used:

* `bcrypt`
* `user32`

The program does not require C++.

---

# Encryption

The vault is not stored as plain text.

The password records are encrypted using:

**AES-256-GCM**

AES-GCM provides both:

1. Confidentiality
2. Authentication/integrity protection

The master password itself is not used directly as the AES key.

Instead, the application derives a 256-bit encryption key using:

**PBKDF2-HMAC-SHA256**

with:

* 600,000 iterations
* 16-byte random salt
* 32-byte derived key

The AES-GCM encryption uses:

* 256-bit key
* 12-byte random nonce
* 16-byte authentication tag

Every vault save generates a new random salt and nonce.

---

# Vault File

The encrypted vault is stored locally as:

```text
vault.dat
```

The file is binary and encrypted.

The basic vault structure contains:

```text
CPMV002
Plaintext size
Salt
Nonce
Authentication tag
Encrypted vault data
```

The actual password records are not stored in readable plain text inside `vault.dat`.

---

# Password Records

Each record can contain:

```text
Title
Username
Password
Website
Notes
```

Example:

```text
Title    : Gmail
Username : example@gmail.com
Password : ********
Website  : https://gmail.com
Notes    : Personal account
```

---

# Project Structure

The project can be organized as:

```text
PASSWORD/
│
├── CPasswordManager.c
├── CPasswordManager.exe
├── vault.dat
├── vault_backup.dat
└── README.md
```

### CPasswordManager.c

Main C source code.

### CPasswordManager.exe

Compiled Windows executable.

### vault.dat

Encrypted password vault.

### vault_backup.dat

Encrypted backup copy of the vault.

### README.md

Project documentation.

---

# Requirements

## Operating System

Windows 10 or Windows 11.

## Compiler

MinGW-w64 GCC.

Recommended:

**MSYS2 UCRT64**

Check GCC:

```bash
gcc --version
```

---

# Compilation

Open **MSYS2 UCRT64**.

Navigate to the project directory:

```bash
cd "/d/DAILY COLLECTION TILL 6 30 PM/C Projects/PASSWORD"
```

Compile:

```bash
gcc -std=c11 -O2 -Wall -Wextra CPasswordManager.c -o CPasswordManager.exe -lbcrypt -luser32
```

If compilation succeeds, start the program:

```bash
./CPasswordManager.exe
```

---

# First Run

When the application is started for the first time, no vault exists.

The program displays:

```text
No vault found.
Creating a new encrypted vault.

Create master password:
```

Create a strong master password containing at least 12 characters.

Example format:

```text
YourOwnStrongPassword@2026!
```

Do not use the example password above as your actual password.

After successful creation, the encrypted vault is saved as:

```text
vault.dat
```

---

# Unlocking the Vault

When `vault.dat` already exists, the application asks for the master password:

```text
============================================
              UNLOCK VAULT
============================================

Attempt 1 of 3

Master password:
```

The program allows three attempts.

If the correct password is supplied, the vault is decrypted and loaded into memory.

---

# Main Menu

After unlocking, the application provides:

```text
============================================
             C PASSWORD MANAGER
============================================
Encrypted Windows C Password Vault
--------------------------------------------
Records: 0
--------------------------------------------
1.  Add Password
2.  List Passwords
3.  Search Passwords
4.  View Password
5.  Edit Password
6.  Delete Password
7.  Generate Password
8.  Copy Password
9.  Backup Vault
10. Restore Vault
11. Change Master Password
12. Lock / Exit
============================================
```

---

# Adding a Password

Select:

```text
1
```

The application asks for:

```text
Title
Username
Password
Website
Notes
```

The password is entered with masked characters.

Example:

```text
Title    : Gmail
Username : example@gmail.com
Password : ********
Website  : https://gmail.com
Notes    : Personal email
```

After the record is added, the complete vault is encrypted and saved.

---

# Searching

Select:

```text
3
```

The search can find records using:

* Title
* Username
* Website

Example:

```text
Search: gmail
```

---

# Password Generator

Select:

```text
7
```

Choose a password length between:

```text
8 - 64 characters
```

The generator uses Windows CNG's secure random number generator.

The generated password can contain:

* Lowercase letters
* Uppercase letters
* Numbers
* Symbols

---

# Clipboard

Select:

```text
8
```

Choose a password record.

The password is copied to the Windows clipboard.

### Security warning

Clipboard contents may potentially be accessible to other applications running on the computer.

Do not leave sensitive passwords in the clipboard longer than necessary.

---

# Backup

Select:

```text
9
```

The encrypted vault is copied to:

```text
vault_backup.dat
```

The backup is still encrypted.

The backup does **not** contain a readable copy of your passwords.

---

# Restore

Select:

```text
10
```

The application restores:

```text
vault_backup.dat
```

to:

```text
vault.dat
```

After restoring, lock and reopen the application so the restored vault can be loaded.

---

# Change Master Password

Select:

```text
11
```

The application asks for:

```text
Current master password
New master password
Confirm new password
```

The vault is then encrypted using a key derived from the new master password.

The password records themselves remain protected by encryption.

---

# Lock / Exit

Select:

```text
12
```

The application:

1. Clears the master password from memory.
2. Clears the vault structure from memory.
3. Frees allocated memory.
4. Exits the application.

To access the vault again, start:

```bash
./CPasswordManager.exe
```

and enter the master password.

---

# Security Model

The important security chain is:

```text
Master Password
       │
       ▼
PBKDF2-HMAC-SHA256
       │
       │ 600,000 iterations
       ▼
256-bit Encryption Key
       │
       ▼
AES-256-GCM
       │
       ▼
Encrypted vault.dat
```

When unlocking:

```text
Master Password
       │
       ▼
PBKDF2-HMAC-SHA256
       │
       ▼
Same encryption key
       │
       ▼
AES-256-GCM authentication
       │
       ▼
Decrypt Vault
       │
       ▼
Password Records
```

If the authentication tag does not match, the vault is rejected.

---

# Important Security Rules

## 1. Do not forget the master password

There is no password-recovery service.

If the master password is lost, the encrypted vault cannot normally be recovered through this application.

---

## 2. Protect vault.dat

Keep:

```text
vault.dat
```

private.

Although the file is encrypted, someone who obtains it can attempt offline password guessing.

Use a strong master password.

---

## 3. Protect backups

The backup file:

```text
vault_backup.dat
```

contains an encrypted copy of the vault.

Treat it as sensitive data.

---

## 4. Do not modify vault.dat manually

Do not edit the file with:

* Notepad
* Hex editors
* Text editors
* Other programs

Manual modification can corrupt the vault.

---

## 5. Keep the master password unique

Do not reuse your Windows password, email password, banking password, or other important password as the vault master password.

---

# Data Storage

The application is completely local.

It does not require:

```text
Internet
Cloud storage
Online database
Web server
Subscription
Account
```

Password data remains on the local computer unless the user manually copies the vault or backup elsewhere.

---

# Limitations

This is a local command-line password manager.

It currently does not provide:

* Cloud synchronization
* Browser extension integration
* Multi-user accounts
* Network sharing
* Automatic clipboard clearing
* Hardware security-key integration
* Windows Hello integration
* GUI interface

The application should therefore be treated as a local security utility rather than a replacement for professionally audited commercial password-management software.

---

# Building the Executable

The complete build command is:

```bash
gcc -std=c11 -O2 -Wall -Wextra CPasswordManager.c -o CPasswordManager.exe -lbcrypt -luser32
```

Run:

```bash
./CPasswordManager.exe
```

---

# Development

The application is intentionally written in C to provide hands-on experience with:

* C programming
* Windows APIs
* Windows CNG
* Memory management
* File I/O
* Binary file formats
* Cryptography APIs
* Secure random number generation
* Console applications
* Password handling
* Windows clipboard APIs
* Error handling

---

# License

This project does not currently specify an open-source license.

If this project is published publicly, add an appropriate license before distributing it.

---

# Disclaimer

This software is provided for educational and personal-use purposes.

Cryptographic software should ideally undergo independent security review and professional penetration/security testing before being relied upon for highly sensitive production credentials.

The developers of this project are not responsible for password loss, data loss, vault corruption, compromised credentials, or other damages resulting from use of the software.

---

# Project Status

**Working Windows C password manager**

Current core functionality:

```text
[✓] Windows executable
[✓] Master password
[✓] Encrypted vault
[✓] AES-256-GCM
[✓] PBKDF2-HMAC-SHA256
[✓] Add records
[✓] List records
[✓] Search
[✓] View
[✓] Edit
[✓] Delete
[✓] Password generator
[✓] Clipboard
[✓] Backup
[✓] Restore
[✓] Change master password
[✓] Lock / Exit
[✓] Local storage
[✓] No database required
[✓] No internet required
```

---

## Quick Start

```bash
cd "/d/DAILY COLLECTION TILL 6 30 PM/C Projects/PASSWORD"

gcc -std=c11 -O2 -Wall -Wextra CPasswordManager.c -o CPasswordManager.exe -lbcrypt -luser32

./CPasswordManager.exe
```

Create your master password, add your credentials, and the encrypted vault will be stored locally as:

```text
vault.dat
```

**Keep your master password and encrypted vault backups safe.**
