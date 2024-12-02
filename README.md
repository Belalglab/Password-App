# Password-App
 1. Overview 
The password manager is a program that helps save and retrieve passwords securely. It uses strong encryption to make sure no one can read stored passwords without the master password. 
 2. Key Features
- Save a master password securely using hashing.
- Encrypt and store passwords safely in a file. 
- Retrieve passwords only after logging in with the master password.
- Generate strong, random passwords. 
3. How to Run It 
Install GCC and OpenSSL.
Compile the program with this command: `gcc -o password_manager password_manager.c -lcrypto ` 
Run the program with this command: `./password_manager`
4. What the Program Does - 
First, it asks for a master password and saves it securely.
- It lets you save passwords for different accounts (like email or social media). 
- All passwords are encrypted and saved in a file. 
- You can see your passwords only after logging in with the master password. 
- It also generates random, strong passwords if you need them.
5. Why It Is Secure 
- It uses AES-256, a very strong encryption standard.
 - It uses PBKDF2 to make the master password harder to guess. 
- Each password has unique encryption data.
6. Conclusion
This password manager is a simple and effective tool for keeping passwords safe. Future versions could include backups or a better user interface to make it more useful.

![image](https://github.com/user-attachments/assets/5041a506-82b9-4047-8fbd-6bd432d7bf54)
