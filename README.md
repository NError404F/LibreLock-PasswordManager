# LibreLock Password Manager

*(if you have better name idea hmu)*

**LibreLock** is a secure, modern password manager built with Python and CustomTkinter. It lets you store, manage, and safely retrieve your passwords, emails, URLs, and notes—all encrypted and protected. Perfect for the extra-paranoid types who triple-check everything.

---
## A Little Backstory (Raw & Honest)

This is my **first “real” program**. Made with:  

- A LOT of coffee ☕  
- A few too many cigarettes 🚬  
- Endless Googling 🤓  
- Frequent “Hey ChatGPT, how do I…?” moments 💬  

It’s made for the extra-paranoid, the overthinkers, and anyone who likes their passwords wrapped in digital bubble wrap.  

---
## ⚠️ Important Disclaimer

This software is **experimental** and primarily a learning project. While the source code here is provided for transparency, **you should always review the code yourself before using it**.  

Never blindly trust any build from the internet—someone could fork this project and release a version with malicious modifications.  

Remember: even paranoid software is only as safe as the user’s diligence. 🕵️‍♂️

---
## Features

- **Secure User Registration & Login**
  - Master password with at least 12 characters, including uppercase, lowercase, numbers, and symbols.
  - Argon2 hashing for master passwords (because SHA256 alone just won’t cut it).
  - Per-user encryption keys derived from your master password.

- **Password Management**
  - Add, view, update, and delete passwords.
  - Store username, email, service URL, notes, and password.
  - Searchable password list with real-time filtering (because scrolling forever is painful).

- **Security**
  - AES-like encryption using Fernet for password storage.
  - HMAC validation for integrity verification.
  - Per-password random salts.
  - Safe copy-to-clipboard functionality (no accidental leaks).

- **Custom Modern UI**
  - Built with `customtkinter` for a sleek, responsive interface.
  - Dark mode by default.
  - Custom popups instead of boring system message boxes.

- **Master Password Management**
  - Change master password and automatically re-encrypt all stored passwords.
  - Logging sanitized—won’t spill your secrets.

- **Extras**
  - Notes support for each service.
  - Service URLs stored and retrievable.

---

## Installation

1. **Clone the repository**

```bash
git clone https://github.com/yourusername/LibreLock.git
cd LibreLock
```
2. **Install dependencies**

```bash
pip install -r requirements.txt
```
Dependencies:

- customtkinter

- argon2-cffi

- cryptography

3. **Run the application**

```bash
python main.py
```
## Usage

1. Launch LibreLock.

2. Register a new user with a strong master password.

3. Login using your credentials.

4. Use the main interface to:

   - Add new password entries.

   - View, update, or delete existing passwords.

   - Search for services using the search bar.

   - Copy passwords safely to the clipboard.

   - Change your master password securely.

## Security Notes

- Master passwords are **never stored in plaintext**.

- All sensitive fields are encrypted individually with a unique salt.

- Logging is sanitized to avoid leaking sensitive data.

- Uses strong crypto primitives: Argon2 for password hashing, Fernet for encryption.

## License & Credits

**License:** Free to use, fork, and improve. Just **give credit**.  

*Zero design skills—UI was basically assembled with help from ChatGPT 😅*   

*Some code snippets were assisted by ChatGPT.*

*No warranties; use at your own risk.*

