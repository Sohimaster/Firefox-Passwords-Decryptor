# Firefox Password Decryptor

A simple Go tool to decrypt and extract saved passwords from Firefox browsers.

## How it works

Firefox stores encrypted passwords in `logins.json` and the decryption key in `key4.db`. This tool:

1. Locates your Firefox profile directory
2. Extracts the master key from `key4.db` 
3. Decrypts password entries from `logins.json`
4. Outputs usernames, passwords, and associated URLs

The decryption process uses PBKDF2 key derivation and AES/3DES decryption depending on the encryption method used by Firefox.

## Usage

Build and run:

```bash
git clone https://github.com/sohimaster/Firefox-Passwords-Decryptor.git
cd Firefox-Passwords-Decryptor
go build
./Firefox-Passwords-Decryptor
```

### Command options

- `./Firefox-Passwords-Decryptor` - Extract passwords (default)
- `./Firefox-Passwords-Decryptor -passwords` - Extract passwords  
- `./Firefox-Passwords-Decryptor -history` - Extract browsing history
- `./Firefox-Passwords-Decryptor -history -passwords` - Extract both

### Example output

```
Firefox profile path: /home/user/.mozilla/firefox/abc123.default-release
Saved passwords: [
  {
    "Username": "john@example.com",
    "Password": "mypassword123",
    "URL": "https://example.com"
  }
]
```

## Requirements

- Go 1.19+
- Firefox browser with saved passwords
- Read access to Firefox profile directory

## Dependencies

- `github.com/mattn/go-sqlite3` - SQLite database access
- `golang.org/x/crypto` - Cryptographic functions

## License

MIT License - see [LICENSE](LICENSE) file.
