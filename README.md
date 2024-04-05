# Firefox Password Decryptor

This tool is primarily designed for decrypting and extracting passwords stored in Firefox, offering an in-depth look into the security of saved credentials. It provides additional reconnaissance capabilities such as system info, open ports info, devices info, and Firefox browsing history extraction.

## Main Feature: Firefox Passwords Decryption

1. **Global Salt Retrieval**: Initiates by fetching the global salt from the `key4.db`, laying the groundwork for key generation.

2. **Key Generation via PBKDF2**: Employs PBKDF2 with SHA-256 hashing to craft a decryption key from the global salt, a critical step for accessing encrypted data.

3. **Parsing ASN.1 Encoded Data**: Analyzes ASN.1 encoded structures to extract encrypted credentials alongside their respective algorithms and initialization vectors (IVs).

4. **AES/Triple DES Decryption**: Depending on the specified algorithm, decrypts the credentials using the generated key and IV.

5. **Padding Removal**: Strips padding from decrypted data to unveil plaintext usernames and passwords.

## Additional Features

- **System Info**: Gathers system information including hostname, OS, architecture, CPU count, and memory.
- **Ports Info**: Enumerates open ports and identifies the processes using them.
- **Devices Info**: Lists connected USB devices.
- **Firefox Browsing History**: Extracts and displays the user's Firefox browsing history.

## Getting Started

Clone the repository and compile the source to begin using the toolkit:

```bash
git clone https://github.com/yourusername/Firefox-Passwords-Decryptor.git
cd Firefox-Passwords-Decryptor
go build
```

### Command-Line Options

Execute the tool with specific flags to utilize its various features:

- `-passwords`: Decrypt and display Firefox passwords (primary feature).
- `-sysinfo`: Retrieve system information.
- `-ports`: List information on open ports.
- `-devices`: Display connected USB devices.
- `-history`: Extract Firefox browsing history.

For instance, to decrypt Firefox passwords and view system info:

```bash
./Firefox-Passwords-Decryptor -passwords -sysinfo

>>>

System info:  {
  "Hostname": "hostname",
  "Os": "linux",
  "Arch": "amd64",
  "CpusCount": 1,
  "MemoryCount": 31244
}
Firefox profile path:  /home/username/.mozilla/firefox/filename.default-release
Db path:  /home/username/.mozilla/firefox/filename.default-release/key4.db
Logins:  [
  {
    "Username": "username",
    "Password": "password",
    "URL": "example.com"
  },
  {
    "Username": "username",
    "Password": "password",
    "URL": "example.com"
  },
]
```

## Dependencies

Ensure the following packages are installed:

```bash
go get -u github.com/google/gousb github.com/mattn/go-sqlite3 github.com/pkg/errors
```
## Contributing

Feel free to submit pull requests, open issues for discussion, or suggest improvements.

## License

This project is distributed under the MIT License - see [LICENSE](LICENSE) for details.
