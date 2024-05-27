## General
____________

### Author
* Josh McIntyre

### Website
* jmcintyre.net

### Overview
* MixingBowl is a simple AES tool for demonstrating symmetric encryption

## Development
________________

### Git Workflow
* master for releases (merge development)
* development for bugfixes and new features

### Building
* make build
Build the application
* make clean
Clean the build directory

### Features
* Encrypt a plaintext using AES-CBC and a given passphrase
* Decrypt a ciphertext using AES-CBC and a given passphrase, plus the salt and IV used for encryption
* Encode the data as base64 text for ease of use

### Requirements
* Requires JavaScript
* Requires a web browser that supports the SubtleCrypto API

### Platforms
* Chrome
* Firefox
* Edge

## Usage
____________

### Web browser encryption
* Enter a passphrase that will be used for encryption
* Enter the plaintext
* Click "encrypt"
* Save the base64 encoded ciphertext, salt, and iv

### Web browser decryption
* Enter the encryption passphrase
* Enter the salt and iv used for encryption
* Enter the ciphertext
* Click "decrypt"
* The plaintext will appear if decryption was successful, or an error message if decryption failed
