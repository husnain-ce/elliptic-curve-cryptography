

# ECC and AES-GCM Encryption System

This Python module provides a secure encryption system utilizing Elliptic Curve Cryptography (ECC) for key exchange and AES-GCM for symmetric key encryption and decryption of messages.

## Features

- **ECC Key Exchange**: Uses the `secp256r1` curve for generating public and private keys.
- **AES-GCM Encryption**: Ensures confidentiality, integrity, and authenticity of the messages.
- **Hexadecimal Encoding**: Outputs the encrypted message in a readable hexadecimal format.

## Dependencies

This module requires the following Python libraries:
- `tinyec`: for handling elliptic curve operations.
- `pycryptodome`: provides cryptographic operations in Python.

To install these dependencies, run:

```bash
pip install tinyec pycryptodome
```

## Usage

The script is a simple command-line tool that guides the user through the process of encrypting and decrypting a message using ECC and AES-GCM.

1. **Input Message**: Enter the plaintext message that you want to encrypt.
2. **Key Generation**: Automatically generates a private key and a corresponding public key.
3. **ECC Encryption**: Encrypts the message using the public key.
4. **ECC Decryption**: Decrypts the message using the private key to retrieve the original plaintext.

The output during the process includes the private key, public key, encrypted message, and decrypted message.

## Example Run

```plaintext
---------------------------ECC PROTOCOL----------------------------
Step 1: Input Message
Enter the message : Hello World
original msg: Hello World

Step 2: Key Generation
Private key : 8745093485730948573094857...
Public key : Point(x=509348573094857, y=30948573094857...)

Step 3: ECC Encryption
encrypted msg: {'ciphertext': 'abcdef123...', 'nonce': '12345abc...', 'authTag': '98765def...', 'ciphertextPubKey': 'abcd1234ef5678...'}

Step 4: ECC Decryption
decrypted msg: Hello World
```

## Security Notes

- Ensure that your environment is secure when handling keys and sensitive data.
- This system is designed for educational and testing purposes, and additional considerations are necessary for production deployment.

## License

This project is open-sourced under the MIT License.

---
