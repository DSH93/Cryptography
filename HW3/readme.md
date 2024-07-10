```markdown
# Encryption and Decryption with AES and ECC

This project demonstrates the use of AES (Advanced Encryption Standard) for encryption and decryption of files, combined with ECC (Elliptic Curve Cryptography) for secure key exchange and digital signatures.

## Files in the Project

- **encryption_files/**: Contains the binary keys and encrypted files.
  - **sig_public_key.bin**: ECC public key used for signature verification.
  - **sig_private_key.bin**: ECC private key used for signing.
  - **ec_bitcoin.txt**: ECC parameters file.

- **scripts/**: Contains all the scripts for encryption, decryption, and key generation.
  - **aes_ecc.py**: The main script that handles encryption and decryption processes.
  - **ecc_ex.py**: Contains ECC-related classes and functions.
  - **make_sig_keys.py**: Script to generate ECC signature keys.
  - **make_ecc_keys.py**: Script to read ECC keys from binary files.
  - **modular_funcs.py**: Contains modular arithmetic functions, including modular inverse.

## Requirements

Before running the script, ensure you have the following Python packages installed:

- cryptography

You can install the required packages using pip:

```bash
pip install cryptography 
```

## How to Use

1. **Clone the repository**:
   
   ```bash
   git clone https://github.com/DSH93/Cryptography.git
   cd HW3
   ```

2. **Prepare the ECC Keys for Decryption**:
   
   Ensure you have the ECC keys `sig_public_key.bin` and `sig_private_key.bin` in the `encryption_files` directory if you want to decrypt files. If you need to generate these keys for encryption, the script will handle it.

3. **Run the Script**:

   From the root directory of the project:

   ```bash
   python scripts/aes_ecc.py
   ```

   The script will prompt you to enter 'e' to encrypt a file or 'd' to decrypt a file.

4. **Encrypt a File**:

   - Choose 'e' when prompted.
   - Enter the filename you wish to encrypt (e.g., `example.txt`).
   - The script will generate an encrypted file in the `encryption_files` directory with a `.enc` extension (e.g., `example.enc`).

5. **Decrypt a File**:

   - Choose 'd' when prompted.
   - Enter the filename you wish to decrypt (e.g., `example.enc`).
   - The script will decrypt the file and print the decrypted content if the signature is verified.

## Explanation of the Process

1. **Encryption**:

   - The script reads the plaintext file.
   - Encrypts the AES key using ECC.
   - Generates a random AES key and encrypts the plaintext using the encrypted AES key in CBC mode.
   - Creates a digital signature of the plaintext using ECC.
   - Writes the encrypted data, encrypted AES key, and the digital signature to a new file in the `encryption_files` directory with a `.enc` extension.

2. **Decryption**:

   - The script reads the encrypted file from the `encryption_files` directory.
   - Extracts the encrypted AES key, encrypted data, and the digital signature.
   - Decrypts the AES key using ECC.
   - Uses the decrypted AES key to decrypt the data.
   - Verifies the digital signature.
   - Prints the decrypted content if the signature is valid.

## Troubleshooting

- Ensure the ECC key files (`sig_public_key.bin` and `sig_private_key.bin`) are present in the `encryption_files` directory when decrypting files.
- Make sure the filename provided during encryption/decryption is correct and the file exists.
- Verify that the required Python packages are installed.
- Ensure you are running the script from the root directory of the project to avoid file path issues.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

## Author

Developed by Dor Shukrun. For any questions or issues, please contact dorke88@gmail.com.
```
