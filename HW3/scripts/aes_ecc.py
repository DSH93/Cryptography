from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from ecc_ex import EC, ECPoint, ECPKS
from make_sig_keys import sig_keys
from make_ecc_keys import read_binary_key
from os import urandom
import hashlib
import random
import time
from modular_funcs import inverse
import os


class AES:
    def __init__(self, key: bytes):
        """
        Initializes the AES object with a given key.
        :param key: The AES encryption key (16 bytes).
        """
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypts the given data using AES-CBC mode.
        :param data: The plaintext data to encrypt (bytes).
        :return: The encrypted data (bytes).
        """
        iv = urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypts the given data using AES-CBC mode.
        :param data: The encrypted data to decrypt (bytes).
        :return: The decrypted plaintext data (bytes).
        """
        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        try:
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
            return unpadded_data
        except ValueError as e:
            return decrypted_data


def unpad(data: bytes) -> bytes:
    """
    Unpads the given data using PKCS7 padding.
    :param data: The padded data (bytes).
    :return: The unpadded data (bytes).
    """
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def get_encrypted_AES_key_in_bytes(encrypted_AES_key: tuple) -> tuple:
    """
    Returns the hashed key and encrypted key bytes.
    :param encrypted_AES_key: The encrypted AES key as a tuple of ECPoints.
    :return: A tuple containing the hashed key (bytes) and the encrypted key bytes (bytes).
    """
    encrypted_key_bytes = (encrypted_AES_key[0].x.to_bytes(32, 'big') + encrypted_AES_key[0].y.to_bytes(32, 'big') +
                           encrypted_AES_key[1].x.to_bytes(32, 'big') + encrypted_AES_key[1].y.to_bytes(32, 'big'))
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())  # hash the encrypted key
    digest.update(encrypted_key_bytes)
    hashed_key = digest.finalize()
    return hashed_key, encrypted_key_bytes


def get_encrypted_data(input_filename: str, AES_obj: AES) -> bytes:
    """
    Encrypts the content of the input file using AES.
    :param input_filename: The name of the file to encrypt (str).
    :param AES_obj: The AES object for encryption.
    :return: The encrypted data (bytes).
    """
    with open(input_filename, 'rb') as f:
        plaintext = f.read()
    encrypted_data = AES_obj.encrypt(plaintext)
    if len(encrypted_data) % 16 != 0:  # check if encrypted data length is a multiple of block size
        raise ValueError("Encrypted data length is not a multiple of block size.")
    return encrypted_data


def write_encrypted_data(signature: bytes, encrypted_key_bytes: bytes, encrypted_data: bytes, filename: str):
    """
    Writes the encrypted data, signature, and encrypted key bytes to a file.
    :param signature: The digital signature (bytes).
    :param encrypted_key_bytes: The encrypted AES key bytes (bytes).
    :param encrypted_data: The encrypted data (bytes).
    :param filename: The name of the original file (str).
    """
    output_filename = filename.split(".")[0] + ".enc"
    signature_size = len(signature).to_bytes(4, "big")
    encrypted_AES_key_size = len(encrypted_key_bytes).to_bytes(4, "big")
    encrypted_data_size = len(encrypted_data).to_bytes(4, "big")

    with open(output_filename, "wb") as writer:
        writer.write(signature_size + encrypted_AES_key_size + encrypted_data_size)
        writer.write(signature + encrypted_key_bytes + encrypted_data)
    print(f"\nThe encryption process is in progress...")
    time.sleep(1)
    if os.path.exists(output_filename):
        print(f"File {output_filename} created successfully.\n")
    else:
        print(f"File {output_filename} was not created.\n")


def is_valid_signature(k: int, h: int, private_key: int, ecc_obj: EC) -> tuple:
    """
    Validates the ECC signature.
    :param k: The random integer k used in signature (int).
    :param h: The hash of the message (int).
    :param private_key: The ECC private key (int).
    :param ecc_obj: The ECC object (EC).
    :return: A tuple (r, s) representing the signature (int, int) or None if invalid.
    """
    kG = ecc_obj.e.power(ecc_obj.G, k)
    r = kG.x % ecc_obj.n
    if r == 0:
        return None
    s = (inverse(k, ecc_obj.n) * (h + private_key * r)) % ecc_obj.n
    if s == 0:
        return None
    return r, s


def make_signature(ecc_public_key: ECPoint, ecc_private_key: int, filename: str, ecc_obj: EC) -> bytes:
    """
    Creates a digital signature for the given file.
    :param ecc_public_key: The ECC public key (ECPoint).
    :param ecc_private_key: The ECC private key (int).
    :param filename: The name of the file to sign (str).
    :param ecc_obj: The ECC object (EC).
    :return: The digital signature (bytes).
    """
    with open(filename, "rb") as f:
        M = f.read()
    h = int.from_bytes(hashlib.sha256(M).digest(), "big")

    while True:
        k = random.SystemRandom().randint(1, ecc_obj.n - 1)
        r, s = is_valid_signature(k, h, ecc_private_key, ecc_obj)
        if r and s:
            break
        continue
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signature


def check_signature(M: bytes, signature: bytes, ecc_obj: EC, public_key: ECPoint) -> bool:
    """
    Checks if the digital signature is valid.
    :param M: The message data (bytes).
    :param signature: The digital signature (bytes).
    :param ecc_obj: The ECC object (EC).
    :param public_key: The ECC public key (ECPoint).
    :return: True if the signature is valid, False otherwise.
    """
    print("\nChecking signature")
    h = int.from_bytes(hashlib.sha256(M).digest(), "big")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r < 1 or r > ecc_obj.n - 1 or s < 1 or s > ecc_obj.n - 1:
        return False
    w = inverse(s, ecc_obj.n)
    u1 = (h * w) % ecc_obj.n
    u2 = (r * w) % ecc_obj.n
    u1G = ecc_obj.e.power(ecc_obj.G, u1)
    u2Q = ecc_obj.e.power(public_key, u2)
    P = ecc_obj.e.add(u1G, u2Q)
    time.sleep(0.7)
    return r == P.x % ecc_obj.n


def extract_data(enc_data_file: str) -> tuple:
    """
    Extracts the signature, encrypted AES key, and encrypted data from the file.
    :param enc_data_file: The name of the encrypted file (str).
    :return: A tuple containing the signature, encrypted AES key, and encrypted data.
    """
    with open(enc_data_file, "rb") as reader:
        all_encrypted_data = reader.read()

    signature_size = int.from_bytes(all_encrypted_data[:4], "big")
    encrypted_AES_key_size = int.from_bytes(all_encrypted_data[4:8], "big")
    encrypted_data_size = int.from_bytes(all_encrypted_data[8:12], "big")
    offset = 12
    signature = all_encrypted_data[offset:offset + signature_size]
    offset += signature_size
    encrypted_AES_key = all_encrypted_data[offset:offset + encrypted_AES_key_size]
    offset += encrypted_AES_key_size
    encrypted_data = all_encrypted_data[offset:offset + encrypted_data_size]
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    return r, s, encrypted_AES_key, encrypted_data


def read_encrypted_data(enc_data_file: str, ecc_obj: EC, public_key: ECPoint) -> tuple:
    """
    Reads and decrypts the encrypted file, and verifies the signature.
    :param enc_data_file: The name of the encrypted file (str).
    :param ecc_obj: The ECC object (EC).
    :param public_key: The ECC public key (ECPoint).
    :return: A tuple containing the signature, encrypted key bytes, and decrypted data.
    """
    r, s, encrypted_AES_key, encrypted_data = extract_data(enc_data_file)
    alpha_x = int.from_bytes(encrypted_AES_key[:32], 'big')
    alpha_y = int.from_bytes(encrypted_AES_key[32:64], 'big')
    beta_x = int.from_bytes(encrypted_AES_key[64:96], 'big')
    beta_y = int.from_bytes(encrypted_AES_key[96:128], 'big')
    alpha = ECPoint(alpha_x, alpha_y)
    beta = ECPoint(beta_x, beta_y)
    encrypted_AES_key = (alpha, beta)
    hashed_key, encrypted_key_bytes = get_encrypted_AES_key_in_bytes(encrypted_AES_key)
    AES_obj = AES(hashed_key)
    decrypted_data = AES_obj.decrypt(encrypted_data)
    print_data(decrypted_data)

    try:
        unpadded_data = unpad(decrypted_data)
    except ValueError as e:
        unpadded_data = decrypted_data

    if check_signature(unpadded_data, r.to_bytes(32, "big") + s.to_bytes(32, "big"), ecc_obj, public_key):
        print("Signature OK\n\n")
    else:
        print("Signature NOT OK\n\n")
    return r, s, encrypted_key_bytes, unpadded_data


def full_encryption_process(input_filename: str, ecc_obj: EC, ecc_public_key: ECPoint, ecc_private_key: int):
    """
    Handles the full encryption process: signing, key encryption, and data encryption.
    :param input_filename: The name of the file to encrypt (str).
    :param ecc_obj: The ECC object (EC).
    :param ecc_public_key: The ECC public key (ECPoint).
    :param ecc_private_key: The ECC private key (int).
    """
    signature = make_signature(ecc_public_key, ecc_private_key, input_filename, ecc_obj)
    key = urandom(16)
    encrypted_AES_key = ecc_obj.encrypt(key, ecc_public_key)
    hashed_key, encrypted_key_bytes = get_encrypted_AES_key_in_bytes(encrypted_AES_key)
    AES_obj = AES(hashed_key)
    encrypted_data = get_encrypted_data(input_filename, AES_obj)
    write_encrypted_data(signature, encrypted_key_bytes, encrypted_data, input_filename)


def user_input() -> tuple:
    """
    Handles user input for choosing encryption or decryption and file selection.
    :return: A tuple containing the filename and the user choice ('e' or 'd').
    """
    while True:
        user_choice = input("Enter 'e' to encrypt or 'd' to decrypt or 'q' to quit: ").lower().strip()
        if user_choice == "q":
            print("Exiting program.")
            exit()
        if user_choice in ("e", "d"):
            action = "encrypt" if user_choice == "e" else "decrypt"
            filename = input(f"Enter a filename to {action}: ")
            if user_choice == "d" and not filename.endswith(".enc"):
                filename = filename.split(".")[0] + ".enc"
            if os.path.exists(filename):
                break  # Valid file and choice, exit loop
            else:
                print("File does not exist")
        else:
            print("Invalid choice")
    return filename, user_choice


def print_data(data: bytes):
    """
    Prints the decrypted data.
    :param data: The decrypted data (bytes).
    """
    decoded_string = data.decode('utf-8')
    quotes = decoded_string.split('\r\n\r\n')
    print("\nDecryption in progress...")
    time.sleep(1)
    print("Decrypted data:")
    for quote in quotes:
        print(quote)


def main():
    while True:
        input_filename, user_choice = user_input()
        if user_choice == "e":
            ecc_obj = sig_keys(to_save=True)  # create ECC object and save keys
            ecc_public_key = read_binary_key("sig_public_key.bin", is_ec_point=True)
            ecc_private_key = read_binary_key("sig_private_key.bin")
            full_encryption_process(input_filename, ecc_obj, ecc_public_key, ecc_private_key)
        elif user_choice == "d":
            ecc_obj = sig_keys(to_save=False)  # create ECC object without and use existing keys
            ecc_public_key = read_binary_key("sig_public_key.bin", is_ec_point=True)
            ecc_private_key = read_binary_key("sig_private_key.bin")
            input_filename = input_filename.split(".")[0] + ".enc"
            if not os.path.exists(input_filename):
                print(f"Error: The file {input_filename} does not exist.")
            else:
                r, s, encrypted_key_bytes, decrypted_data = read_encrypted_data(input_filename, ecc_obj, ecc_public_key)
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
