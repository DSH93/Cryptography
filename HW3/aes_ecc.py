from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from ecc_ex import EC, ECPoint, ECPKS
from make_sig_keys import *
from os import urandom
import hashlib
import random
import time
from modular_funcs import inverse
import os



class AES:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        iv = urandom(16)
        cipher = Cipher(
            algorithms.AES(self.key), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, data):
        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = decryptor.update(data[16:]) + decryptor.finalize()
        return unpadder.update(decrypted_data) + unpadder.finalize()

def is_valid_signature(k, h, private_key, ecc_obj):
    kG = ecc_obj.e.power(ecc_obj.G, k)
    r = kG.x % ecc_obj.n
    if r == 0:
        return None
    s = (inverse(k, ecc_obj.n) * (h + private_key * r)) % ecc_obj.n
    if s == 0:
        return None
    return r, s

def make_signature(ecc_public_key, ecc_private_key, filename, ecc_obj):
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

def user_input():
    script_dir = os.path.dirname(os.path.abspath(__file__))  # Get the directory where the script is located
    while True:
        user_choice = input("What would you like to do? e: encrypt, d: decrypt: ")
        if user_choice in ("e", "d"):
            action = "encrypt" if user_choice == "e" else "decrypt"
            filename = input(f"Enter a filename to {action}: ")
            file_path = os.path.join(script_dir, filename)  # Construct absolute path
            print(f"Checking file path: {file_path}")  # Debug print to check the constructed path
            if os.path.exists(file_path):
                break  # Valid file and choice, exit loop
            else:
                print("File does not exist")
        else:
            print("Invalid choice")
    return file_path, user_choice


def extract_data(enc_data_file):
    with open(enc_data_file, "rb") as reader:
        all_encrypted_data = reader.read()

    signature_size = 64
    encrypted_AES_key_size = 32

    signature = all_encrypted_data[:signature_size]
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")

    encrypted_AES_key = all_encrypted_data[signature_size:signature_size + encrypted_AES_key_size]
    encrypted_data = all_encrypted_data[signature_size + encrypted_AES_key_size:]

    return r, s, encrypted_AES_key, encrypted_data


def get_encrypted_AES_key_in_bytes(encrypted_AES_key):
    encrypted_key_bytes = (encrypted_AES_key[0].x.to_bytes(32, 'big') +
                           encrypted_AES_key[0].y.to_bytes(32, 'big') +
                           encrypted_AES_key[1].x.to_bytes(32, 'big') +
                           encrypted_AES_key[1].y.to_bytes(32, 'big'))
     
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(encrypted_key_bytes)
    hashed_key = digest.finalize()
     
    return hashed_key, encrypted_key_bytes


def get_encrypted_data(plaintext, AES_obj, input_filename):
    with open(input_filename, 'rb') as f:
        plaintext = f.read()
    encrypted_data = AES_obj.encrypt(plaintext)
    return encrypted_data

def write_encrypted_data(encrypted_data, filename):
    output_filename = filename.split(".")[0] + ".enc"
    print("encrypting data...\n")
    with open(output_filename, "wb") as writer:
        writer.write(encrypted_data)
    time.sleep(1)
    print("Data has been encrypted and saved to", output_filename)
    

def check_signature(M, signature,ecc_public_key):
    h = int.from_bytes(hashlib.sha256(M).digest(), "big")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r < 1 or r > ecc_public_key.n - 1 or s < 1 or s > ecc_public_key.n - 1:
        return False
    w = inverse(s, ecc_public_key.n)
    u1 = (h * w) % ecc_public_key.n
    u2 = (r * w) % ecc_public_key.n
    u1G = ecc_public_key.e.power(ecc_public_key.G, u1)
    u2Q = ecc_public_key.e.power(ecc_public_key.Q, u2)
    P = ecc_public_key.e.add(u1G, u2Q)
    return r == P.x % ecc_public_key.n

def read_encrypted_data(enc_data_file, ecc_obj):
    r, s, encrypted_AES_key, encrypted_data = extract_data(enc_data_file)
    hashed_key, encrypted_key_bytes = get_encrypted_AES_key_in_bytes(encrypted_AES_key)
    AES_obj = AES(hashed_key)
    decrypted_data = AES_obj.decrypt(encrypted_data)
    print("Decrypted data:\n", decrypted_data)
    time.sleep(0.5)
    print("Checking signature...\n")
    time.sleep(1)
    if check_signature(decrypted_data, r.to_bytes(32, "big") + s.to_bytes(32, "big"), ecc_obj):
        print("Signature OK\n")
    else:
        print("Signature not OK\n")
    
    return r, s, encrypted_key_bytes, decrypted_data



def full_encryption_process(input_filename, ecc_obj, ecc_public_key, ecc_private_key):  

    signature = make_signature(ecc_public_key, ecc_private_key, input_filename, ecc_obj)
    key = urandom(16)
    encrypted_AES_key = ecc_obj.encrypt(key, ecc_public_key)
    hashed_key, encrypted_key_bytes = get_encrypted_AES_key_in_bytes(encrypted_AES_key)
    AES_obj = AES(hashed_key)
    encrypted_data = get_encrypted_data(input_filename, AES_obj, input_filename)
    all_encrypted_data = signature + encrypted_key_bytes + encrypted_data
    write_encrypted_data(all_encrypted_data, input_filename)


    


def main():
    ecc_obj = sig_keys()
    ecc_public_key = read_binary_key("sig_public_key.bin", is_ec_point=True)
    ecc_private_key = read_binary_key("sig_private_key.bin")
    
    while True:
        input_filename, user_choice = user_input()
        if user_choice == "e":
            full_encryption_process(input_filename, ecc_obj, ecc_public_key, ecc_private_key)
            
        elif user_choice == "d":
            r, s, encrypted_key_bytes, decrypted_data = read_encrypted_data(input_filename, ecc_obj)
        else:
            print("Invalid choice")


    

if __name__ == "__main__":
    main()
