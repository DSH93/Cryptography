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
    def __init__(self, key):
        self.key = key

    def encrypt(self, data): # data is in bytes
        iv = urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data
    

    def decrypt(self, data):
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



def unpad(data):
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def get_encrypted_AES_key_in_bytes(encrypted_AES_key): # returns hashed key and encrypted key bytes
    encrypted_key_bytes = (encrypted_AES_key[0].x.to_bytes(32, 'big') + encrypted_AES_key[0].y.to_bytes(32, 'big') +
                           encrypted_AES_key[1].x.to_bytes(32, 'big') + encrypted_AES_key[1].y.to_bytes(32, 'big')) 
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend()) # hash the encrypted key
    digest.update(encrypted_key_bytes) 
    hashed_key = digest.finalize() 
    return hashed_key, encrypted_key_bytes



def get_encrypted_data(input_filename, AES_obj): # returns encrypted data
    with open(input_filename, 'rb') as f:
        plaintext = f.read()
    encrypted_data = AES_obj.encrypt(plaintext)
    if len(encrypted_data) % 16 != 0: # check if encrypted data length is a multiple of block size
        raise ValueError("Encrypted data length is not a multiple of block size.")
    return encrypted_data



def write_encrypted_data(signature, encrypted_key_bytes, encrypted_data, filename):
    output_filename = filename.split(".")[0] + ".enc"
    signature_size = len(signature).to_bytes(4, "big")
    encrypted_AES_key_size = len(encrypted_key_bytes).to_bytes(4, "big")
    encrypted_data_size = len(encrypted_data).to_bytes(4, "big")

    with open(output_filename, "wb") as writer:
        writer.write(signature_size + encrypted_AES_key_size + encrypted_data_size)
        writer.write(signature + encrypted_key_bytes + encrypted_data)
    print(f"\nthe encryption process is in progress...")
    time.sleep(1)
    if os.path.exists(output_filename):
        print(f"File {output_filename} created successfully.\n")
    else:
        print(f"File {output_filename} was not created.\n")
        
        
        
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



def check_signature(M, signature, ecc_obj, public_key):
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



# Encryption Process Functions
def extract_data(enc_data_file):
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




def read_encrypted_data(enc_data_file, ecc_obj, public_key):
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




def full_encryption_process(input_filename, ecc_obj, ecc_public_key, ecc_private_key):
    signature = make_signature(ecc_public_key, ecc_private_key, input_filename, ecc_obj)
    key = urandom(16)
    encrypted_AES_key = ecc_obj.encrypt(key, ecc_public_key)
    hashed_key, encrypted_key_bytes = get_encrypted_AES_key_in_bytes(encrypted_AES_key)
    AES_obj = AES(hashed_key)
    encrypted_data = get_encrypted_data(input_filename, AES_obj)
    write_encrypted_data(signature, encrypted_key_bytes, encrypted_data, input_filename)
    



# User Interaction Functions
def user_input():
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



def print_data(data):
    decoded_string = data.decode('utf-8')
    quotes = decoded_string.split('\r\n\r\n')
    print("\ndecrypioin in progress...")
    time.sleep(1)
    print("Decrypted data:")
    for quote in quotes:
        print(quote)


def main():
    while True:
        input_filename, user_choice = user_input()
        if user_choice == "e":
            ecc_obj = sig_keys(to_save=True) # create ECC object and save keys
            ecc_public_key = read_binary_key("sig_public_key.bin", is_ec_point=True)
            ecc_private_key = read_binary_key("sig_private_key.bin")
            full_encryption_process(input_filename, ecc_obj, ecc_public_key, ecc_private_key)
        elif user_choice == "d":
            ecc_obj = sig_keys(to_save=False) # create ECC object without and use existing keys
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
