from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from make_sig_keys import *
from os import urandom



class AES:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        iv = urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
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
    
def make_signature(data, private_key, filename):
    
    
    

    
    
def user_input():
    user_choice = input("What you would like to do? e: encrypt, d: decrypt: ")
    if user_choice == 'e':
        filename = input("Enter a filename to encrypt: ")
    elif user_choice == 'd':
        pass
    else:
        raise ValueError("Invalid input")
    return filename

        
 
    
def main():
    filename_eliptic_curve = 'ec_bitcoin.txt'
    e, G, n = read_key(filename_eliptic_curve)
    ecc_obj = ECPKS(e, G, n)
    ecc_private_key, ecc_public_key = ecc_obj.make_key_pair()
    input_filename = user_input()
    make_signature(ecc_public_key, ecc_private_key, input_filename)
    
    key = urandom(32) # AES key
    encrypted_AES_key = ecc_obj.encrypt(key, ecc_public_key) # encrypted AES key with ECC public key, encrypted_AES_key is a tuple
    
    
  
    
    decrypted = ecc_obj.decrypt(C,pr_k)
    print(decrypted)

    
    
if __name__ == '__main__':
    main()