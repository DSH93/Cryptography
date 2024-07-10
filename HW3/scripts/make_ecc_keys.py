import os
from typing import Union
from modular_funcs import inverse, is_quad_res, modular_root
from ecc_ex import ECPoint, EC, ECPKS
import time

# Create the directory for encryption files if it doesn't exist
if not os.path.exists('encryption_files'):
    os.makedirs('encryption_files')

def read_key_file(filename: str) -> bytes:
    """
    Reads the content of a key file.
    :param filename: The name of the key file (str).
    :return: The content of the key file (bytes).
    """
    with open(filename, 'rb') as reader:
        return reader.read()

def save_key(key: bytes, filename: str):
    """
    Saves the given key to a file.
    :param key: The key to save (bytes).
    :param filename: The name of the file to save the key in (str).
    """
    filename = os.path.join('encryption_files', filename)
    with open(filename, 'wb') as writer:
        writer.write(key)

def save_as_binary(key: Union[int, ECPoint], filename: str):
    """
    Saves the given key as a binary file.
    :param key: The key to save (int or ECPoint).
    :param filename: The name of the file to save the key in (str).
    """
    if isinstance(key, int):
        n_bytes = (key.bit_length() + 7) // 8
        key_bytes = key.to_bytes(n_bytes, 'big')
        save_key(key_bytes, filename)
    elif isinstance(key, ECPoint):
        n_bytes_x = (key.x.bit_length() + 7) // 8
        n_bytes_y = (key.y.bit_length() + 7) // 8
        x_bytes = key.x.to_bytes(n_bytes_x, 'big')
        y_bytes = key.y.to_bytes(n_bytes_y, 'big')
        save_key(x_bytes + y_bytes, filename)
    else:
        raise ValueError("Unsupported key type")

def read_binary_key(filename: str, is_ec_point: bool = False) -> Union[int, ECPoint]:
    """
    Reads a binary key from a file.
    :param filename: The name of the key file (str).
    :param is_ec_point: Whether the key is an ECPoint (bool).
    :return: The key (int or ECPoint).
    """
    filename = os.path.join('encryption_files', filename)
    key_bytes = read_key_file(filename)
    if not is_ec_point:
        return int.from_bytes(key_bytes, 'big')
    else:
        half_length = len(key_bytes) // 2
        x_bytes = key_bytes[:half_length]
        y_bytes = key_bytes[half_length:]
        x = int.from_bytes(x_bytes, 'big')
        y = int.from_bytes(y_bytes, 'big')
        return ECPoint(x, y)

def read_key() -> tuple:
    """
    Reads the ECC parameters from a file.
    :return: A tuple containing the ECC parameters (EC, ECPoint, int).
    """
    filename = input("Enter the filename of the key file (or press Enter to use default file 'ec_bitcoin.txt'): ").strip()
    if filename == '' or not os.path.exists(filename):
        print("Using default file 'ec_bitcoin.txt'\n")
        filename = 'encryption_files/ec_bitcoin.txt'
    key = read_key_file(filename)
    key_lines = key.decode().splitlines()
    p = int(key_lines[0][2:])
    a = int(key_lines[1][2:])
    b = int(key_lines[2][2:])
    x = int(key_lines[3][2:])
    y = int(key_lines[4][2:])
    n = int(key_lines[5][2:])
    e = EC(p, a, b)
    G = ECPoint(x, y)
    return e, G, n

def main():
    """
    Main function to generate and save ECC keys, then verify them.
    """
    e, G, n = read_key()
    ecc_obj = ECPKS(e, G, n)
    private_key, public_key = ecc_obj.make_key_pair()

    save_as_binary(public_key, 'public_key.bin')
    save_as_binary(private_key, 'private_key.bin')

    read_private_key = read_binary_key('private_key.bin')
    read_public_key = read_binary_key('public_key.bin', is_ec_point=True)
    print("\nChecking if keys saved and read successfully", end="", flush=True)
    for _ in range(3):
        time.sleep(0.4)
        print(".", end="", flush=True)
    time.sleep(0.8)
    print(f"\nPrivate Key: {read_private_key == private_key}")
    print(f"Public Key: {read_public_key.x == public_key.x}, {read_public_key.y == public_key.y}")
    if read_private_key == private_key and read_public_key.x == public_key.x and read_public_key.y == public_key.y:
        print("Keys saved and read successfully")
    else:    
        print("Keys not saved and read successfully")

if __name__ == '__main__':
    main()
