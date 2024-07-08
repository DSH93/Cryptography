import os
from modular_funcs import inverse, is_quad_res, modular_root
from ecc_ex import ECPoint, EC, ECPKS



def read_file(file_name):
    with open(file_name, 'r') as reader:
        key = reader.read().split()
    return key

def save_key(key, filename):
    with open(filename, 'w') as writer:
        writer.write(str(key))
        
    
def save_as_binary(key, filename):
    if isinstance(key, int):
        header = "private_key: "
        key = bin(key)
        key = header + str(key)
        save_key(key, filename)
    elif isinstance(key, ECPoint):
        header = "public key:\n"
        x = f'x: {bin(key.x)}\n'
        y = f'y: {bin(key.y)}'
        key = header + x + y
        save_key(key, filename)
        
    else:
        raise ValueError("Unsupported key type")


def read_key(filename):
    key = read_file(filename)
    p = int(key[0][2:])
    a = int(key[1][2:])
    b = int(key[2][2:])
    x = int(key[3][2:])
    y = int(key[4][2:])
    n = int(key[5][2:])
    e = EC(p,a,b)
    G = ECPoint(x,y)
    return e, G, n
    


def main():
    filename = 'ec_bitcoin.txt'
    e, G, n = read_key(filename)
    ecc_obj = ECPKS(e, G, n) 
    private_key, public_key = ecc_obj.make_key_pair()
    
    save_as_binary(public_key, 'public_key.txt')
    save_as_binary(private_key, 'private_key.txt') 


if __name__ == '__main__':
    main()