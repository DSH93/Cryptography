from make_ecc_keys import read_key, save_as_binary, read_binary_key
from ecc_ex import ECPKS

def sig_keys():
    e, G, n = read_key()
    ecc_obj = ECPKS(e, G, n) 
    private_key, public_key = ecc_obj.make_key_pair()
    
    save_as_binary(public_key, 'sig_public_key.bin')
    save_as_binary(private_key, 'sig_private_key.bin') 
    return ecc_obj


