from make_ecc_keys import read_key, save_as_binary, read_binary_key
from ecc_ex import ECPKS

def sig_keys(to_save: bool = True) -> ECPKS:
    """
    Generates ECC signature keys and optionally saves them to files.
    :param to_save: Whether to save the keys to files (bool).
    :return: The ECC object (ECPKS).
    """
    e, G, n = read_key()
    ecc_obj = ECPKS(e, G, n) 
    private_key, public_key = ecc_obj.make_key_pair()
    
    if not to_save:
        return ecc_obj
    
    save_as_binary(public_key, 'sig_public_key.bin')
    save_as_binary(private_key, 'sig_private_key.bin')
    return ecc_obj
