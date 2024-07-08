from make_ecc_keys import *



def main():
    filename = 'ec_bitcoin.txt'
    e, G, n = read_key(filename)
    ecc_obj = ECPKS(e, G, n) 
    private_key, public_key = ecc_obj.make_key_pair()
    
    save_as_binary(public_key, 'sig_public_key.txt')
    save_as_binary(private_key, 'sig_private_key.txt') 


if __name__ == '__main__':
    main()