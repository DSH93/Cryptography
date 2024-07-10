from modular_funcs import *
from os import urandom
   
class ECPoint:
    ''' A point on an elliptic curve '''
    def __init__(self,x,y):
        self.__x = x
        self.__y = y
        
    @property
    def x(self):
        return self.__x
    
    @x.setter
    def x(self, value):
        self.__x = value
        
    @property
    def y(self):
        return self.__y
    
    @y.setter
    def y(self, value):
        self.__y = value
    
    def __str__(self):
        return f'({self.x},{self.y})'
    
    def equals(self, other):
        return self.x == other.x and self.y == other.y

import random

class EC:
    ''' a finite elliptic curve '''
    def __init__(self,p,a,b):
        self.__p = p
        self.__a = a
        self.__b = b
    
    @property
    def p(self):
        return self.__p
    
    @p.setter
    def p(self, value):
        self.__p = value
        
    @property
    def a(self):
        return self.__a
    
    @a.setter
    def a(self, value):
        self.__a = value

    @property
    def b(self):
        return self.__b
    
    @b.setter
    def b(self, value):
        self.__b = value

    def get_rhs(self, x):
        return (pow(x,3,self.p)+self.a*x+self.b)%self.p

    def __on_curve(self,P):
        return P==0 or self.get_rhs(P.x) == (P.y**2)%self.p

    def minus(self,P):
        return ECPoint(P.x,self.p-P.y)

    def add(self,P,Q):
        if not self.__on_curve(P):
            raise ValueError(f'{P} is not on the curve')
        if not self.__on_curve(Q):
            raise ValueError(f'{Q} is not on the curve')
        if P==0: return Q
        if Q==0: return P
        if P.equals(self.minus(Q)): return 0
        # compute lambda
        if P.equals(Q):
            l = (((3*P.x*P.x+self.a)%self.p)*(inverse(2*P.y,self.p)))%self.p
        else:
            l = ((Q.y-P.y)%self.p*inverse((Q.x-P.x)%self.p,self.p))%self.p
        x3 = (l*l-(P.x+Q.x))%self.p
        y3 = (l*(P.x-x3)-P.y)%self.p
        return ECPoint(x3,y3)

    def power(self,P,k):
        if not self.__on_curve(P):
            raise ValueError(f'{P} not on the curve')
        bin_str = bin(k)[2:]
        result = 0
        for b in bin_str:
            result = self.add(result,result)
            if b == '1':
                result = self.add(result,P)
        return result

    def random_point(self):
        x = random.SystemRandom().randint(1,self.p-1)
        z = self.get_rhs(x)
        while not is_quad_res(z,self.p):
            x = (x+1)%self.p
            z = self.get_rhs(x)
        y = modular_root(z,self.p)
        return ECPoint(x,y)

class ECPKS: # Elliptic Curve Public Key Encryption Scheme
    ''' Class for performing elliptic curve public key encryption and decryption '''
    def __init__(self, e, G, n):
        self.__e = e # the curve
        self.__G = G # the base point
        self.__n = n # the order of G
        self.__t = 50

    @property
    def e(self):
        return self.__e

    @property
    def G(self):
        return self.__G

    @property
    def n(self):
        return self.__n



    def make_key_pair(self):
        private_key = random.SystemRandom().randint(2,self.n-1)
        public_key = self.e.power(self.G,private_key)
        return private_key, public_key

    def __encode(self, M): # M is a bytes type plaintext
        m = int.from_bytes(M,'big')
        if m*self.__t >= self.e.p:
            raise ValueError(f'plaintext {M} is too big')
        x = m*self.__t
        for i in range(1,self.__t+1):
            x += 1
            if is_quad_res(self.e.get_rhs(x), self.e.p):
                break
        y = modular_root(self.e.get_rhs(x),self.e.p)
        return ECPoint(x,y)

    def __decode(self,P):
        m = (P.x-1)//self.__t
        return m.to_bytes((m.bit_length()+7)//8,'big')

    def encrypt(self,M, pub_k):
        P = self.__encode(M)
        k = random.SystemRandom().randint(2,self.n-1)
        alpha = self.e.power(self.G, k)
        beta = self.e.add(P, self.e.power(pub_k,k))
        return alpha, beta

    def decrypt(self,C, pr_k):
        alpha, beta = C[0], C[1]
        P = self.e.add(beta, self.e.minus(self.e.power(alpha,pr_k)))
        return self.__decode(P)


def main():
    with open('ec_bitcoin.txt', 'r') as reader:
        key = reader.read().split()
    p = int(key[0][2:])
    a = int(key[1][2:])
    b = int(key[2][2:])
    x = int(key[3][2:])
    y = int(key[4][2:])
    n = int(key[5][2:])
    e = EC(p,a,b) # elliptic curve
    
    
    ecc_obj = ECPKS(e, ECPoint(x,y), n) # ECPoint(x,y) is the base point G
    # ecc_obj is the ECC object with the elliptic curve, base point and order of the base point
    pr_k, pu_k = ecc_obj.make_key_pair()
    M = b'encrypt this message'
    C = ecc_obj.encrypt(M, pu_k)
    decrypted = ecc_obj.decrypt(C,pr_k)
    print(decrypted)


if __name__ == '__main__':
    main()