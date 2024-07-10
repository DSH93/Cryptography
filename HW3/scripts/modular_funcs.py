# -*- coding: utf-8 -*-
"""
Functions for modular computations

@author: Dani
"""
import random

def inverse(x,n):
    ''' returns x^(-1) mod n '''
    t0 = 0; t1 = 1
    r0 = n; r1 = x
    while r0%r1 != 0:
        q = r0//r1
        t0, t1 = t1, t0-q*t1
        r0, r1 = r1, r0%r1
    if r1>1: return None
    return t1%n


def is_quad_res(a,p):
    ''' Euler Criterion '''
    return a==0 or pow(a,(p-1)//2,p) == 1 # True if a is a quadratic residue modulo p 


def modular_root(a,p):
    ''' returns sqrt(a) modulo p if it exists '''
    if a==0: return 0
    if not is_quad_res(a,p):
        return None
    n=2
    while is_quad_res(n,p):
        n+=1
    alpha = 1
    s=(p-1)//2
    j=0
    i=1
    while s%2==0:
        alpha+=1
        s//=2
    b=pow(n,s,p)
    r=pow(a,(s+1)//2,p)
    root=r
    power_2_check=pow(2,alpha-1,p)
    d=2
    a_inv=inverse(a,p)
    while d <= alpha:
        power_2_check //= 2
        test_val = pow(a_inv*root*root%p,power_2_check,p)
        if test_val != 1:
            j+=i
        i*=2
        root = pow(b,j,p)*r%p
        d+=1
    return random.choice([root, p-root])

