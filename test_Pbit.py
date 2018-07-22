import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import time
import math
import numpy as np

def coeffs_Pbit_i(i,p,alpha):
    #Returns the coefficients ri that will help compute the polynomial P_bit that interpolates the function f:x-->bit_i(x) on [p]
    #alpha : nb of bits
    #0=< 2^alpha-1 < p, p prime
    #0=< i =< alpha
    print("Computing coefficients of Psqrt")
    def bezout(a, b):
        #computes (u,v,p) st a*u + b*v = gdc(a,b)
        if a == 0 and b == 0: return (0, 0, 0)
        if b == 0: return (a/abs(a), 0, abs(a))
        (u, v, gdc) = bezout(b, a%b)
        return (v, (u - v*(a/b)), gdc)
    def inv_modulo(x, p):
        #Computes y in [p] st x*y=1 mod p
        (u, _, gdc) = bezout(x, p)
        if gdc == 1: return u%abs(p)
        else: raise Exception("%s et %s are not mutually prime" % (x, p))
    l1=range(0,p)
    a='{0:0'+str(alpha)+'b}'
    l2=[int(list(a.format(x))[i]) for x in l1]
    print("l2 : ",l2)
    #find the coeffs ri (in Zp) that help construct the polynomial
    r=[]
    print("Computing coefficients of Pbit_i") 
    for i in range(p):
        num=l2[i]
        den=1
        for j in range(p):
            if i!=j:
                den*=i-j
        tmp=(num*inv_modulo(den,p))%p
        r.append(int(tmp))
    return r

def compute_Pbit_i(x,p,coeffs_i,HE):
    #0=< x =< p  , p prime
    #returns [1] if the ith bit of x is 1, otherwise 0 (x coded on alpha bits)
    res=HE.encrypt(PyPtxt([0], HE)) 
    for i in range(0,p) :
        tmp=HE.encrypt(PyPtxt([coeffs_i[i]], HE))
        for j in range(p):
            if i!=j:
                tmp*=(x-HE.encrypt(PyPtxt([j], HE)))
        res+=tmp
    return res

start = time.time()
HE = Pyfhel()
#Generate key
KEYGEN_PARAMS={ "p":17,      "r":1,
                "d":0,        "c":2,
                "sec":128,    "w":64,
                "L":40,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
print("  KeyGen completed in "+str(end-start)+" sec." )

n=10
i=1
alpha=4
ptxt=PyPtxt([n], HE)
x=HE.encrypt(ptxt)
print("Compute the "+str(i)+"th bit of "+str(n)+" (written on "+str(alpha)+" bits)")

start = time.time()
coeffs_i=coeffs_Pbit_i(i=i,p=17,alpha=alpha)
result=compute_Pbit_i(x,p=17,coeffs_i=coeffs_i,HE=HE)
decrypted_res=HE.decrypt(result)
print("1st bit of 20 written in 5 bits : ",decrypted_res)
end=time.time()
print(str(end-start)+" sec." )