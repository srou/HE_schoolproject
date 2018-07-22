import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import time
import math
import numpy as np


def coeffs_Psqrt(p):
    #Returns the coefficients ri that will help compute the polynomial P_sqrt that interpolates the function f:x-->floor(sqrt(x)) on [p]
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
    l2=[int(math.floor(math.sqrt(i))) for i in l1]
    print("l2 : ",l2)
    #find the coeffs ri (in Zp) that help construct the polynomial
    r=[]
    print("Computing coefficients of Psqrt") 
    for i in range(p):
        num=l2[i]
        den=1
        for j in range(p):
            if i!=j:
                den*=i-j
        tmp=(num*inv_modulo(den,p))%p
        r.append(int(tmp))
    return r

def compute_Psqrt(x,p,coeffs,HE):
    #x encrypted as a single Ctxt
    #0=< x =< p  , p prime
    res=HE.encrypt(PyPtxt([0], HE))  #encrypted integers from 0 to p
    enc_integers=[HE.encrypt(PyPtxt([i], HE)) for i in range(p)]
    for i in range(0,p) :
        if coeffs[i]!=0:
            tmp=enc_integers[coeffs[i]]
            for j in range(p):
                if i!=j:
                    tmp*=(x-enc_integers[j]) # tmp*=(x-HE.encrypt(PyPtxt([j], HE)))
            print type(coeffs[i])
            print type(tmp),HE.decrypt(tmp)
            res+=tmp
    return res

start = time.time()
HE = Pyfhel()
#Generate key
KEYGEN_PARAMS={ "p":7,      "r":1,
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

p=KEYGEN_PARAMS["p"]
n=4
x=HE.encrypt(PyPtxt([n], HE))
print("p=",p)

start = time.time()
coeffs=coeffs_Psqrt(p)
print(coeffs)
result=compute_Psqrt(x,p,coeffs,HE)

decrypted_res=HE.decrypt(result)
print("floor(sqrt("+str(n)+")) : ",decrypted_res)
end=time.time()
print(str(end-start)+" sec." )