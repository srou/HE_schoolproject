import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import time
import math
import numpy as np

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
def convert_to_bits(x,p,alpha,HE):
    def coeffs_Pbit_i(i,p,alpha):
        #Returns the coefficients ri that will help compute the polynomial P_bit that interpolates the function f:x-->bit_i(x) on [p]
        #alpha : nb of bits
        #0=< 2^alpha-1 < p, p prime
        #0=< i =< alpha
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
        #0=< x =< 2^alpha-1 < p  , p prime
        #returns [1] if the ith bit of x is 1, otherwise 0 (x coded on alpha bits)
        res=HE.encrypt(PyPtxt([0], HE)) 
        for i in range(0,p) :
            tmp=HE.encrypt(PyPtxt([coeffs_i[i]], HE))
            for j in range(p):
                if i!=j:
                    tmp*=(x-HE.encrypt(PyPtxt([j], HE)))
            res+=tmp
        return res
    #takes in input an encrypted number x and returns its representation as a list of alpha encrypted bits
    #0=< x =< 2^alpha-1 < p  , p prime
    bits_x=[]  #encrypted bit representation of x
    for i in range(alpha):
        print("Computing bit "+str(i))
        coeffs_i=coeffs_Pbit_i(i=i,p=p,alpha=alpha)
        bits_x.append(compute_Pbit_i(x=x,p=p,coeffs_i=coeffs_i,HE=HE))
    return bits_x

start = time.time()
HE = Pyfhel()
#Generate key
KEYGEN_PARAMS={ "p":11,      "r":1,
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

n=7
alpha=3
p=KEYGEN_PARAMS["p"]
print("Converting "+str(n)+" to bits (alpha = "+str(alpha)+")")
start = time.time()
x=HE.encrypt(PyPtxt([n], HE))
bits_x=convert_to_bits(x,p,alpha,HE)
end=time.time()
print ("Result : ",[HE.decrypt(res) for res in bits_x])
print(str(end-start)+" sec." )

#i=1
#x=HE.encrypt(PyPtxt([n], HE))
#print("Compute the "+str(i)+"th bit of "+str(n)+" (written on "+str(alpha)+" bits)")

#start = time.time()
#coeffs_i=coeffs_Pbit_i(i=i,p=17,alpha=alpha)
#result=compute_Pbit_i(x,p=17,coeffs_i=coeffs_i,HE=HE)
#decrypted_res=HE.decrypt(result)
#print("Result : ",decrypted_res)
#end=time.time()
#print(str(end-start)+" sec." )