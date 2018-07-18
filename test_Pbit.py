import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import time
import math
import numpy as np

def P_bits(x,i,p,alpha):
    #x encrypted as a single Ctxt
    #0=< x =< p  (p=2**alpha)
    #0=< i <alpha
    #returns [1] if the ith bit of x is 1, otherwise 0
    def poly_bits(i,alpha):
    #returns the coeffs of the polynomial P that interpolates the function Pbit_i on [0,2^alpha - 1]
    #where Pbit_i(n)=ith bit of n in its representation on alpha bits
        def x_bits(n,L):
            #encrypts n on L bits
            a='{0:0'+str(L)+'b}'
            return [int(i) for i in list(a.format(n))]
        p=(2**alpha)
        l1=range(0,p)
        l2=[x_bits(i,alpha)[0] for i in range(p)]   #1er bit de chaque nombre entre 0 et 15
        print l2
        return np.polyfit(l1,l2,p)

    coeffs=poly_bits(i,alpha)
    p_1=PyPtxt([1], HE)
    c_1=HE.encrypt(p_1)
    res=c_1*coeffs[0]
    for k in range(1,len(coeffs)):
        res+=coeffs[k]*(x**k)
    return res

start = time.time()
HE = Pyfhel()
#Generate Key
KEYGEN_PARAMS={ "p":2,        "r":32,
                "d":0,        "c":3,
                "sec":128,    "w":64,
                "L":40,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
print("  KeyGen completed in "+str(end-start)+" sec." )

#compute the 1st bit of 20 (written on 5 bits)
ptxt=PyPtxt([20], HE)
x=HE.encrypt(ptxt)

start = time.time()
result=P_bits(x,i=1,p=32,alpha=5)
decrypted_res=HE.decrypt(result)
print("1st bit of 20 written in 5 bits : ",decrypted_res)
end=time.time()
print(str(end-start)+" sec." )