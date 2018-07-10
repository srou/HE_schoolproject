import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import pandas as pd 
import time
import math
import numpy as np

def is_smaller(x_bits,y_bits,HE,alpha=8,n=1000):
    #takes in input 2 encrypted number (st 0=< x,y < n) given in their binary form
    #coded on alpha bits
    #returns [1] iff y<x , [0] otherwise  (where [1]= encrypt(1))
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Initialisation of same_prefix and same_bit
    print("Initisalisation")
    p_1=PyPtxt([1], HE)
    c_1=HE.encrypt(p_1)
    same_prefix=[c_1]
    same_bit=[]
    res=(c_1-y_bits[0])*x_bits[0]
    for i in range(alpha):                        #min(alpha,int(math.floor(math.log(n))+1))):
        tmp1=c_1.copy(c_1)
        same_bit.append(tmp1-((x_bits[i]-y_bits[i])**2))
        tmp=c_1.copy(c_1)
        #print("c_1 : ",HE.decrypt(c_1))
        print("tmp : ",HE.decrypt(tmp))
        for j in range(i+1):
            print("same_bit : "+str(j),HE.decrypt(same_bit[j]))
            tmp*=same_bit[j]
        print("tmp : ",HE.decrypt(tmp))
        same_prefix.append(tmp)
        res+=(c_1-y_bits[i])*x_bits[i]*same_prefix[i]  ## peut etre un pb d'indice
        print("res : ",HE.decrypt(res))
    return res


start = time.time()
HE = Pyfhel()
#Generate Key
KEYGEN_PARAMS={ "p":2,        "r":32,
                "d":0,        "c":3,
                "sec":128,    "w":64,
                "L":35,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
print("  KeyGen completed in "+str(end-start)+" sec." )

#test is_smaller with integers 5 and 6
x=6
x_bits=[int(i) for i in list('{0:08b}'.format(x))] #int 6 as a list of 8 bits
x_bits_enc=[]
print("Encrypting "+str(x)+" in bits ",x_bits)
start = time.time()
for i in x_bits:
    p=PyPtxt([i], HE)
    x_bits_enc.append(HE.encrypt(p))
end=time.time()
print(str(end-start)+" sec." )

y=5
y_bits=[int(i) for i in list('{0:08b}'.format(y))] #int 5 as a list of 8 bits
y_bits_enc=[]
print("Encrypting "+str(y)+" in bits.",y_bits)
start = time.time()
for i in y_bits:
    p=PyPtxt([i], HE)
    y_bits_enc.append(HE.encrypt(p))
end=time.time()
print(str(end-start)+" sec." )

result=is_smaller(x_bits_enc,y_bits_enc,HE)
decrypted_res=HE.decrypt(result)
print("decrypted result : ",decrypted_res)